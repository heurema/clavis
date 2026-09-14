package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/heurema/clavis/internal/auth"
)

// The tenant settings and the headers they travel in. A tenant is connection
// configuration rather than caller input: one stored secret header cannot
// carry two identifiers and a credential, so the two are settings of their own.
const (
	keyAccountID    = "accountId"
	keyProjectID    = "projectId"
	headerAccountID = "AccountID"
	headerProjectID = "ProjectID"
)

// The read-only endpoints of the source's LogsQL API. No other path is
// reachable: the endpoint is chosen from the input, never composed from one.
const (
	logsQueryPath             = "/select/logsql/query"
	logsFieldNamesPath        = "/select/logsql/field_names"
	logsFieldValuesPath       = "/select/logsql/field_values"
	logsStreamsPath           = "/select/logsql/streams"
	logsStreamFieldNamesPath  = "/select/logsql/stream_field_names"
	logsStreamFieldValuesPath = "/select/logsql/stream_field_values"
)

// The names the platform gives the six answers. A log source writes no result
// type of its own, so these name the input rather than classify the data.
const (
	resultTypeLogs              = "logs"
	resultTypeFieldNames        = "fieldNames"
	resultTypeFieldValues       = "fieldValues"
	resultTypeStreams           = "streams"
	resultTypeStreamFieldNames  = "streamFieldNames"
	resultTypeStreamFieldValues = "streamFieldValues"
)

// logsReadBuffer is what one read of the line stream may take. A row larger
// than it is assembled across reads under the body ceiling rather than
// refused, so the buffer is a read size and never a bound on a row.
const logsReadBuffer = 64 << 10

type victoriaLogs struct{}

func (victoriaLogs) Type() auth.ProviderType { return auth.ProviderVictoriaLogs }

// ParseTarget accepts the shared HTTP settings plus the optional tenant. A
// custom authentication header named like a tenant header is refused: it would
// let one stored setting decide both who we are and whose data we read.
func (victoriaLogs) ParseTarget(raw map[string]string) (map[string]string, error) {
	if err := allowedKeys(raw, keyURL, keyAuth, keyUser, keyHeader, keyAccountID, keyProjectID); err != nil {
		return nil, err
	}
	target, err := httpTarget(raw)
	if err != nil {
		return nil, err
	}
	if header, ok := target[keyHeader]; ok && tenantHeaderName(header) {
		return nil, invalid("Setting header must not name a tenant header; set the tenant with accountId and projectId.")
	}
	for _, key := range []string{keyAccountID, keyProjectID} {
		value, present := raw[key]
		if !present {
			continue
		}
		if !auth.ValidTenantID(value) {
			return nil, invalid("Settings accountId and projectId must each be an unsigned 32-bit decimal integer.")
		}
		target[key] = value
	}
	return target, nil
}

// tenantHeaderName reports whether a header name is one of the two the
// provider sends itself, compared the way HTTP compares a field name.
func tenantHeaderName(value string) bool {
	canonical := http.CanonicalHeaderKey(value)
	return canonical == http.CanonicalHeaderKey(headerAccountID) ||
		canonical == http.CanonicalHeaderKey(headerProjectID)
}

func (victoriaLogs) ValidateSecret(target map[string]string, secret auth.Secret) error {
	return validateHTTPSecret(target, secret)
}

// Probe sends exactly one GET to the health endpoint under the stored
// authentication and the connection's tenant headers, so a check exercises the
// same request shape an execution will send.
func (victoriaLogs) Probe(ctx context.Context, target map[string]string, secret auth.Secret) auth.CheckOutcome {
	return httpProbe(ctx, target, secret, tenantHeaders(target))
}

// tenantHeaders renders the configured tenant. An omitted setting sends no
// header at all, which is what a single-node source expects.
func tenantHeaders(target map[string]string) http.Header {
	headers := http.Header{}
	for _, pair := range []struct{ key, name string }{
		{keyAccountID, headerAccountID},
		{keyProjectID, headerProjectID},
	} {
		if value := target[pair.key]; value != "" {
			headers.Set(pair.name, value)
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// logsFields reports whether any log input or log parameter is set. The other
// two providers ask it so a log input on their connection is refused before
// anything is dialled, rather than sent to a source that has no such endpoint.
func logsFields(request ExecuteRequest) bool {
	return request.LogsQL != "" || request.FieldNames || request.FieldValues != "" ||
		request.Streams || request.StreamFieldNames || request.StreamFieldValues != "" ||
		request.Limit != nil || request.Filter != ""
}

// logsEndpoint declares one endpoint and the parameters it takes. The source
// takes a limit on four of the six and a filter on four others; sending one
// where the endpoint has no parameter for it would be dropped in silence
// rather than answered, so it is refused instead.
type logsEndpoint struct {
	path        string
	resultType  string
	stream      bool
	takesLimit  bool
	takesFilter bool
}

// logsCall is the one request an execution sends: a GET to one chosen path
// with the parameters the caller gave.
type logsCall struct {
	path       string
	query      url.Values
	resultType string
	stream     bool
}

// Execute forwards one input to one endpoint and returns the source's own rows
// under the connection's bounds. Nothing here parses LogsQL, a time, a limit or
// a filter: the strings reach the source as they were submitted, so ordering
// and aggregation stay the query's job and the source's acceptance rules are
// the only ones that apply.
func (victoriaLogs) Execute(ctx context.Context, target map[string]string, secret auth.Secret, request ExecuteRequest) (ExecuteResult, error) {
	request = boundedRequest(request)
	timeout := sourceTimeout(request.Timeout)
	call, err := logsCallFor(request, timeout)
	if err != nil {
		return ExecuteResult{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet,
		target[keyURL]+call.path+"?"+call.query.Encode(), nil)
	if err != nil {
		return ExecuteResult{}, ErrUnreachable
	}
	httpRequest.Header.Set("Accept", "application/json")
	// The tenant travels before the credential, so a tenant header can never
	// overwrite the authentication the target configured.
	applyHTTPHeaders(httpRequest, tenantHeaders(target))
	applyHTTPAuth(httpRequest, target, secret)
	// The client is built per execution, as the probe's is, and its deadline is
	// the source's own timeout plus the documented grace. Keep-alive is off, so
	// closing the body at a cap closes the connection and the source stops.
	client := httpClient(timeout + auth.MetricsGrace)
	defer client.CloseIdleConnections()
	response, err := client.Do(httpRequest)
	if err != nil {
		return ExecuteResult{}, httpTransportError(err)
	}
	defer func() { _ = response.Body.Close() }()
	if failure, mapped := httpStatusFailure(response.StatusCode); mapped {
		return ExecuteResult{}, failure
	}
	if response.StatusCode != http.StatusOK {
		return ExecuteResult{}, logsHTTPError(response)
	}
	var result ExecuteResult
	if call.stream {
		result, err = logsRows(response.Body, request)
	} else {
		result, err = logsValues(response.Body, call, request)
	}
	if err != nil {
		return ExecuteResult{}, logsBodyError(err)
	}
	return result, nil
}

// logsCallFor chooses the endpoint and builds its parameters. Only the fields
// that were given travel, and each travels as its own text: a limit is the
// caller's decimal, never the platform's cap, because a limit changes what the
// source executes.
func logsCallFor(request ExecuteRequest, timeout time.Duration) (logsCall, error) {
	endpoint, err := logsEndpointFor(request)
	if err != nil {
		return logsCall{}, err
	}
	// The log stream carries the caller's LogsQL; a discovery endpoint takes
	// the same parameter and the caller's query arrives in Match. Either way it
	// is the caller's own text and reaches the source byte for byte.
	logsQL := request.LogsQL
	if !endpoint.stream {
		logsQL = request.Match
	}
	field := request.FieldValues
	if request.StreamFieldValues != "" {
		field = request.StreamFieldValues
	}
	query := url.Values{"query": {logsQL}}
	setParameter(query, "start", request.Start)
	setParameter(query, "end", request.End)
	setParameter(query, "field", field)
	setParameter(query, "filter", request.Filter)
	if request.Limit != nil {
		// An explicit zero is the caller saying "no limit" to the source and
		// reaches it as a sent zero; an absent limit is no parameter at all.
		query.Set("limit", strconv.FormatInt(*request.Limit, 10))
	}
	query.Set("timeout", timeoutValue(timeout))
	return logsCall{
		path: endpoint.path, query: query,
		resultType: endpoint.resultType, stream: endpoint.stream,
	}, nil
}

// logsEndpointFor reports the one endpoint the request names, or refuses the
// request. The service decides this first, with a hint naming the right input;
// this is the backstop that keeps a missed rule from reaching a source.
func logsEndpointFor(request ExecuteRequest) (logsEndpoint, error) {
	// An input another provider takes is not a log input, whatever else is set.
	if request.SQL != "" || request.PromQL != "" || request.Labels ||
		request.LabelValues != "" || request.Series != "" ||
		request.At != "" || request.Step != "" {
		return logsEndpoint{}, ErrUnsupportedInput
	}
	var chosen logsEndpoint
	inputs := 0
	for _, candidate := range []struct {
		set      bool
		endpoint logsEndpoint
	}{
		{request.LogsQL != "", logsEndpoint{
			path: logsQueryPath, resultType: resultTypeLogs, stream: true, takesLimit: true}},
		{request.FieldNames, logsEndpoint{
			path: logsFieldNamesPath, resultType: resultTypeFieldNames, takesFilter: true}},
		{request.FieldValues != "", logsEndpoint{
			path: logsFieldValuesPath, resultType: resultTypeFieldValues, takesLimit: true, takesFilter: true}},
		{request.Streams, logsEndpoint{
			path: logsStreamsPath, resultType: resultTypeStreams, takesLimit: true}},
		{request.StreamFieldNames, logsEndpoint{
			path: logsStreamFieldNamesPath, resultType: resultTypeStreamFieldNames, takesFilter: true}},
		{request.StreamFieldValues != "", logsEndpoint{
			path: logsStreamFieldValuesPath, resultType: resultTypeStreamFieldValues, takesLimit: true, takesFilter: true}},
	} {
		if candidate.set {
			inputs++
			chosen = candidate.endpoint
		}
	}
	if inputs != 1 {
		return logsEndpoint{}, ErrUnsupportedInput
	}
	// Discovery needs the source's query, which arrives in Match; the log
	// stream carries its own and takes no second one.
	if chosen.stream == (request.Match != "") {
		return logsEndpoint{}, ErrUnsupportedInput
	}
	if request.Limit != nil && (!chosen.takesLimit || *request.Limit < 0) {
		return logsEndpoint{}, ErrUnsupportedInput
	}
	if request.Filter != "" && !chosen.takesFilter {
		return logsEndpoint{}, ErrUnsupportedInput
	}
	return chosen, nil
}

// logsHTTPError maps an answer the source refused to give. A log source writes
// plain text with a status: a rejected query is 400 and its own aborted
// evaluation is 503. The status is the whole classification; the text is never
// searched for a word, because reading the source's prose would be the platform
// interpreting a failure it did not write.
func logsHTTPError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))
	if err != nil {
		// A deadline reached while reading an error body is the timeout the
		// caller was promised, not a source rejection with half its text.
		return logsBodyError(readError(err))
	}
	return &SourceError{Failure: auth.SourceFailure{
		ErrorType: "http_" + strconv.Itoa(response.StatusCode),
		Message:   boundedText(body),
	}}
}

// logsBodyError turns the two body failures into the source failure the caller
// sees. The messages are the platform's own fixed text: the body that produced
// them was never read as the source's words. A failure the reader already
// shaped, such as a line that is not one JSON object, travels as it is.
func logsBodyError(err error) error {
	switch {
	case errors.Is(err, errBodyTooLarge):
		return &SourceError{Failure: auth.SourceFailure{
			ErrorType: ResponseTooLarge,
			Message:   "The source's answer passed the response ceiling and was not read as data.",
		}}
	case errors.Is(err, errMalformed):
		return &SourceError{Failure: auth.SourceFailure{
			ErrorType: MalformedResponse,
			Message:   "The source's answer could not be read as the log API's response.",
		}}
	default:
		return err
	}
}

// logsRows reads the log stream, which is newline-delimited JSON objects with
// no envelope around them and no end the source promises. Rows are kept in
// arrival order while the caps allow; when keeping the next one would pass a
// cap the reader stops and the caller closes the body, which closes the
// connection because keep-alive is off. Reaching the end of the stream first
// means the answer is complete, also when the kept count equals the cap
// exactly, because the end was observed rather than assumed.
func logsRows(body io.Reader, request ExecuteRequest) (ExecuteResult, error) {
	// The ceiling bounds one row here rather than the body: the stream has no
	// documented length, but a single row the platform cannot hold is a row it
	// must not present as data.
	ceiling := int64(auth.MetricsBodyCeiling(request.MaxBytes))
	reader := bufio.NewReaderSize(body, logsReadBuffer)
	keeper := &rowKeeper{maxRows: request.MaxRows, maxBytes: int64(request.MaxBytes)}
	var out bytes.Buffer
	out.WriteByte('[')
	first := true
	for {
		line, ended, err := logsLine(reader, ceiling)
		if err != nil {
			return ExecuteResult{}, err
		}
		// A blank line carries no row. The source writes one after the last
		// row, and a final line without its newline is a row like any other.
		if len(bytes.TrimSpace(line)) > 0 {
			row, size, err := logsRow(line)
			if err != nil {
				return ExecuteResult{}, err
			}
			if !keeper.keep(size) {
				keeper.dropped = true
				break
			}
			if !first {
				out.WriteByte(',')
			}
			first = false
			out.Write(row)
		}
		if ended {
			break
		}
	}
	out.WriteByte(']')
	return ExecuteResult{
		ResultType: resultTypeLogs,
		Result:     out.Bytes(),
		Truncated:  keeper.dropped,
		Statements: 1,
		Rows:       keeper.rows,
		Bytes:      keeper.bytes,
	}, nil
}

// logsLine reads one line without its terminator, bounded by the ceiling so a
// source that never writes one cannot be read into memory. The second return
// says the stream ended with this line, which is how a final row without a
// newline is accepted.
func logsLine(reader *bufio.Reader, ceiling int64) ([]byte, bool, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		// The ceiling bounds the row; a terminator is allowed on top of it, but
		// only when it is there, so a final row without one is bounded the same.
		limit := ceiling
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
			limit++
		}
		if int64(len(line))+int64(len(chunk)) > limit {
			return nil, false, errBodyTooLarge
		}
		// ReadSlice returns a view of the reader's own buffer, valid only until
		// the next read, so every byte kept is copied here.
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], false, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return line, true, nil
		default:
			return nil, false, readError(err)
		}
	}
}

// logsRow reads one line as exactly one JSON object and re-encodes it
// compactly, keeping the source's field order and every value byte for byte.
// It returns the UTF-8 length the row costs the byte cap: the text of every
// field name, the text of every string value and the raw text of every other.
// A line that is not one JSON object fails the whole request with the offending
// text, because a log source writes an error into the stream it was writing
// rows into, and half a stream is not data.
func logsRow(line []byte) ([]byte, int64, error) {
	walk := &jsonWalker{decoder: json.NewDecoder(bytes.NewReader(line))}
	// Numbers keep the digits the source wrote: a float round trip would change
	// what the caller is told the source said.
	walk.decoder.UseNumber()
	row, size, err := logsObject(walk)
	if err == nil {
		// Nothing may follow the object on the line: a second document would
		// mean the line was never the one row it is read as.
		if _, trailing := walk.decoder.Token(); !errors.Is(trailing, io.EOF) {
			err = errMalformed
		}
	}
	if err != nil {
		// The offending line is the source's own text and travels bounded, as
		// every text the platform did not write does.
		return nil, 0, &SourceError{Failure: auth.SourceFailure{
			ErrorType: MalformedResponse,
			Message:   boundedText(line),
		}}
	}
	return row, size, nil
}

// logsObject reads one JSON object into an ordered encoding. Members are
// written back in the order they were read and values travel as the raw bytes
// the source wrote, compacted, so a nested object, a long number and a string
// holding JSON text all survive unchanged.
func logsObject(walk *jsonWalker) ([]byte, int64, error) {
	if err := walk.expect('{'); err != nil {
		return nil, 0, err
	}
	var out bytes.Buffer
	out.WriteByte('{')
	var size int64
	first := true
	for walk.decoder.More() {
		name, err := walk.key()
		if err != nil {
			return nil, 0, err
		}
		var raw json.RawMessage
		if err := walk.decoder.Decode(&raw); err != nil {
			return nil, 0, readError(err)
		}
		var value bytes.Buffer
		if err := json.Compact(&value, raw); err != nil {
			return nil, 0, errMalformed
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(jsonString(name))
		out.WriteByte(':')
		out.Write(value.Bytes())
		size += int64(len(name)) + logsValueSize(value.Bytes())
	}
	if err := walk.expect('}'); err != nil {
		return nil, 0, err
	}
	out.WriteByte('}')
	return out.Bytes(), size, nil
}

// logsValueSize is what one value costs the byte cap: the text of a string, and
// the raw text of anything else, so a number or an object counts what it holds
// rather than nothing.
func logsValueSize(raw []byte) int64 {
	if len(raw) > 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			return int64(len(text))
		}
	}
	return int64(len(raw))
}

// logsValues reads a discovery answer, which is one JSON envelope rather than a
// stream: it is read under the ceiling and drained to its end, as a metrics
// envelope is, so the whole document is validated even when the caps dropped
// items from it.
func logsValues(body io.Reader, call logsCall, request ExecuteRequest) (ExecuteResult, error) {
	ceiling := int64(auth.MetricsBodyCeiling(request.MaxBytes)) + 1
	reader := &ceilingReader{reader: io.LimitReader(body, ceiling), remaining: ceiling}
	decoder := json.NewDecoder(reader)
	// The hit counts keep the digits the source wrote.
	decoder.UseNumber()
	walk := &logsDecoder{
		jsonWalker: &jsonWalker{decoder: decoder},
		keeper:     &rowKeeper{maxRows: request.MaxRows, maxBytes: int64(request.MaxBytes)},
	}
	if err := walk.envelope(); err != nil {
		return ExecuteResult{}, err
	}
	if walk.values == nil {
		return ExecuteResult{}, errMalformed
	}
	return ExecuteResult{
		ResultType: call.resultType,
		Result:     walk.values,
		Truncated:  walk.keeper.dropped,
		Statements: 1,
		Rows:       walk.keeper.rows,
		Bytes:      walk.keeper.bytes,
	}, nil
}

// logsDecoder walks a discovery envelope with the shared token walker.
type logsDecoder struct {
	*jsonWalker
	keeper *rowKeeper
	values []byte
}

// envelope reads the one top-level object to its end, whatever the caps did to
// the items inside it.
func (d *logsDecoder) envelope() error {
	if err := d.expect('{'); err != nil {
		return err
	}
	for d.decoder.More() {
		key, err := d.key()
		if err != nil {
			return err
		}
		if key == "values" {
			err = d.valueList()
		} else {
			// A source answers keys of its own. They are skipped rather than
			// refused: the platform judges the envelope it documents, not what
			// a source adds beside it.
			err = d.skip(0)
		}
		if err != nil {
			return err
		}
	}
	if err := d.expect('}'); err != nil {
		return err
	}
	// Nothing may follow the envelope: a second document would mean the answer
	// was never the one thing the platform validated.
	if _, err := d.decoder.Token(); !errors.Is(err, io.EOF) {
		return readError(err)
	}
	return nil
}

// valueList reads the value-and-hits pairs, keeping them in order while the
// caps allow and dropping a later item whole, because an item is what the
// caller asked for. Reading continues to the end of the envelope either way.
func (d *logsDecoder) valueList() error {
	if err := d.expect('['); err != nil {
		return err
	}
	var out bytes.Buffer
	out.WriteByte('[')
	first := true
	for d.decoder.More() {
		item, size, err := d.pair()
		if err != nil {
			return err
		}
		if !d.keeper.keep(size) {
			d.keeper.dropped = true
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(item)
	}
	if err := d.expect(']'); err != nil {
		return err
	}
	out.WriteByte(']')
	d.values = out.Bytes()
	return nil
}

// pair reads one item and re-encodes it as the two members the caller reads,
// with the hit count exactly as the source wrote it. An item missing either
// member, or carrying the wrong type for one, is not the shape the endpoint
// documents and fails the answer rather than arriving half-formed.
func (d *logsDecoder) pair() ([]byte, int64, error) {
	if err := d.expect('{'); err != nil {
		return nil, 0, err
	}
	value, hits := "", ""
	hasValue, hasHits := false, false
	for d.decoder.More() {
		key, err := d.key()
		if err != nil {
			return nil, 0, err
		}
		switch key {
		case "value":
			value, err = d.text()
			hasValue = err == nil
		case "hits":
			hits, err = d.number()
			hasHits = err == nil
		default:
			err = d.skip(0)
		}
		if err != nil {
			return nil, 0, err
		}
	}
	if err := d.expect('}'); err != nil {
		return nil, 0, err
	}
	if !hasValue || !hasHits {
		return nil, 0, errMalformed
	}
	var out bytes.Buffer
	out.WriteString(`{"value":`)
	out.Write(jsonString(value))
	out.WriteString(`,"hits":`)
	out.WriteString(hits)
	out.WriteByte('}')
	// The item costs the byte cap its value text and the digits of its count.
	return out.Bytes(), int64(len(value) + len(hits)), nil
}

// number reads one JSON number as the text the source wrote.
func (d *logsDecoder) number() (string, error) {
	token, err := d.next()
	if err != nil {
		return "", err
	}
	value, ok := token.(json.Number)
	if !ok {
		return "", errMalformed
	}
	return value.String(), nil
}
