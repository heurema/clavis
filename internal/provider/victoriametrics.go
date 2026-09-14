package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
)

type victoriaMetrics struct{}

func (victoriaMetrics) Type() auth.ProviderType { return auth.ProviderVictoriaMetrics }

// ParseTarget accepts a base URL plus an authentication method. Only the
// non-secret half of the method lives in the target: the basic username or the
// custom header name.
func (victoriaMetrics) ParseTarget(raw map[string]string) (map[string]string, error) {
	if err := allowedKeys(raw, keyURL, keyAuth, keyUser, keyHeader); err != nil {
		return nil, err
	}
	return httpTarget(raw)
}

func (victoriaMetrics) ValidateSecret(target map[string]string, secret auth.Secret) error {
	return validateHTTPSecret(target, secret)
}

// Probe sends exactly one GET to the health endpoint under the stored
// authentication. A metrics target carries no headers of its own.
func (victoriaMetrics) Probe(ctx context.Context, target map[string]string, secret auth.Secret) auth.CheckOutcome {
	return httpProbe(ctx, target, secret, nil)
}

// The read-only endpoints of the source's Prometheus API. No other path is
// reachable: the endpoint is chosen from the input, never composed from one.
const (
	metricsQueryPath      = "/api/v1/query"
	metricsQueryRangePath = "/api/v1/query_range"
	metricsLabelsPath     = "/api/v1/labels"
	metricsLabelPrefix    = "/api/v1/label/"
	metricsValuesSuffix   = "/values"
	metricsSeriesPath     = "/api/v1/series"
)

// The result types the platform names for the discovery endpoints. An
// expression's type is the source's own word and is never inferred here.
const (
	resultTypeLabels      = "labels"
	resultTypeLabelValues = "labelValues"
	resultTypeSeries      = "series"
)

const (
	metricsStatusSuccess = "success"
	metricsStatusError   = "error"
	// The source's own classification of an evaluation it aborted, which is
	// the platform's timeout rather than a rejection to show the caller.
	metricsTimeoutType = "timeout"

	metricsFormType = "application/x-www-form-urlencoded"
)

// metricsCall is one request to one endpoint. Exactly one of form and query is
// set: the two query endpoints take a form-encoded POST, the three metadata
// endpoints a GET, which is what the source documents for each.
type metricsCall struct {
	method     string
	path       string
	form       url.Values
	query      url.Values
	resultType string
	discovery  bool
}

// Execute forwards one input to one endpoint and returns the source's own
// answer under the connection's bounds. Nothing here parses PromQL, a time, a
// step or a selector: the strings reach the source as they were submitted and
// the source's acceptance rules are the only ones that apply.
func (victoriaMetrics) Execute(ctx context.Context, target map[string]string, secret auth.Secret, request ExecuteRequest) (ExecuteResult, error) {
	request = boundedRequest(request)
	timeout := sourceTimeout(request.Timeout)
	call, err := metricsEndpoint(request, timeout)
	if err != nil {
		return ExecuteResult{}, err
	}
	httpRequest, err := metricsRequest(ctx, target, secret, call)
	if err != nil {
		return ExecuteResult{}, err
	}
	// The client is built per execution, as the probe's is, and its deadline
	// is the source's own timeout plus the documented grace for writing and
	// reading the answer.
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
		return ExecuteResult{}, metricsHTTPError(response)
	}
	result, err := metricsBody(response.Body, call, request)
	if err != nil {
		return ExecuteResult{}, metricsBodyError(err)
	}
	return result, nil
}

// metricsRequest builds the one HTTP request, applying the stored
// authentication exactly as the probe does.
func metricsRequest(ctx context.Context, target map[string]string, secret auth.Secret, call metricsCall) (*http.Request, error) {
	endpoint := target[keyURL] + call.path
	if call.query != nil {
		endpoint += "?" + call.query.Encode()
	}
	var body io.Reader
	if call.form != nil {
		body = strings.NewReader(call.form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, call.method, endpoint, body)
	if err != nil {
		return nil, ErrUnreachable
	}
	request.Header.Set("Accept", "application/json")
	if call.form != nil {
		request.Header.Set("Content-Type", metricsFormType)
	}
	applyHTTPAuth(request, target, secret)
	return request, nil
}

// metricsEndpoint chooses the endpoint and builds its parameters from the
// input. Only the fields that were given travel: an absent end or step is an
// absent parameter, so the source applies its own default rather than one the
// platform invented.
func metricsEndpoint(request ExecuteRequest, timeout time.Duration) (metricsCall, error) {
	if !metricsInput(request) {
		return metricsCall{}, ErrUnsupportedInput
	}
	seconds := timeoutValue(timeout)
	if request.PromQL != "" {
		form := url.Values{"query": {request.PromQL}}
		path := metricsQueryPath
		if request.Start != "" {
			path = metricsQueryRangePath
			form.Set("start", request.Start)
			setParameter(form, "end", request.End)
			setParameter(form, "step", request.Step)
		} else {
			setParameter(form, "time", request.At)
		}
		form.Set("timeout", seconds)
		return metricsCall{method: http.MethodPost, path: path, form: form}, nil
	}
	query := url.Values{}
	// A series request carries its selector as the first match[]; an optional
	// match narrows any discovery request and is repeated after it.
	for _, selector := range []string{request.Series, request.Match} {
		if selector != "" {
			query.Add("match[]", selector)
		}
	}
	setParameter(query, "start", request.Start)
	setParameter(query, "end", request.End)
	// The source's own cap, asked for one item beyond ours so a full answer is
	// still recognisable as one the platform cut. The platform's cap is the
	// authoritative one: a source that ignores limit changes nothing here.
	query.Set("limit", strconv.Itoa(request.MaxRows+1))
	query.Set("timeout", seconds)
	call := metricsCall{method: http.MethodGet, query: query, discovery: true}
	switch {
	case request.Labels:
		call.path, call.resultType = metricsLabelsPath, resultTypeLabels
	case request.LabelValues != "":
		// The one metrics input that is validated, because it forms a path
		// segment; the escape is belt and braces over that grammar.
		if !auth.ValidLabelName(request.LabelValues) {
			return metricsCall{}, ErrUnsupportedInput
		}
		call.path = metricsLabelPrefix + url.PathEscape(request.LabelValues) + metricsValuesSuffix
		call.resultType = resultTypeLabelValues
	default:
		call.path, call.resultType = metricsSeriesPath, resultTypeSeries
	}
	return call, nil
}

// metricsInput reports whether the request carries exactly one input this
// provider takes, with the time fields that input allows. The service decides
// this first, with a hint naming the right input; this is the backstop.
func metricsInput(request ExecuteRequest) bool {
	inputs := 0
	for _, set := range []bool{request.SQL != "", request.PromQL != "", request.Labels,
		request.LabelValues != "", request.Series != ""} {
		if set {
			inputs++
		}
	}
	if inputs != 1 || request.SQL != "" || logsFields(request) {
		return false
	}
	if request.PromQL == "" {
		// Discovery takes a selector and a range, never an instant or a step.
		return request.At == "" && request.Step == ""
	}
	if request.Start == "" {
		// An instant query takes a pinned time, and nothing a range needs:
		// a step or an end the endpoint has no parameter for would be
		// dropped in silence rather than answered.
		return request.Step == "" && request.End == "" && request.Match == ""
	}
	return request.At == "" && request.Match == ""
}

// metricsBodyError turns the two body failures into the source failure the
// caller sees. The messages are the platform's own fixed text: the body that
// produced them was never read as the source's words.
func metricsBodyError(err error) error {
	switch {
	case errors.Is(err, errBodyTooLarge):
		return &SourceError{Failure: auth.SourceFailure{
			ErrorType: ResponseTooLarge,
			Message:   "The source's answer passed the response ceiling and was not read as data.",
		}}
	case errors.Is(err, errMalformed):
		return &SourceError{Failure: auth.SourceFailure{
			ErrorType: MalformedResponse,
			Message:   "The source's answer could not be read as a Prometheus API response.",
		}}
	default:
		return err
	}
}

// metricsStatusError maps an answer the source refused to give. Its own error
// envelope is preferred; a status without one travels as the status itself
// with a bounded prefix of whatever text came with it, which is what a proxy
// or a gateway in front of the source usually answers.
func metricsHTTPError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))
	if err != nil {
		// A deadline reached while reading an error body is the timeout the
		// caller was promised, not a source rejection with half its text.
		return readError(err)
	}
	var envelope struct {
		Status    string `json:"status"`
		ErrorType string `json:"errorType"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Status == metricsStatusError {
		return metricsEnvelopeError(envelope.ErrorType, envelope.Error)
	}
	return &SourceError{Failure: auth.SourceFailure{
		ErrorType: "http_" + strconv.Itoa(response.StatusCode),
		Message:   boundedText(body),
	}}
}

// metricsEnvelopeError is the source's own rejection. Its words reach the
// caller who wrote the expression and nothing else; an evaluation the source
// aborted is the timeout the caller was promised rather than a rejection.
func metricsEnvelopeError(errorType, message string) error {
	if errorType == metricsTimeoutType {
		return ErrTimeout
	}
	return &SourceError{Failure: auth.SourceFailure{ErrorType: errorType, Message: message}}
}

// metricsDecoder walks the source's answer with the shared token walker: the
// document may be far larger than the response the caller is allowed, and the
// samples that fit must be kept in source order while the rest is read and
// dropped.
type metricsDecoder struct {
	*jsonWalker
	// The same keeper the SQL executor applies to rows: the sample cap is the
	// row cap, and the byte cap counts the text that was kept.
	keeper *rowKeeper
	call   metricsCall

	status     string
	hasStatus  bool
	errorType  string
	errorText  string
	warnings   []string
	infos      []string
	isPartial  bool
	resultType string
	result     []byte
}

// metricsBody reads one answer under the ceiling and the connection's caps.
func metricsBody(body io.Reader, call metricsCall, request ExecuteRequest) (ExecuteResult, error) {
	ceiling := int64(auth.MetricsBodyCeiling(request.MaxBytes)) + 1
	reader := &ceilingReader{reader: io.LimitReader(body, ceiling), remaining: ceiling}
	decoder := json.NewDecoder(reader)
	// Timestamps and sample values keep the digits the source wrote: a float
	// round trip would change what the caller is told the source said.
	decoder.UseNumber()
	walk := &metricsDecoder{
		jsonWalker: &jsonWalker{decoder: decoder},
		keeper:     &rowKeeper{maxRows: request.MaxRows, maxBytes: int64(request.MaxBytes)},
		call:       call,
	}
	if err := walk.envelope(); err != nil {
		return ExecuteResult{}, err
	}
	if !walk.hasStatus {
		return ExecuteResult{}, errMalformed
	}
	switch walk.status {
	case metricsStatusError:
		// The status may follow the data, so a source that streamed samples
		// and then failed is a failure, not a short answer.
		return ExecuteResult{}, metricsEnvelopeError(walk.errorType, walk.errorText)
	case metricsStatusSuccess:
	default:
		return ExecuteResult{}, errMalformed
	}
	if walk.result == nil || walk.resultType == "" {
		return ExecuteResult{}, errMalformed
	}
	return ExecuteResult{
		ResultType: walk.resultType,
		Result:     walk.result,
		Warnings:   walk.warnings,
		Infos:      walk.infos,
		IsPartial:  walk.isPartial,
		Truncated:  walk.keeper.dropped,
		Statements: 1,
		Rows:       walk.keeper.rows,
		Bytes:      walk.keeper.bytes,
	}, nil
}

// envelope reads the one top-level object to its end, whatever the caps did to
// the data inside it, so a status or an error that follows the data is honoured.
func (d *metricsDecoder) envelope() error {
	if err := d.expect('{'); err != nil {
		return err
	}
	for d.decoder.More() {
		key, err := d.key()
		if err != nil {
			return err
		}
		switch key {
		case "status":
			d.status, err = d.text()
			d.hasStatus = err == nil
		case "errorType":
			d.errorType, err = d.text()
		case "error":
			d.errorText, err = d.text()
		case "warnings":
			d.warnings, err = d.texts()
		case "infos":
			d.infos, err = d.texts()
		case "isPartial":
			d.isPartial, err = d.flag()
		case "data":
			err = d.data()
		default:
			// A source answers keys of its own, such as query statistics.
			// They are skipped rather than refused: the platform judges the
			// envelope it documents, not what a source adds beside it.
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
	token, err := d.decoder.Token()
	if err == nil {
		_ = token
		return errMalformed
	}
	if !errors.Is(err, io.EOF) {
		return readError(err)
	}
	return nil
}

// data branches on the shape the endpoint answers: an object holding the
// result type and the result for an expression, the list itself for discovery.
func (d *metricsDecoder) data() error {
	token, err := d.next()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		// A null data member is an absent one: the status decides the outcome,
		// so a source that says error and null data reports its own error.
		if token == nil {
			if d.call.discovery {
				d.resultType, d.result = d.call.resultType, []byte("[]")
			}
			return nil
		}
		return errMalformed
	}
	switch {
	case d.call.discovery && delim == '[':
		d.resultType = d.call.resultType
		return d.discovery()
	case !d.call.discovery && delim == '{':
		return d.queryData()
	default:
		return errMalformed
	}
}

// queryData reads the result type and the result, in whichever order the
// source wrote them; the result is read without needing the type, which is why
// an instant query answering a matrix needs nothing special.
func (d *metricsDecoder) queryData() error {
	for d.decoder.More() {
		key, err := d.key()
		if err != nil {
			return err
		}
		switch key {
		case "resultType":
			d.resultType, err = d.text()
		case "result":
			err = d.queryResult()
		default:
			err = d.skip(0)
		}
		if err != nil {
			return err
		}
	}
	return d.expect('}')
}

// queryResult reads the result array. Its first element tells a list of series
// from the pair a scalar or a string answers, so the shape is read from the
// document rather than assumed from the request.
func (d *metricsDecoder) queryResult() error {
	token, err := d.next()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		if token == nil {
			d.result = []byte("[]")
			return nil
		}
		return errMalformed
	}
	if delim != '[' {
		return errMalformed
	}
	var out bytes.Buffer
	out.WriteByte('[')
	if d.decoder.More() {
		first, err := d.next()
		if err != nil {
			return err
		}
		if delim, ok := first.(json.Delim); ok && delim == '{' {
			err = d.seriesList(&out)
		} else {
			err = d.scalarResult(&out, first)
		}
		if err != nil {
			return err
		}
	}
	if err := d.expect(']'); err != nil {
		return err
	}
	out.WriteByte(']')
	d.result = out.Bytes()
	return nil
}

// seriesList reads the series of a vector or a matrix, the opening brace of
// the first one already consumed.
func (d *metricsDecoder) seriesList(out *bytes.Buffer) error {
	first := true
	for {
		series, kept, err := d.series()
		if err != nil {
			return err
		}
		if kept {
			if !first {
				out.WriteByte(',')
			}
			out.Write(series)
			first = false
		}
		if !d.decoder.More() {
			return nil
		}
		token, err := d.next()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); !ok || delim != '{' {
			return errMalformed
		}
	}
}

// series reads one series object, its opening brace already consumed. The
// members are written back in the order they were read, so the source's own
// order survives; a series that lost samples gains the truncation mark, and a
// vector entry whose one sample was cut is dropped, because half of a sample
// is not a shape any caller can read.
func (d *metricsDecoder) series() ([]byte, bool, error) {
	// Once the byte cap is spent, a later series is read and dropped whole,
	// labels included: kept bytes then stay bounded by the cap plus the one
	// series that crossed it, which is what the route and the CLI read under.
	// The sample cap alone keeps a series with its labels and no samples.
	if d.keeper.started && d.keeper.bytes > d.keeper.maxBytes {
		for d.decoder.More() {
			if _, err := d.key(); err != nil {
				return nil, false, err
			}
			if err := d.skip(0); err != nil {
				return nil, false, err
			}
		}
		if err := d.expect('}'); err != nil {
			return nil, false, err
		}
		d.keeper.dropped = true
		return nil, false, nil
	}
	var out bytes.Buffer
	out.WriteByte('{')
	first, cut, dropped := true, false, false
	for d.decoder.More() {
		key, err := d.key()
		if err != nil {
			return nil, false, err
		}
		var member bytes.Buffer
		switch key {
		case "metric":
			size, err := d.labelSet(&member)
			if err != nil {
				return nil, false, err
			}
			// Label text is kept content and counts against the byte cap, but
			// never decides a sample on its own: a series is emitted with its
			// labels even when every sample of it was cut.
			d.keeper.bytes += size
		case "value":
			size, err := d.pair(&member)
			if err != nil {
				return nil, false, err
			}
			if !d.keeper.keep(size) {
				dropped, d.keeper.dropped = true, true
				continue
			}
		case "values":
			lost, err := d.pairs(&member)
			if err != nil {
				return nil, false, err
			}
			if lost {
				cut, d.keeper.dropped = true, true
			}
		default:
			// A member the platform does not know is the source's own and
			// travels as it is, under the same byte accounting.
			size, err := d.raw(&member)
			if err != nil {
				return nil, false, err
			}
			d.keeper.bytes += size
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(jsonString(key))
		out.WriteByte(':')
		out.Write(member.Bytes())
	}
	if err := d.expect('}'); err != nil {
		return nil, false, err
	}
	if cut {
		if !first {
			out.WriteByte(',')
		}
		out.WriteString(`"truncated":true`)
	}
	out.WriteByte('}')
	return out.Bytes(), !dropped, nil
}

// discovery reads a metadata list, its opening bracket already consumed: label
// names and label values are strings, a series list is label sets. Each item
// is one sample; an item beyond a cap is dropped whole, because an item is
// what the caller asked for.
func (d *metricsDecoder) discovery() error {
	var out bytes.Buffer
	out.WriteByte('[')
	first := true
	for d.decoder.More() {
		token, err := d.next()
		if err != nil {
			return err
		}
		var item bytes.Buffer
		var size int64
		if delim, ok := token.(json.Delim); ok {
			if delim != '{' {
				return errMalformed
			}
			if size, err = d.labelSetBody(&item); err != nil {
				return err
			}
		} else {
			text, ok := token.(string)
			if !ok {
				return errMalformed
			}
			item.Write(jsonString(text))
			size = int64(len(text))
		}
		if !d.keeper.keep(size) {
			d.keeper.dropped = true
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(item.Bytes())
	}
	if err := d.expect(']'); err != nil {
		return err
	}
	out.WriteByte(']')
	d.result = out.Bytes()
	return nil
}

// labelSet reads a label set and returns the UTF-8 length of the names and
// values it kept.
func (d *metricsDecoder) labelSet(out *bytes.Buffer) (int64, error) {
	token, err := d.next()
	if err != nil {
		return 0, err
	}
	if token == nil {
		out.WriteString("{}")
		return 0, nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return 0, errMalformed
	}
	return d.labelSetBody(out)
}

// labelSetBody reads a label set whose opening brace is already consumed,
// writing the pairs back in the order the source wrote them.
func (d *metricsDecoder) labelSetBody(out *bytes.Buffer) (int64, error) {
	out.WriteByte('{')
	var size int64
	first := true
	for d.decoder.More() {
		name, err := d.key()
		if err != nil {
			return 0, err
		}
		value, err := d.text()
		if err != nil {
			return 0, err
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(jsonString(name))
		out.WriteByte(':')
		out.Write(jsonString(value))
		size += int64(len(name) + len(value))
	}
	if err := d.expect('}'); err != nil {
		return 0, err
	}
	out.WriteByte('}')
	return size, nil
}

// pairs reads a matrix series' samples, keeping them in order until a cap is
// reached and reporting whether any were lost.
func (d *metricsDecoder) pairs(out *bytes.Buffer) (bool, error) {
	token, err := d.next()
	if err != nil {
		return false, err
	}
	if token == nil {
		out.WriteString("[]")
		return false, nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return false, errMalformed
	}
	out.WriteByte('[')
	lost, first := false, true
	for d.decoder.More() {
		var sample bytes.Buffer
		size, err := d.pair(&sample)
		if err != nil {
			return false, err
		}
		// A sample beyond a cap is read and dropped: what the source did must
		// never depend on what the caller is shown.
		if !d.keeper.keep(size) {
			lost = true
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(sample.Bytes())
	}
	if err := d.expect(']'); err != nil {
		return false, err
	}
	out.WriteByte(']')
	return lost, nil
}

// pair reads one timestamp and value, returning the UTF-8 length of the value
// text; the timestamp is a number and costs the byte cap nothing.
func (d *metricsDecoder) pair(out *bytes.Buffer) (int64, error) {
	if err := d.expect('['); err != nil {
		return 0, err
	}
	out.WriteByte('[')
	var size int64
	first := true
	for d.decoder.More() {
		token, err := d.next()
		if err != nil {
			return 0, err
		}
		encoded, text, err := metricsScalar(token)
		if err != nil {
			return 0, err
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.WriteString(encoded)
		size += text
	}
	if err := d.expect(']'); err != nil {
		return 0, err
	}
	out.WriteByte(']')
	return size, nil
}

// scalarResult reads the pair a scalar or a string answers, its first element
// already read. It is one sample.
func (d *metricsDecoder) scalarResult(out *bytes.Buffer, token json.Token) error {
	encoded, size, err := metricsScalar(token)
	if err != nil {
		return err
	}
	elements, total := []string{encoded}, size
	for d.decoder.More() {
		next, err := d.next()
		if err != nil {
			return err
		}
		encoded, size, err = metricsScalar(next)
		if err != nil {
			return err
		}
		elements, total = append(elements, encoded), total+size
	}
	if !d.keeper.keep(total) {
		d.keeper.dropped = true
		return nil
	}
	out.WriteString(strings.Join(elements, ","))
	return nil
}

// raw keeps a value the platform has no opinion about, compacted so it costs
// the response only what it holds.
func (d *metricsDecoder) raw(out *bytes.Buffer) (int64, error) {
	var message json.RawMessage
	if err := d.decoder.Decode(&message); err != nil {
		return 0, readError(err)
	}
	if err := json.Compact(out, message); err != nil {
		return 0, errMalformed
	}
	return int64(out.Len()), nil
}

func (d *metricsDecoder) texts() ([]string, error) {
	token, err := d.next()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return nil, errMalformed
	}
	var texts []string
	for d.decoder.More() {
		text, err := d.text()
		if err != nil {
			return nil, err
		}
		texts = append(texts, text)
	}
	if err := d.expect(']'); err != nil {
		return nil, err
	}
	return texts, nil
}

func (d *metricsDecoder) flag() (bool, error) {
	token, err := d.next()
	if err != nil {
		return false, err
	}
	flag, ok := token.(bool)
	if !ok {
		return false, errMalformed
	}
	return flag, nil
}

// metricsScalar re-encodes one primitive and reports the UTF-8 length it costs
// the byte cap, which is its text when it is one and nothing when it is a
// number: a sample's value is a string in this format, and its timestamp is
// not text the caller asked for.
func metricsScalar(token json.Token) (string, int64, error) {
	switch value := token.(type) {
	case json.Number:
		return value.String(), 0, nil
	case string:
		return string(jsonString(value)), int64(len(value)), nil
	case bool:
		return strconv.FormatBool(value), 0, nil
	case nil:
		return "null", 0, nil
	default:
		return "", 0, errMalformed
	}
}
