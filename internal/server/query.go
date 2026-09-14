package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/heurema/clavis/internal/auth"
)

// queryBodyAllowance is what the request body may add on top of the SQL
// itself: the JSON framing, the connection reference and maxRows. The CLI
// bounds its own request with the same sum, so a body one side refuses is a
// body the other never builds.
const queryBodyAllowance = 4096

// The hints below are the adapter's own. A request that fails these checks
// never reaches the service, so the guidance has to be given here; none of
// them echoes a submitted value, and none of them repeats the SQL.
var (
	hintQueryBody       = "Send a JSON object with connection, one input and an optional positive maxRows"
	hintQueryConnection = "Address the connection by its UUID or its name"
	hintQueryInput      = "Send exactly one of sql, promql, labels, labelValues, series, logsql, fieldNames, " +
		"fieldValues, streams, streamFieldNames or streamFieldValues"
	hintQueryText = "sql, promql, logsql, series, match and a field name are each at most " +
		strconv.Itoa(auth.MaxSQLBytes) + " bytes, and filter at most " + strconv.Itoa(auth.MaxFilterBytes)
	hintQueryLabel   = "labelValues is one Prometheus label name"
	hintQueryMaxRows = "maxRows is optional and must be a positive integer at or below the connection's row cap"
)

// jsonBool reads the one boolean member the execution body carries. Like every
// other member it has exactly one decoder, so a quoted or numeric value is a
// rejection rather than a coercion.
func jsonBool(assign func(bool)) jsonValue {
	return func(decoder *json.Decoder) error {
		token, err := decoder.Token()
		value, ok := token.(bool)
		if err != nil || !ok {
			return &auth.Error{Code: auth.InvalidArgument}
		}
		assign(value)
		return nil
	}
}

// jsonInt64Pointer reads the one optional integer the execution body carries.
// The pointer is the point of it: an absent limit is the caller saying nothing
// and an explicit zero is the caller's own "no limit", and the two reach the
// source as no parameter and as a sent zero. A quoted or fractional value is a
// rejection rather than a coercion, like every other member here.
func jsonInt64Pointer(assign func(int64)) jsonValue {
	return func(decoder *json.Decoder) error {
		token, err := decoder.Token()
		number, ok := token.(json.Number)
		if err != nil || !ok {
			return invalidArgument()
		}
		value, convErr := strconv.ParseInt(number.String(), 10, 64)
		if convErr != nil {
			return invalidArgument()
		}
		assign(value)
		return nil
	}
}

// The executor owns authorization, the credential and the source call; a
// composition without one must reject the route instead of invoking anything.
func (a *authHTTP) requireExecutor() error {
	if a.executor == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

// queryRequest decodes and locally validates the one execution body. The SQL,
// the expression, the query, the times, the selectors and the filter are
// bounded but never inspected: the platform forwards them unchanged, so the
// only judgements here are shape, size, the connection reference and the label
// name that forms a path segment on the source. Which input fits the
// connection's provider, and which time fields, limit and filter that input
// takes, are the service's to decide on the record.
func queryRequest(r *http.Request, request *auth.QueryRequest) error {
	if _, err := query(r); err != nil {
		return err
	}
	var maxRows bool
	if err := decodeFields(r, auth.MaxSQLBytes+queryBodyAllowance, map[string]jsonValue{
		"connection":  jsonString(func(value string) { request.Connection = value }),
		"sql":         jsonString(func(value string) { request.SQL = value }),
		"promql":      jsonString(func(value string) { request.PromQL = value }),
		"at":          jsonString(func(value string) { request.At = value }),
		"start":       jsonString(func(value string) { request.Start = value }),
		"end":         jsonString(func(value string) { request.End = value }),
		"step":        jsonString(func(value string) { request.Step = value }),
		"labels":      jsonBool(func(value bool) { request.Labels = value }),
		"labelValues": jsonString(func(value string) { request.LabelValues = value }),
		"series":      jsonString(func(value string) { request.Series = value }),
		"match":       jsonString(func(value string) { request.Match = value }),
		// The log inputs and the two parameters the log endpoints take beside
		// them. Which endpoint takes which is the service's rule, decided on
		// the connection's own record.
		"logsql":            jsonString(func(value string) { request.LogsQL = value }),
		"fieldNames":        jsonBool(func(value bool) { request.FieldNames = value }),
		"fieldValues":       jsonString(func(value string) { request.FieldValues = value }),
		"streams":           jsonBool(func(value bool) { request.Streams = value }),
		"streamFieldNames":  jsonBool(func(value bool) { request.StreamFieldNames = value }),
		"streamFieldValues": jsonString(func(value string) { request.StreamFieldValues = value }),
		"limit":             jsonInt64Pointer(func(value int64) { request.Limit = &value }),
		"filter":            jsonString(func(value string) { request.Filter = value }),
		"maxRows":           jsonInt(func(value int) { request.MaxRows, maxRows = value, true }),
	}); err != nil {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryBody}
	}
	if !auth.ValidConnectionRef(request.Connection) {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryConnection}
	}
	inputs := 0
	for _, set := range []bool{request.SQL != "", request.PromQL != "", request.Labels,
		request.LabelValues != "", request.Series != "", request.LogsQL != "", request.FieldNames,
		request.FieldValues != "", request.Streams, request.StreamFieldNames, request.StreamFieldValues != ""} {
		if set {
			inputs++
		}
	}
	if inputs != 1 {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryInput}
	}
	for _, text := range []string{request.SQL, request.PromQL, request.Series, request.Match,
		request.LogsQL, request.FieldValues, request.StreamFieldValues} {
		if len(text) > auth.MaxSQLBytes {
			return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryText}
		}
	}
	// A filter is a substring the source matches against a value, not a query,
	// so it carries the short bound of its own.
	if len(request.Filter) > auth.MaxFilterBytes {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryText}
	}
	if request.LabelValues != "" && !auth.ValidLabelName(request.LabelValues) {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryLabel}
	}
	// The connection's own cap is the service's to apply; only a value that can
	// never lower anything is refused here.
	if maxRows && request.MaxRows < 1 {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryMaxRows}
	}
	return nil
}

// executeQueryJSON is the one execution route. It follows the shared shape of
// the grant and connection routes: bounded body first, then a bearer-only
// session, then the service call, with every failure rendered through the one
// envelope, which carries the source's own rejection as error.source.
//
// The results are encoded and served as they are. The drain keeps the row that
// crosses the byte cap and always keeps the first row, and JSON escaping grows
// values, so a legitimate response can exceed the connection's byte cap plus
// the envelope allowance; refusing it here would turn a correct execution into
// a fault. The CLI reads the body under a bound with the escaping headroom.
func (a *authHTTP) executeQueryJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.QueryRequest
	err := queryRequest(r, &request)
	var session auth.Session
	if err == nil {
		session, err = a.cliSession(r)
	}
	if err == nil {
		err = a.requireExecutor()
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	response, err := a.executor.ExecuteQuery(r.Context(), session, request)
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
