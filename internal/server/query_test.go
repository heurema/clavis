package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

// fakeExecutor records exactly what the route handed the execution service, so
// a rejected request can be proven never to have reached it. It is embedded in
// backendFixture, which supplies the session.
type fakeExecutor struct {
	queryResponse auth.QueryResponse
	queryErr      error
	queryCalls    []queryCall
	queryBlock    func(context.Context)
	// queryDeadline is what the route gave the service to work in, which is
	// the one fact the execution budget is about.
	queryDeadline   time.Time
	queryDeadlineOK bool
}

type queryCall struct {
	request auth.QueryRequest
	role    auth.Role
}

func (f *fakeExecutor) ExecuteQuery(ctx context.Context, session auth.Session, request auth.QueryRequest) (auth.QueryResponse, error) {
	f.queryCalls = append(f.queryCalls, queryCall{request: request, role: session.User.Role})
	f.queryDeadline, f.queryDeadlineOK = ctx.Deadline()
	if f.queryBlock != nil {
		f.queryBlock(ctx)
	}
	return f.queryResponse, f.queryErr
}

const (
	queryConnection = "payments-prod-reporting"
	validQueryBody  = `{"connection":"` + queryConnection + `","sql":"select 1"}`
	querySentinel   = "SENTINEL_PRIVATE_SQL"
)

func text(value string) *string { return &value }

var queryResults = auth.QueryResponse{
	Results: []auth.QueryResult{{
		Command: "SELECT",
		Columns: []auth.QueryColumn{{Name: "id", Type: "int8"}, {Name: "label", Type: "text"}},
		Rows:    [][]*string{{text("1"), text("alpha")}, {text("2"), nil}},
		// The row bound cut this result, so both flags are set.
		RowCount: 2, Truncated: true,
	}, {
		Command: "UPDATE", Columns: []auth.QueryColumn{}, Rows: [][]*string{}, RowCount: 3,
	}},
	Truncated: true, DurationMS: 17,
}

// metricsAnswer is the other documented document: the source's own result
// under the provider that named it, with its warnings and its partial flag.
var metricsAnswer = auth.QueryResponse{
	Provider:   auth.ProviderVictoriaMetrics,
	ResultType: "vector",
	Result:     json.RawMessage(`[{"metric":{"__name__":"up","job":"api"},"value":[1700000000,"1"]}]`),
	Warnings:   []string{"the range is long"},
	IsPartial:  true,
	DurationMS: 9,
}

// logsAnswer is the third documented document: the source's own rows under the
// provider that named them. A log source writes no warnings, no infos and no
// partial flag, so none of them appears beside it.
var logsAnswer = auth.QueryResponse{
	Provider:   auth.ProviderVictoriaLogs,
	ResultType: "logs",
	Result: json.RawMessage(`[{"_time":"2026-09-14T10:00:00Z","_msg":"boom","level":"error"},` +
		`{"_time":"2026-09-14T10:00:01Z","_msg":"again","level":"warn"}]`),
	DurationMS: 11,
}

// limitOf is how a test sets the one optional integer, where an absent limit
// and an explicit zero are different requests.
func limitOf(value int64) *int64 { return &value }

func queryFixture(t *testing.T) (*backendFixture, http.Handler) {
	t.Helper()
	f := &backendFixture{}
	f.queryResponse = queryResults
	return f, authHandler(t, f, nil, "http://127.0.0.1")
}

func queryHeaders() http.Header { return bearerHeaders("Content-Type", "application/json") }

func TestQueryRouteReturnsTheDocumentedResultsDocument(t *testing.T) {
	f, handler := queryFixture(t)
	// Browser negotiation headers must never turn the route into a document.
	headers := queryHeaders()
	headers.Set("Accept", "text/html")
	headers.Set("Hx-Request", "true")
	response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, headers)
	require.Equal(t, 200, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Empty(t, response.Header().Get("Set-Cookie"))
	expected, err := json.Marshal(queryResults)
	require.NoError(t, err)
	require.JSONEq(t, string(expected), response.Body.String())
	// A NULL is null, and every value is a string: the shape an agent branches
	// on never depends on the statement it sent.
	require.Contains(t, response.Body.String(), `["2",null]`)
	require.Equal(t, []queryCall{{request: auth.QueryRequest{Connection: queryConnection, SQL: "select 1"}, role: auth.Admin}}, f.queryCalls)
}

// Members are the reason this route exists, so the adapter hands the session
// to the service rather than deciding on the role itself.
func TestQueryRoutePassesMemberSessionsToTheService(t *testing.T) {
	f, handler := queryFixture(t)
	f.role = auth.Member
	response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	require.Equal(t, 200, response.Code)
	require.Len(t, f.queryCalls, 1)
	require.Equal(t, auth.Member, f.queryCalls[0].role)
}

func TestQueryRouteSendsTheRequestUnchanged(t *testing.T) {
	f, handler := queryFixture(t)
	script := "insert into notes values ('x');\nselect count(*) from notes;\n"
	body, err := json.Marshal(auth.QueryRequest{Connection: connectionTargetID, SQL: script, MaxRows: 10})
	require.NoError(t, err)
	require.Equal(t, 200, requestAuth(handler, "POST", auth.QueryPath, string(body), queryHeaders()).Code)
	require.Equal(t, []queryCall{{request: auth.QueryRequest{Connection: connectionTargetID, SQL: script, MaxRows: 10}, role: auth.Admin}}, f.queryCalls)
}

// The SQL is bounded, not inspected: a statement filling the documented bound
// reaches the service exactly as written.
func TestQueryRouteAcceptsTheLargestDocumentedStatement(t *testing.T) {
	f, handler := queryFixture(t)
	script := "select '" + strings.Repeat("x", auth.MaxSQLBytes-len("select ''")) + "'"
	require.Len(t, script, auth.MaxSQLBytes)
	body, err := json.Marshal(auth.QueryRequest{Connection: queryConnection, SQL: script})
	require.NoError(t, err)
	require.Equal(t, 200, requestAuth(handler, "POST", auth.QueryPath, string(body), queryHeaders()).Code)
	require.Len(t, f.queryCalls, 1)
	require.Equal(t, script, f.queryCalls[0].request.SQL)
}

// Every metrics input reaches the service exactly as it was submitted: the
// route decodes the strings and the one boolean and judges nothing about the
// times, the steps or the selectors, which are the source's to interpret.
func TestQueryRouteSendsTheMetricsInputsUnchanged(t *testing.T) {
	for name, request := range map[string]auth.QueryRequest{
		"instant": {Connection: queryConnection, PromQL: "up", At: "2026-09-13T00:00:00Z"},
		"range": {Connection: queryConnection, PromQL: "sum(rate(errors_total[5m])) by (job)",
			Start: "-1h", End: "now", Step: "1m", MaxRows: 10},
		"labels":       {Connection: queryConnection, Labels: true, Match: `{job="api"}`, Start: "-1h"},
		"label values": {Connection: queryConnection, LabelValues: "__name__", End: "now"},
		"series":       {Connection: queryConnection, Series: `{__name__=~"up"}`, Match: `{job="api"}`},
		// A reversed range is the source's to clamp, not the route's to refuse.
		"reversed range": {Connection: queryConnection, PromQL: "up", Start: "now", End: "-1h", Step: "1m"},
	} {
		t.Run(name, func(t *testing.T) {
			f, handler := queryFixture(t)
			f.queryResponse = metricsAnswer
			body, err := json.Marshal(request)
			require.NoError(t, err)
			response := requestAuth(handler, "POST", auth.QueryPath, string(body), queryHeaders())
			require.Equal(t, 200, response.Code, response.Body.String())
			require.Equal(t, []queryCall{{request: request, role: auth.Admin}}, f.queryCalls)
		})
	}
}

// The metrics document is served as the service built it: the provider names
// the shape, the result is the source's own JSON and no results list appears.
func TestQueryRouteServesTheMetricsDocument(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryResponse = metricsAnswer
	response := requestAuth(handler, "POST", auth.QueryPath,
		`{"connection":"`+queryConnection+`","promql":"up"}`, queryHeaders())
	require.Equal(t, 200, response.Code)
	expected, err := json.Marshal(metricsAnswer)
	require.NoError(t, err)
	require.JSONEq(t, string(expected), response.Body.String())
	require.Contains(t, response.Body.String(), `"provider":"victoriametrics"`)
	require.Contains(t, response.Body.String(), `"resultType":"vector"`)
	require.Contains(t, response.Body.String(), `"isPartial":true`)
	require.NotContains(t, response.Body.String(), `"results"`)
}

// A metrics source classifies its own failure, and it has no statements: the
// envelope carries the errorType and leaves the statement out altogether.
func TestQueryRouteRendersAMetricsSourceFailure(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryErr = &auth.Error{Code: auth.SourceError, Source: &auth.SourceFailure{
		ErrorType: "bad_data", Message: `unsupported expression "up ~~"`}}
	response := requestAuth(handler, "POST", auth.QueryPath,
		`{"connection":"`+queryConnection+`","promql":"up ~~"}`, queryHeaders())
	require.Equal(t, 422, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, "bad_data", failure.Source.ErrorType)
	require.Equal(t, `unsupported expression "up ~~"`, failure.Source.Message)
	require.Empty(t, failure.Source.SQLState)
	require.Nil(t, failure.Source.Statement)
	require.NotContains(t, response.Body.String(), "statement")
	require.NotContains(t, response.Body.String(), "sqlstate")
}

// A response above the connection's byte cap plus the envelope allowance is
// still the source's answer: the drain keeps the row that crosses the cap and
// JSON escaping grows values, so the route serves what the service produced
// rather than turning a correct execution into a fault.
// Every log input reaches the service exactly as it was submitted, and an
// absent limit stays a different request from an explicit zero: the source is
// told nothing in the one case and told the caller's own zero in the other.
func TestQueryRouteSendsTheLogInputsUnchanged(t *testing.T) {
	for name, request := range map[string]auth.QueryRequest{
		"logsql":        {Connection: queryConnection, LogsQL: "error | sort by (_time) desc", Start: "-1h", End: "now"},
		"limited":       {Connection: queryConnection, LogsQL: "error", Limit: limitOf(50)},
		"explicit zero": {Connection: queryConnection, LogsQL: "error", Limit: limitOf(0)},
		"field names":   {Connection: queryConnection, FieldNames: true, Match: "*", Filter: "err"},
		"field values": {Connection: queryConnection, FieldValues: "level", Match: "*",
			Filter: "err", Limit: limitOf(5), Start: "-1h"},
		"streams":            {Connection: queryConnection, Streams: true, Match: "*", Limit: limitOf(5)},
		"stream field names": {Connection: queryConnection, StreamFieldNames: true, Match: "*", Filter: "j"},
		"stream field values": {Connection: queryConnection, StreamFieldValues: "job", Match: "*",
			Filter: "api", MaxRows: 10},
	} {
		t.Run(name, func(t *testing.T) {
			f, handler := queryFixture(t)
			f.queryResponse = logsAnswer
			body, err := json.Marshal(request)
			require.NoError(t, err)
			response := requestAuth(handler, "POST", auth.QueryPath, string(body), queryHeaders())
			require.Equal(t, 200, response.Code, response.Body.String())
			require.Equal(t, []queryCall{{request: request, role: auth.Admin}}, f.queryCalls)
		})
	}
	// The two limits are different bodies as well as different requests: the
	// absent one carries no member at all.
	absent, err := json.Marshal(auth.QueryRequest{Connection: queryConnection, LogsQL: "error"})
	require.NoError(t, err)
	require.NotContains(t, string(absent), "limit")
	zero, err := json.Marshal(auth.QueryRequest{Connection: queryConnection, LogsQL: "error", Limit: limitOf(0)})
	require.NoError(t, err)
	require.Contains(t, string(zero), `"limit":0`)
}

// The log document is served as the service built it: the provider names the
// shape, the result is the source's own rows and no results list appears.
func TestQueryRouteServesTheLogDocument(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryResponse = logsAnswer
	response := requestAuth(handler, "POST", auth.QueryPath,
		`{"connection":"`+queryConnection+`","logsql":"error","limit":2}`, queryHeaders())
	require.Equal(t, 200, response.Code)
	expected, err := json.Marshal(logsAnswer)
	require.NoError(t, err)
	require.JSONEq(t, string(expected), response.Body.String())
	require.Contains(t, response.Body.String(), `"provider":"victorialogs"`)
	require.Contains(t, response.Body.String(), `"resultType":"logs"`)
	require.NotContains(t, response.Body.String(), `"results"`)
	require.NotContains(t, response.Body.String(), `"isPartial"`)
	require.Len(t, f.queryCalls, 1)
	require.Equal(t, int64(2), *f.queryCalls[0].request.Limit)
}

// A log source classifies nothing of its own: the platform names the status it
// answered with, and the envelope carries no sqlstate and no statement.
func TestQueryRouteRendersALogSourceFailure(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryErr = &auth.Error{Code: auth.SourceError, Source: &auth.SourceFailure{
		ErrorType: "http_400", Message: `cannot parse "error ~~"`}}
	response := requestAuth(handler, "POST", auth.QueryPath,
		`{"connection":"`+queryConnection+`","logsql":"error ~~"}`, queryHeaders())
	require.Equal(t, 422, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, "http_400", failure.Source.ErrorType)
	require.Equal(t, `cannot parse "error ~~"`, failure.Source.Message)
	require.Empty(t, failure.Source.SQLState)
	require.Nil(t, failure.Source.Statement)
	require.NotContains(t, response.Body.String(), "sqlstate")
}

func TestQueryRouteServesAnOversizedResponseUnchanged(t *testing.T) {
	f, handler := queryFixture(t)
	// Every byte of the value escapes to six, so the encoded body is far above
	// the ceiling while the value itself is inside the byte cap.
	value := strings.Repeat("\x01", 2<<20)
	f.queryResponse = auth.QueryResponse{
		Results: []auth.QueryResult{{
			Command: "SELECT", Columns: []auth.QueryColumn{{Name: "v", Type: "text"}},
			Rows: [][]*string{{text(value)}}, RowCount: 1,
		}},
		DurationMS: 4,
	}
	response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	require.Equal(t, 200, response.Code)
	require.Greater(t, response.Body.Len(), auth.MaxMaxBytes+auth.QueryEnvelopeAllowance)
	var decoded auth.QueryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
	require.Equal(t, value, *decoded.Results[0].Rows[0][0])
}

// A comment-only string is one result with no command word at all, and the
// route carries that through rather than inventing a tag.
func TestQueryRouteCarriesAnEmptyStatementResult(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryResponse = auth.QueryResponse{
		Results:    []auth.QueryResult{{Columns: []auth.QueryColumn{}, Rows: [][]*string{}}},
		DurationMS: 1,
	}
	response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), `"command":""`)
}

// The source's own rejection is the one message in the envelope the platform
// did not write, and it is nested inside the error object rather than beside it.
func TestQueryRouteRendersTheSourceFailureInsideTheEnvelope(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryErr = &auth.Error{Code: auth.SourceError, Hint: "Correct the statement and try again",
		Source: &auth.SourceFailure{SQLState: "42601", Message: `syntax error at or near "selec"`,
			Detail: "detail line", Hint: "source hint", Position: 1, Statement: auth.StatementIndex(0)}}
	response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	require.Equal(t, 422, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, auth.SourceError, failure.Error.Code)
	require.Equal(t, "Correct the statement and try again", failure.Error.Hint)
	require.NotNil(t, failure.Source)
	require.Equal(t, "42601", failure.Source.SQLState)
	require.Equal(t, `syntax error at or near "selec"`, failure.Source.Message)
	require.Equal(t, "detail line", failure.Source.Detail)
	require.Equal(t, "source hint", failure.Source.Hint)
	require.Equal(t, 1, failure.Source.Position)
	// Zero is meaningful: the whole string was rejected before anything ran.
	require.NotNil(t, failure.Source.Statement)
	require.Equal(t, 0, *failure.Source.Statement)
	require.Contains(t, response.Body.String(), `"source":{`)
	// A failure that carries no source block does not grow one.
	f, handler = queryFixture(t)
	f.queryErr = &auth.Error{Code: auth.SourceTimeout}
	response = requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	require.Equal(t, 504, response.Code)
	require.NotContains(t, response.Body.String(), "source")
}

func TestQueryServiceFailuresUseDocumentedStatusesAndHints(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		hint   string
	}{
		{&auth.Error{Code: auth.Unauthenticated}, 401, auth.Unauthenticated, ""},
		{&auth.Error{Code: auth.Forbidden}, 403, auth.Forbidden, ""},
		{&auth.Error{Code: auth.ConnectionNotFound, Hint: "List connections to see what you may use."}, 404,
			auth.ConnectionNotFound, "List connections to see what you may use."},
		{&auth.Error{Code: auth.ConnectionDisabled, Hint: "Ask an administrator to enable it."}, 409,
			auth.ConnectionDisabled, "Ask an administrator to enable it."},
		{&auth.Error{Code: auth.CredentialsUnavailable}, 409, auth.CredentialsUnavailable, ""},
		{&auth.Error{Code: auth.ProviderUnsupported, Hint: "Only postgresql connections execute SQL."}, 400,
			auth.ProviderUnsupported, "Only postgresql connections execute SQL."},
		{&auth.Error{Code: auth.SourceTimeout, Hint: "The statement timeout is 30000 ms."}, 504, auth.SourceTimeout,
			"The statement timeout is 30000 ms."},
		{&auth.Error{Code: auth.SourceUnreachable, Hint: "Run connections check."}, 502, auth.SourceUnreachable, "Run connections check."},
		{&auth.Error{Code: auth.SourceAuthRejected, Hint: "Run connections check."}, 502, auth.SourceAuthRejected, "Run connections check."},
		{&auth.Error{Code: auth.InvalidArgument, Hint: "maxRows must not exceed 1000."}, 400, auth.InvalidArgument,
			"maxRows must not exceed 1000."},
		{errors.New(querySentinel), 503, auth.ServiceUnavailable, ""},
	} {
		t.Run(tc.code, func(t *testing.T) {
			f, handler := queryFixture(t)
			f.queryErr = tc.err
			response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
			require.Equal(t, tc.status, response.Code)
			var failure auth.ErrorResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
			require.Equal(t, tc.code, failure.Error.Code)
			require.Equal(t, tc.hint, failure.Error.Hint)
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		})
	}
}

// Every local rejection names the field it refused without repeating the SQL,
// and none of them reaches the service.
func TestQueryBodiesAndQueriesAreStrict(t *testing.T) {
	oversized, err := json.Marshal(auth.QueryRequest{Connection: queryConnection,
		SQL: "select '" + strings.Repeat("x", auth.MaxSQLBytes) + "'"})
	require.NoError(t, err)
	oversizedExpression, err := json.Marshal(auth.QueryRequest{Connection: queryConnection,
		PromQL: strings.Repeat("u", auth.MaxSQLBytes+1)})
	require.NoError(t, err)
	oversizedQuery, err := json.Marshal(auth.QueryRequest{Connection: queryConnection,
		LogsQL: strings.Repeat("e", auth.MaxSQLBytes+1)})
	require.NoError(t, err)
	oversizedFilter, err := json.Marshal(auth.QueryRequest{Connection: queryConnection,
		FieldNames: true, Match: "*", Filter: strings.Repeat("f", auth.MaxFilterBytes+1)})
	require.NoError(t, err)
	for _, tc := range []struct {
		name, path, body, contentType, hint string
	}{
		{"unknown field", auth.QueryPath, `{"connection":"c-name","sql":"select 1","timeout":5}`, "application/json", hintQueryBody},
		{"duplicate field", auth.QueryPath, `{"connection":"c-name","connection":"other","sql":"select 1"}`, "application/json", hintQueryBody},
		{"case alias", auth.QueryPath, `{"Connection":"c-name","sql":"select 1"}`, "application/json", hintQueryBody},
		{"null sql", auth.QueryPath, `{"connection":"c-name","sql":null}`, "application/json", hintQueryBody},
		{"numeric sql", auth.QueryPath, `{"connection":"c-name","sql":7}`, "application/json", hintQueryBody},
		{"non-object body", auth.QueryPath, `["select 1"]`, "application/json", hintQueryBody},
		{"string body", auth.QueryPath, `"select 1"`, "application/json", hintQueryBody},
		{"trailing document", auth.QueryPath, validQueryBody + `{}`, "application/json", hintQueryBody},
		{"float max rows", auth.QueryPath, `{"connection":"c-name","sql":"select 1","maxRows":1.5}`, "application/json", hintQueryBody},
		{"quoted max rows", auth.QueryPath, `{"connection":"c-name","sql":"select 1","maxRows":"10"}`, "application/json", hintQueryBody},
		{"form body", auth.QueryPath, "connection=c-name&sql=select+1", "application/x-www-form-urlencoded", hintQueryBody},
		{"typeless body", auth.QueryPath, validQueryBody, "", hintQueryBody},
		{"empty body", auth.QueryPath, `{}`, "application/json", hintQueryConnection},
		{"missing connection", auth.QueryPath, `{"sql":"select 1"}`, "application/json", hintQueryConnection},
		{"uppercase connection", auth.QueryPath, `{"connection":"PAYMENTS","sql":"select 1"}`, "application/json", hintQueryConnection},
		{"spaced connection", auth.QueryPath, `{"connection":"c name","sql":"select 1"}`, "application/json", hintQueryConnection},
		{"no input", auth.QueryPath, `{"connection":"c-name"}`, "application/json", hintQueryInput},
		{"empty sql", auth.QueryPath, `{"connection":"c-name","sql":""}`, "application/json", hintQueryInput},
		{"oversized sql", auth.QueryPath, string(oversized), "application/json", hintQueryText},
		{"two inputs", auth.QueryPath, `{"connection":"c-name","sql":"x","promql":"up"}`, "application/json", hintQueryInput},
		{"two metrics inputs", auth.QueryPath, `{"connection":"c-name","labels":true,"series":"up"}`, "application/json", hintQueryInput},
		{"labels false alone", auth.QueryPath, `{"connection":"c-name","labels":false}`, "application/json", hintQueryInput},
		{"quoted labels", auth.QueryPath, `{"connection":"c-name","labels":"true"}`, "application/json", hintQueryBody},
		{"numeric promql", auth.QueryPath, `{"connection":"c-name","promql":7}`, "application/json", hintQueryBody},
		{"null step", auth.QueryPath, `{"connection":"c-name","promql":"up","step":null}`, "application/json", hintQueryBody},
		{"unknown metrics field", auth.QueryPath, `{"connection":"c-name","promql":"up","window":"5m"}`, "application/json", hintQueryBody},
		{"duplicate promql", auth.QueryPath, `{"connection":"c-name","promql":"up","promql":"down"}`, "application/json", hintQueryBody},
		{"bad label name", auth.QueryPath, `{"connection":"c-name","labelValues":"9metric"}`, "application/json", hintQueryLabel},
		{"pathy label name", auth.QueryPath, `{"connection":"c-name","labelValues":"../admin"}`, "application/json", hintQueryLabel},
		{"oversized promql", auth.QueryPath, string(oversizedExpression), "application/json", hintQueryText},
		{"zero max rows", auth.QueryPath, `{"connection":"c-name","sql":"select 1","maxRows":0}`, "application/json", hintQueryMaxRows},
		{"negative max rows", auth.QueryPath, `{"connection":"c-name","sql":"select 1","maxRows":-1}`, "application/json", hintQueryMaxRows},
		// The log half of the same rules: one input, one decoder per member, and
		// a limit that is a JSON integer or nothing at all.
		{"two log inputs", auth.QueryPath, `{"connection":"c-name","logsql":"error","streams":true}`, "application/json", hintQueryInput},
		{"log and sql", auth.QueryPath, `{"connection":"c-name","sql":"x","logsql":"error"}`, "application/json", hintQueryInput},
		{"streams false alone", auth.QueryPath, `{"connection":"c-name","streams":false}`, "application/json", hintQueryInput},
		{"empty logsql", auth.QueryPath, `{"connection":"c-name","logsql":""}`, "application/json", hintQueryInput},
		{"quoted field names", auth.QueryPath, `{"connection":"c-name","fieldNames":"true"}`, "application/json", hintQueryBody},
		{"numeric logsql", auth.QueryPath, `{"connection":"c-name","logsql":7}`, "application/json", hintQueryBody},
		{"quoted limit", auth.QueryPath, `{"connection":"c-name","logsql":"error","limit":"5"}`, "application/json", hintQueryBody},
		{"float limit", auth.QueryPath, `{"connection":"c-name","logsql":"error","limit":1.5}`, "application/json", hintQueryBody},
		{"exponent limit", auth.QueryPath, `{"connection":"c-name","logsql":"error","limit":1e2}`, "application/json", hintQueryBody},
		{"null limit", auth.QueryPath, `{"connection":"c-name","logsql":"error","limit":null}`, "application/json", hintQueryBody},
		{"duplicate limit", auth.QueryPath, `{"connection":"c-name","logsql":"error","limit":1,"limit":2}`, "application/json", hintQueryBody},
		{"unknown log field", auth.QueryPath, `{"connection":"c-name","logsql":"error","tail":true}`, "application/json", hintQueryBody},
		{"oversized logsql", auth.QueryPath, string(oversizedQuery), "application/json", hintQueryText},
		{"oversized filter", auth.QueryPath, string(oversizedFilter), "application/json", hintQueryText},
		{"unknown parameter", auth.QueryPath + "?dryRun=true", validQueryBody, "application/json", ""},
		{"malformed query", auth.QueryPath + "?limit=%zz", validQueryBody, "application/json", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := queryFixture(t)
			headers := bearerHeaders()
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			response := requestAuth(handler, "POST", tc.path, tc.body, headers)
			require.Equal(t, 400, response.Code)
			var failure auth.ErrorResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
			require.Equal(t, auth.InvalidArgument, failure.Error.Code)
			require.Equal(t, tc.hint, failure.Error.Hint)
			require.NotContains(t, response.Body.String(), "select")
			require.Empty(t, f.queryCalls, "an invalid request must never reach the service")
		})
	}
}

// A body one byte above the documented request bound is refused by the reader
// before any decoding, so the SQL bound cannot be circumvented by framing.
func TestQueryRouteBoundsTheRequestBody(t *testing.T) {
	f, handler := queryFixture(t)
	padding := auth.MaxSQLBytes + queryBodyAllowance
	body := `{"connection":"` + queryConnection + `","sql":"` + strings.Repeat("x", padding) + `"}`
	require.Greater(t, len(body), padding)
	response := requestAuth(handler, "POST", auth.QueryPath, body, queryHeaders())
	require.Equal(t, 400, response.Code)
	require.Contains(t, response.Body.String(), auth.InvalidArgument)
	require.Empty(t, f.queryCalls)
}

// A cookie is not a CLI credential: the query route is bearer-only exactly
// like the connection and grant routes.
func TestQueryRouteIsBearerOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		status  int
	}{
		{"cookie only", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 401},
		{"no credential", http.Header{}, 401},
		{"bearer and cookie", http.Header{
			"Authorization": {"Bearer " + string(fixtureToken)},
			"Cookie":        {developmentCookie + "=" + string(fixtureToken)},
		}, 400},
		{"cross origin", bearerHeaders("Origin", "http://evil.invalid"), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := queryFixture(t)
			headers := tc.headers.Clone()
			headers.Set("Content-Type", "application/json")
			response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, headers)
			require.Equal(t, tc.status, response.Code)
			require.Empty(t, response.Header().Get("Set-Cookie"))
			require.Empty(t, f.queryCalls)
		})
	}
}

// The route answers only POST, and it is not an administration route.
func TestQueryRouteRejectsOtherMethods(t *testing.T) {
	_, handler := queryFixture(t)
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		response := requestAuth(handler, method, auth.QueryPath, "", bearerHeaders())
		require.Equal(t, 405, response.Code, method)
	}
}

func TestQueryRouteFailsClosedWithoutAnExecutor(t *testing.T) {
	f := &backendFixture{}
	adapter, err := newAuthHTTP("http://127.0.0.1", f, fixtureViews())
	require.NoError(t, err)
	adapter.admin, adapter.connections, adapter.grants, adapter.members = f, f, f, f
	ready := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
	composed := handler(time.Second, ready, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
	response := requestAuth(composed, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	require.Equal(t, 503, response.Code)
	require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
	require.Empty(t, f.queryCalls)
}

// The composition boundary requires the executor like every other dependency:
// a server that cannot execute never serves the route at all.
func TestHandlerWithAuthRequiresTheExecutor(t *testing.T) {
	fixture := &backendFixture{}
	ready := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
	composed, err := HandlerWithAuth(time.Second, ready, fixture, fixture, fixture, fixture, fixture, fixture, nil,
		"http://127.0.0.1", AuthViews{}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.Nil(t, composed)
	require.Error(t, err)
	status, failure := auth.FailureFor(err)
	require.Equal(t, 400, status)
	require.Equal(t, auth.InvalidArgument, failure.Error.Code)
}

// Execution runs under its own budget, not the shared five-second bound: the
// source's statement timeout alone may be twenty times that, and the service
// adds its own hung-connection backstop on top.
func TestQueryRouteRunsUnderTheExecutionBudget(t *testing.T) {
	require.Equal(t, 10*auth.MaxStatementTimeout+10*time.Second, auth.QueryRequestBudget)
	require.Greater(t, auth.QueryRequestBudget, auth.OperationTimeout)
	f, handler := queryFixture(t)
	start := time.Now()
	require.Equal(t, 200, requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders()).Code)
	require.True(t, f.queryDeadlineOK, "the service must be given a bounded context")
	granted := f.queryDeadline.Sub(start)
	require.LessOrEqual(t, granted, auth.QueryRequestBudget+time.Second)
	require.Greater(t, granted, auth.QueryRequestBudget-5*time.Second)

	// Every other route keeps the shared bound, so the longer budget is the
	// execution route's alone.
	g, other := grantFixture(t)
	checked := false
	g.grantBlock = func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		checked = ok && time.Until(deadline) <= auth.OperationTimeout
	}
	require.Equal(t, 200, requestAuth(other, "GET", auth.GrantsPath, "", bearerHeaders()).Code)
	require.True(t, checked)
}

// A statement that outlives the shared bound is answered with its results, not
// with unavailability.
func TestQueryRouteOutlivesTheSharedOperationBound(t *testing.T) {
	f, handler := queryFixture(t)
	slow := auth.OperationTimeout + time.Second
	f.queryBlock = func(context.Context) { time.Sleep(slow) }
	start := time.Now()
	response := requestAuth(handler, "POST", auth.QueryPath, validQueryBody, queryHeaders())
	elapsed := time.Since(start)
	require.Equal(t, 200, response.Code)
	require.GreaterOrEqual(t, elapsed, slow)
	require.Less(t, elapsed, 10*time.Second)
	require.Len(t, f.queryCalls, 1)
}

// The budget is still a deadline: a request whose own context expires is
// answered as unavailability with nothing published from a half-done call.
func TestQueryRouteFailsClosedWhenTheRequestDeadlinePasses(t *testing.T) {
	f, handler := queryFixture(t)
	f.queryBlock = func(ctx context.Context) { <-ctx.Done() }
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest("POST", auth.QueryPath, strings.NewReader(validQueryBody)).WithContext(ctx)
	request.RemoteAddr = "127.0.0.1:43210"
	request.Header = queryHeaders()
	response := httptest.NewRecorder()
	start := time.Now()
	handler.ServeHTTP(response, request)
	require.Equal(t, 503, response.Code)
	require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
	require.Less(t, time.Since(start), 7*time.Second)
	require.NotContains(t, response.Body.String(), "results")
}

// The bound the CLI reads under is stated once here so a change to either side
// is visible in this lane too.
func TestQueryBoundsAreTheDocumentedOnes(t *testing.T) {
	require.Equal(t, 256<<10, auth.MaxSQLBytes)
	require.Equal(t, 64<<10, auth.QueryEnvelopeAllowance)
	require.Equal(t, 4096, queryBodyAllowance)
	require.Contains(t, hintQueryText, strconv.Itoa(auth.MaxSQLBytes))
}
