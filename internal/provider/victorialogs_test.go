package provider

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

// The query a test submits. It is the caller's own text: it may reach the
// source unchanged and may never appear in an error the platform produces.
const logsExpression = `_msg:"SENTINEL_QUERY" | sort by (_time) desc`

// The tenant a test configures. Like the secret, it identifies the connection
// rather than the answer, so it may never travel into a failure either.
const (
	logsAccountID = "4294967295"
	logsProjectID = "1234567"
)

// Two rows as a source writes them: newline-delimited objects, no envelope.
const (
	logsRowOne = `{"_time":"2026-09-14T10:00:00.123456789Z","_msg":"boom","level":"error"}`
	logsRowTwo = `{"_time":"2026-09-14T10:00:01Z","_msg":"fine","level":"info"}`
)

func logsBody(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// logsSource answers every request with one canned body.
func logsSource(t *testing.T, status int, contentType, body string) (string, *metricsCapture) {
	t.Helper()
	return metricsSource(t, status, contentType, body)
}

func logsStreamSource(t *testing.T, body string) (string, *metricsCapture) {
	t.Helper()
	return logsSource(t, http.StatusOK, "application/stream+json", body)
}

func logsTarget(t *testing.T, address string) map[string]string {
	t.Helper()
	target, err := victoriaLogs{}.ParseTarget(map[string]string{keyURL: address, keyAuth: authNone})
	require.NoError(t, err)
	return target
}

// logsExecute runs one execution against a fake source under a deadline
// generous enough that only the provider's own bounds can end it.
func logsExecute(t *testing.T, address string, request ExecuteRequest) (ExecuteResult, error) {
	t.Helper()
	return victoriaLogs{}.Execute(probeContext(t, 20*time.Second), logsTarget(t, address), "", request)
}

func logsQueryRequest() ExecuteRequest {
	return ExecuteRequest{LogsQL: logsExpression, Timeout: 30 * time.Second}
}

func limit(value int64) *int64 { return &value }

func TestVictoriaLogsParseTarget(t *testing.T) {
	base := "https://logs.example.com:9428"
	for _, testCase := range []struct {
		name string
		raw  map[string]string
		want map[string]string
	}{
		{
			name: "no authentication and no tenant",
			raw:  map[string]string{keyURL: base, keyAuth: authNone},
			want: map[string]string{keyURL: base, keyAuth: authNone},
		},
		{
			name: "both tenant settings",
			raw: map[string]string{keyURL: base + "/", keyAuth: authBasic, keyUser: "reader",
				keyAccountID: "12", keyProjectID: "3"},
			want: map[string]string{keyURL: base, keyAuth: authBasic, keyUser: "reader",
				keyAccountID: "12", keyProjectID: "3"},
		},
		{
			name: "one tenant setting only",
			raw:  map[string]string{keyURL: base, keyAuth: authBearer, keyAccountID: "0"},
			want: map[string]string{keyURL: base, keyAuth: authBearer, keyAccountID: "0"},
		},
		{
			name: "the widest tenant a source takes",
			raw:  map[string]string{keyURL: base, keyAuth: authNone, keyProjectID: "4294967295"},
			want: map[string]string{keyURL: base, keyAuth: authNone, keyProjectID: "4294967295"},
		},
		{
			name: "a custom header that is not a tenant header",
			raw:  map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "X-Scope-OrgID"},
			want: map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "X-Scope-OrgID"},
		},
		{
			name: "a path prefix survives",
			raw:  map[string]string{keyURL: base + "/logs/", keyAuth: authNone},
			want: map[string]string{keyURL: base + "/logs", keyAuth: authNone},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target, err := victoriaLogs{}.ParseTarget(testCase.raw)
			require.NoError(t, err)
			require.Equal(t, testCase.want, target)
		})
	}
}

func TestVictoriaLogsParseTargetRejections(t *testing.T) {
	base := "https://logs.example.com:9428"
	for _, testCase := range []struct {
		name string
		raw  map[string]string
	}{
		{"no settings", map[string]string{}},
		{"unknown key", map[string]string{keyURL: base, keyAuth: authNone, sentinel: sentinel}},
		{"credentials in url", map[string]string{keyURL: "https://reader:" + sentinel + "@logs", keyAuth: authNone}},
		{"query string", map[string]string{keyURL: base + "/?token=" + sentinel, keyAuth: authNone}},
		{"unknown auth method", map[string]string{keyURL: base, keyAuth: sentinel}},
		{"basic without a user", map[string]string{keyURL: base, keyAuth: authBasic}},
		{"reserved authorization header", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "Authorization"}},
		// A stored header named like a tenant header would let one setting
		// carry both a credential and a tenant.
		{"header named like the account tenant", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: headerAccountID}},
		{"header named like the project tenant", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: headerProjectID}},
		{"header named like a tenant in lower case", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "accountid"}},
		{"header named like a tenant in upper case", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "PROJECTID"}},
		{"header named like a tenant in mixed case", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "AccountId"}},
		{"empty account", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: ""}},
		{"empty project", map[string]string{keyURL: base, keyAuth: authNone, keyProjectID: ""}},
		{"signed account", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: "+1"}},
		{"negative account", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: "-1"}},
		{"account beyond 32 bits", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: "4294967296"}},
		{"account with too many digits", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: "12345678901"}},
		{"account that is not a number", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: sentinel}},
		{"account with a space", map[string]string{keyURL: base, keyAuth: authNone, keyAccountID: "1 "}},
		{"account with a newline", map[string]string{keyURL: base, keyAuth: authNone, keyProjectID: "1\n2"}},
		{"fractional project", map[string]string{keyURL: base, keyAuth: authNone, keyProjectID: "1.0"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target, err := victoriaLogs{}.ParseTarget(testCase.raw)
			require.Nil(t, target)
			requireRejected(t, err)
		})
	}
}

func TestVictoriaLogsValidateSecret(t *testing.T) {
	none := map[string]string{keyAuth: authNone}
	require.NoError(t, victoriaLogs{}.ValidateSecret(none, ""))
	requireRejected(t, victoriaLogs{}.ValidateSecret(none, auth.Secret(sentinel)))
	for _, method := range []string{authBasic, authBearer, authHeader} {
		target := map[string]string{keyAuth: method}
		require.NoError(t, victoriaLogs{}.ValidateSecret(target, auth.Secret(sentinel)))
		requireRejected(t, victoriaLogs{}.ValidateSecret(target, ""))
		requireRejected(t, victoriaLogs{}.ValidateSecret(target, auth.Secret(sentinel+"\r\n")))
		requireRejected(t, victoriaLogs{}.ValidateSecret(target, auth.Secret(strings.Repeat("x", auth.MaxSecretBytes+1))))
	}
	// A bearer token or header value travels in a header, so a control byte in
	// one is refused here rather than at check time.
	for _, secret := range []string{"tok\ten", "tok\x01en", "tok\x7fen"} {
		requireRejected(t, victoriaLogs{}.ValidateSecret(map[string]string{keyAuth: authBearer}, auth.Secret(secret)))
	}
}

// The probe sends the tenant beside the stored authentication, so a check
// exercises the request shape an execution will send.
func TestVictoriaLogsProbeSendsAuthAndTenant(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		raw    func(url string) map[string]string
		secret auth.Secret
		check  func(t *testing.T, headers http.Header)
	}{
		{
			name: authNone,
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authNone}
			},
			check: func(t *testing.T, headers http.Header) {
				require.Empty(t, headers.Values("Authorization"))
				require.Empty(t, headers.Values(headerAccountID))
				require.Empty(t, headers.Values(headerProjectID))
			},
		},
		{
			name: authBasic + " with both tenants",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authBasic, keyUser: "reader",
					keyAccountID: logsAccountID, keyProjectID: logsProjectID}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				encoded := base64.StdEncoding.EncodeToString([]byte("reader:" + probeSecret))
				require.Equal(t, "Basic "+encoded, headers.Get("Authorization"))
				require.Equal(t, logsAccountID, headers.Get(headerAccountID))
				require.Equal(t, logsProjectID, headers.Get(headerProjectID))
			},
		},
		{
			name: authBearer + " with one tenant",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authBearer, keyAccountID: logsAccountID}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				require.Equal(t, "Bearer "+probeSecret, headers.Get("Authorization"))
				require.Equal(t, logsAccountID, headers.Get(headerAccountID))
				// An omitted setting sends no header at all.
				require.Empty(t, headers.Values(headerProjectID))
			},
		},
		{
			name: authHeader + " beside a tenant",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authHeader, keyHeader: "X-Scope-OrgID",
					keyProjectID: logsProjectID}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				require.Equal(t, probeSecret, headers.Get("X-Scope-OrgID"))
				require.Equal(t, logsProjectID, headers.Get(headerProjectID))
				require.Empty(t, headers.Values("Authorization"))
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, seen := healthServer(t, http.StatusOK)
			target, err := victoriaLogs{}.ParseTarget(testCase.raw(address))
			require.NoError(t, err)
			require.NoError(t, victoriaLogs{}.ValidateSecret(target, testCase.secret))
			outcome := victoriaLogs{}.Probe(probeContext(t, 5*time.Second), target, testCase.secret)
			require.Equal(t, auth.CheckReachable, outcome)
			testCase.check(t, seen.only(t))
			requireNoSentinel(t, outcome, target)
		})
	}
}

func TestVictoriaLogsProbeStatuses(t *testing.T) {
	for _, testCase := range []struct {
		status int
		want   auth.CheckOutcome
	}{
		{http.StatusOK, auth.CheckReachable},
		{http.StatusUnauthorized, auth.CheckAuthRejected},
		{http.StatusForbidden, auth.CheckAuthRejected},
		{http.StatusNotFound, auth.CheckUnreachable},
		{http.StatusServiceUnavailable, auth.CheckUnreachable},
	} {
		address, seen := healthServer(t, testCase.status)
		target, err := victoriaLogs{}.ParseTarget(map[string]string{keyURL: address, keyAuth: authBearer,
			keyAccountID: logsAccountID})
		require.NoError(t, err)
		outcome := victoriaLogs{}.Probe(probeContext(t, 5*time.Second), target, auth.Secret(probeSecret))
		require.Equal(t, testCase.want, outcome, testCase.status)
		require.Equal(t, 1, seen.count())
		requireNoSentinel(t, outcome)
	}
}

// Every endpoint receives exactly the strings that were submitted: no time is
// reformatted, no limit is invented, no query is rewritten, and a parameter
// that was not given is not sent at all.
func TestVictoriaLogsExecuteEndpoints(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		request ExecuteRequest
		path    string
		values  url.Values
		absent  []string
	}{
		{
			name:    "a log query",
			request: ExecuteRequest{LogsQL: logsExpression, Timeout: 30 * time.Second},
			path:    logsQueryPath,
			values:  url.Values{"query": {logsExpression}, "timeout": {"30s"}},
			absent:  []string{"start", "end", "limit", "field", "filter"},
		},
		{
			name: "a log query with bounds and a limit",
			request: ExecuteRequest{LogsQL: logsExpression, Start: "-1h", End: "now",
				Limit: limit(50), Timeout: time.Second},
			path: logsQueryPath,
			values: url.Values{"query": {logsExpression}, "start": {"-1h"}, "end": {"now"},
				"limit": {"50"}, "timeout": {"1s"}},
			absent: []string{"field", "filter"},
		},
		{
			// An explicit zero is the caller's own "no limit" and reaches the
			// source as a zero rather than as no parameter.
			name:    "a log query with an explicit zero limit",
			request: ExecuteRequest{LogsQL: logsExpression, Limit: limit(0), Timeout: 30 * time.Second},
			path:    logsQueryPath,
			values:  url.Values{"query": {logsExpression}, "limit": {"0"}, "timeout": {"30s"}},
		},
		{
			name:    "field names",
			request: ExecuteRequest{FieldNames: true, Match: logsExpression, Timeout: 30 * time.Second},
			path:    logsFieldNamesPath,
			values:  url.Values{"query": {logsExpression}, "timeout": {"30s"}},
			absent:  []string{"limit", "field", "filter"},
		},
		{
			name: "field values with a filter and a limit",
			request: ExecuteRequest{FieldValues: "level", Match: "*", Filter: "err",
				Limit: limit(7), Start: "-5m", Timeout: 30 * time.Second},
			path: logsFieldValuesPath,
			values: url.Values{"query": {"*"}, "field": {"level"}, "filter": {"err"},
				"limit": {"7"}, "start": {"-5m"}, "timeout": {"30s"}},
			absent: []string{"end"},
		},
		{
			name:    "streams",
			request: ExecuteRequest{Streams: true, Match: "*", Limit: limit(3), Timeout: 30 * time.Second},
			path:    logsStreamsPath,
			values:  url.Values{"query": {"*"}, "limit": {"3"}, "timeout": {"30s"}},
			absent:  []string{"field", "filter"},
		},
		{
			name:    "stream field names",
			request: ExecuteRequest{StreamFieldNames: true, Match: "*", Filter: "ho", Timeout: 30 * time.Second},
			path:    logsStreamFieldNamesPath,
			values:  url.Values{"query": {"*"}, "filter": {"ho"}, "timeout": {"30s"}},
			absent:  []string{"limit", "field"},
		},
		{
			name: "stream field values",
			request: ExecuteRequest{StreamFieldValues: "host", Match: "*", End: "now",
				Timeout: 1500 * time.Millisecond},
			path:   logsStreamFieldValuesPath,
			values: url.Values{"query": {"*"}, "field": {"host"}, "end": {"now"}, "timeout": {"1.5s"}},
			absent: []string{"start", "limit", "filter"},
		},
		{
			// A missing bound is the documented default rather than no bound.
			name:    "a missing timeout is the documented default",
			request: ExecuteRequest{FieldNames: true, Match: "*"},
			path:    logsFieldNamesPath,
			values:  url.Values{"query": {"*"}, "timeout": {"30s"}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			body := logsBody(logsRowOne)
			if testCase.path != logsQueryPath {
				body = `{"values":[]}`
			}
			address, seen := logsStreamSource(t, body)
			_, err := logsExecute(t, address, testCase.request)
			require.NoError(t, err)
			exchange := seen.only(t)
			require.Equal(t, http.MethodGet, exchange.method)
			require.Equal(t, testCase.path, exchange.path)
			require.Equal(t, testCase.values, exchange.values(t))
			require.Equal(t, "application/json", exchange.headers.Get("Accept"))
			require.Empty(t, exchange.rawBody, "a read-only endpoint takes a query string, not a body")
			// A parameter that was not given is absent from the wire, not
			// present and empty: the source applies its own default.
			for _, key := range testCase.absent {
				require.NotContains(t, exchange.rawQuery, url.QueryEscape(key)+"=", key)
			}
		})
	}
}

// The four authentication methods reach the source exactly as the probe sends
// them, with the tenant beside them and never instead of them.
func TestVictoriaLogsExecuteAuthAndTenantHeaders(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		raw    func(url string) map[string]string
		secret auth.Secret
		check  func(t *testing.T, headers http.Header)
	}{
		{
			name: authNone + " without a tenant",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authNone}
			},
			check: func(t *testing.T, headers http.Header) {
				require.Empty(t, headers.Values("Authorization"))
				require.Empty(t, headers.Values(headerAccountID))
				require.Empty(t, headers.Values(headerProjectID))
			},
		},
		{
			name: authNone + " with both tenants",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authNone,
					keyAccountID: logsAccountID, keyProjectID: logsProjectID}
			},
			check: func(t *testing.T, headers http.Header) {
				require.Empty(t, headers.Values("Authorization"))
				require.Equal(t, []string{logsAccountID}, headers.Values(headerAccountID))
				require.Equal(t, []string{logsProjectID}, headers.Values(headerProjectID))
			},
		},
		{
			name: authBasic + " with both tenants",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authBasic, keyUser: "reader",
					keyAccountID: logsAccountID, keyProjectID: logsProjectID}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				encoded := base64.StdEncoding.EncodeToString([]byte("reader:" + probeSecret))
				require.Equal(t, "Basic "+encoded, headers.Get("Authorization"))
				require.Equal(t, logsAccountID, headers.Get(headerAccountID))
				require.Equal(t, logsProjectID, headers.Get(headerProjectID))
			},
		},
		{
			name: authBearer + " with one tenant",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authBearer, keyProjectID: logsProjectID}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				require.Equal(t, "Bearer "+probeSecret, headers.Get("Authorization"))
				require.Equal(t, logsProjectID, headers.Get(headerProjectID))
				require.Empty(t, headers.Values(headerAccountID))
			},
		},
		{
			name: authHeader + " with both tenants",
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authHeader, keyHeader: "X-Scope-OrgID",
					keyAccountID: logsAccountID, keyProjectID: logsProjectID}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				require.Equal(t, probeSecret, headers.Get("X-Scope-OrgID"))
				require.Equal(t, logsAccountID, headers.Get(headerAccountID))
				require.Equal(t, logsProjectID, headers.Get(headerProjectID))
				require.Empty(t, headers.Values("Authorization"))
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, seen := logsStreamSource(t, logsBody(logsRowOne))
			target, err := victoriaLogs{}.ParseTarget(testCase.raw(address))
			require.NoError(t, err)
			require.NoError(t, victoriaLogs{}.ValidateSecret(target, testCase.secret))
			result, err := victoriaLogs{}.Execute(probeContext(t, 10*time.Second), target,
				testCase.secret, logsQueryRequest())
			require.NoError(t, err)
			require.Equal(t, resultTypeLogs, result.ResultType)
			testCase.check(t, seen.only(t).headers)
		})
	}
}

// One execution is one request, and the source sees no connection kept open on
// the caller's behalf.
func TestVictoriaLogsExecuteSendsOneRequest(t *testing.T) {
	address, seen := logsStreamSource(t, logsBody(logsRowOne, logsRowTwo))
	_, err := logsExecute(t, address, logsQueryRequest())
	require.NoError(t, err)
	require.Equal(t, 1, seen.count())
	require.Equal(t, "close", strings.ToLower(seen.only(t).headers.Get("Connection")))
}

// Rows reach the caller as the source wrote them: every field, every value
// type and the order of both survive, and the platform adds nothing.
func TestVictoriaLogsExecuteRowsPassThrough(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		body   string
		result string
		rows   int64
		bytes  int64
	}{
		{
			name:   "two ordinary rows in arrival order",
			body:   logsBody(logsRowOne, logsRowTwo),
			result: `[` + logsRowOne + `,` + logsRowTwo + `]`,
			rows:   2,
		},
		{
			// Rows are query results, not log lines: an aggregate has neither
			// _time nor _msg and is accepted exactly as it arrived.
			name:   "an aggregate row without the log fields",
			body:   logsBody(`{"level":"error","n":"12"}`),
			result: `[{"level":"error","n":"12"}]`,
			rows:   1,
		},
		{
			name: "every JSON value type unchanged and in order",
			body: logsBody(`{"s":"text","n":123456789012345678901234567890.5,"neg":-0.0,` +
				`"o":{"b":[1,{"c":null}]},"a":[true,false,null],"t":true,"f":false,"z":null}`),
			result: `[{"s":"text","n":123456789012345678901234567890.5,"neg":-0.0,` +
				`"o":{"b":[1,{"c":null}]},"a":[true,false,null],"t":true,"f":false,"z":null}]`,
			rows: 1,
			// Names cost their length and a value that is not a string costs
			// its raw text: 10 bytes of names, 4 for the string, 32, 4, 20,
			// 17, 4, 5 and 4 for the rest.
			bytes: 100,
		},
		{
			name: "a message holding JSON text and control characters",
			body: logsBody(`{"_msg":"{\"nested\":\"json\"}\n\tline two\u0000","_stream":"{host=\"a\"}"}`),
			result: `[{"_msg":"{\"nested\":\"json\"}\n\tline two\u0000",` +
				`"_stream":"{host=\"a\"}"}]`,
			rows: 1,
		},
		{
			// Duplicate names are the source's own and are not collapsed, which
			// a map would have done.
			name:   "a repeated field name survives",
			body:   logsBody(`{"a":"1","a":"2"}`),
			result: `[{"a":"1","a":"2"}]`,
			rows:   1,
		},
		{
			name:   "an empty object is a row",
			body:   logsBody(`{}`),
			result: `[{}]`,
			rows:   1,
		},
		{
			// A source that answered nothing answers an empty list, never null.
			name:   "an empty body",
			body:   "",
			result: `[]`,
		},
		{
			name:   "a body of blank lines only",
			body:   "\n\n\n",
			result: `[]`,
		},
		{
			// The last line of a stream may arrive without its terminator.
			name:   "a final line without a newline",
			body:   logsRowOne + "\n" + logsRowTwo,
			result: `[` + logsRowOne + `,` + logsRowTwo + `]`,
			rows:   2,
		},
		{
			name:   "one line without any newline at all",
			body:   logsRowOne,
			result: `[` + logsRowOne + `]`,
			rows:   1,
		},
		{
			name:   "blank lines between rows are not rows",
			body:   "\n" + logsRowOne + "\n\n" + logsRowTwo + "\n\n",
			result: `[` + logsRowOne + `,` + logsRowTwo + `]`,
			rows:   2,
		},
		{
			name:   "insignificant whitespace inside a row is compacted away",
			body:   logsBody(`{ "a" : "b" , "c" : [ 1 , 2 ] }`),
			result: `[{"a":"b","c":[1,2]}]`,
			rows:   1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsStreamSource(t, testCase.body)
			result, err := logsExecute(t, address, logsQueryRequest())
			require.NoError(t, err)
			require.Equal(t, resultTypeLogs, result.ResultType)
			require.Equal(t, testCase.result, string(result.Result))
			require.Equal(t, testCase.rows, result.Rows)
			if testCase.bytes != 0 {
				require.Equal(t, testCase.bytes, result.Bytes)
			}
			require.False(t, result.Truncated)
			require.Equal(t, int64(1), result.Statements)
			// A log answer carries none of the metrics envelope's members.
			require.Nil(t, result.Warnings)
			require.Nil(t, result.Infos)
			require.False(t, result.IsPartial)
			require.Nil(t, result.Results)
		})
	}
}

// A stream that ends exactly on the cap is a complete answer: the end was
// observed rather than assumed, so nothing is marked truncated.
func TestVictoriaLogsExecuteExactCapIsNotTruncated(t *testing.T) {
	for _, name := range []string{"with a trailing newline", "without a trailing newline"} {
		t.Run(name, func(t *testing.T) {
			body := logsRowOne + "\n" + logsRowTwo + "\n" + logsRowOne
			if name == "with a trailing newline" {
				body += "\n"
			}
			address, _ := logsStreamSource(t, body)
			result, err := logsExecute(t, address, ExecuteRequest{LogsQL: logsExpression, MaxRows: 3})
			require.NoError(t, err)
			require.False(t, result.Truncated)
			require.Equal(t, int64(3), result.Rows)
		})
	}
}

// A source limit within the cap is read to the stream's end, so the answer is
// complete and says so.
func TestVictoriaLogsExecuteSourceLimitWithinTheCap(t *testing.T) {
	address, seen := logsStreamSource(t, logsBody(logsRowOne, logsRowTwo))
	result, err := logsExecute(t, address, ExecuteRequest{LogsQL: logsExpression, Limit: limit(10), MaxRows: 1000})
	require.NoError(t, err)
	require.False(t, result.Truncated)
	require.Equal(t, int64(2), result.Rows)
	require.Equal(t, []string{"10"}, seen.only(t).values(t)["limit"])
}

// logsFlood answers with the same row until the client stops reading. It
// reports that the write side ended, which is how a test observes that the
// platform closed the connection rather than draining the stream.
func logsFlood(t *testing.T, row string) (string, *atomic.Bool) {
	t.Helper()
	cut := &atomic.Bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		for range 500000 {
			if _, err := io.WriteString(w, row+"\n"); err != nil {
				cut.Store(true)
				return
			}
			flusher.Flush()
			if r.Context().Err() != nil {
				cut.Store(true)
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, cut
}

// The log stream is unbounded unless the caller's limit bounds it, so the
// platform stops at the cap, closes the connection and says the source's
// completion was never observed.
func TestVictoriaLogsExecuteStopsAtTheRowCap(t *testing.T) {
	address, cut := logsFlood(t, logsRowOne)
	result, err := logsExecute(t, address, ExecuteRequest{LogsQL: logsExpression, MaxRows: 25})
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.Equal(t, int64(25), result.Rows)
	require.Equal(t, 25, strings.Count(string(result.Result), logsRowOne))
	// The source saw the connection close: keep-alive is off, so closing the
	// body stops the work rather than leaving it running.
	require.Eventually(t, cut.Load, 10*time.Second, 10*time.Millisecond,
		"the source must observe the connection close")
}

// The byte cap stops the stream the same way, and the first row is kept even
// when it alone is larger than the cap: a caller must see the shape of what it
// asked for.
func TestVictoriaLogsExecuteStopsAtTheByteCap(t *testing.T) {
	row := `{"_msg":"` + strings.Repeat("x", 512) + `"}`
	address, cut := logsFlood(t, row)
	result, err := logsExecute(t, address, ExecuteRequest{LogsQL: logsExpression, MaxRows: 1000, MaxBytes: 16})
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.Equal(t, int64(1), result.Rows)
	require.Equal(t, `[`+row+`]`, string(result.Result))
	// The first row counts its bytes even though it was kept regardless.
	require.Equal(t, int64(len("_msg")+512), result.Bytes)
	require.Eventually(t, cut.Load, 10*time.Second, 10*time.Millisecond)
}

// A row the platform cannot hold is not data it may present: the ceiling
// bounds one row of the stream rather than the body, which has no length.
func TestVictoriaLogsExecuteRowBeyondTheCeiling(t *testing.T) {
	request := ExecuteRequest{LogsQL: logsExpression, MaxRows: 10, MaxBytes: auth.MinMaxBytes}
	ceiling := auth.MetricsBodyCeiling(request.MaxBytes)
	oversized := `{"_msg":"` + strings.Repeat("x", ceiling) + `"}`
	// One byte over the ceiling is refused whether or not a terminator follows.
	justOver := `{"_msg":"` + strings.Repeat("x", ceiling-len(`{"_msg":""}`)+1) + `"}`
	require.Len(t, justOver, ceiling+1)
	for _, testCase := range []struct{ name, body string }{
		{"the first row", oversized},
		{"a later row", logsBody(logsRowOne) + oversized},
		{"one byte over with a newline", justOver + "\n"},
		{"one byte over without a newline", justOver},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsStreamSource(t, testCase.body)
			_, err := logsExecute(t, address, request)
			var rejected *SourceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, ResponseTooLarge, rejected.Failure.ErrorType)
			require.NotEmpty(t, rejected.Failure.Message)
			requireNoSentinel(t, err.Error(), rejected.Failure.Message)
		})
	}
	// A row just inside the ceiling is data like any other.
	fitting := `{"_msg":"` + strings.Repeat("x", ceiling-len(`{"_msg":""}`)) + `"}`
	address, _ := logsStreamSource(t, fitting+"\n")
	result, err := logsExecute(t, address, request)
	require.NoError(t, err)
	require.Equal(t, int64(1), result.Rows)
}

// A source writes an error into the stream it was writing rows into. Half a
// stream is not data: the request fails with the source's own text and no rows.
func TestVictoriaLogsExecuteMalformedLine(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		body     string
		contains string
	}{
		{"a plain-text error after two rows",
			logsBody(logsRowOne, logsRowTwo, "cannot execute query: unexpected token"),
			"cannot execute query: unexpected token"},
		{"an error on the first line", logsBody("internal error: shard 3 is down"),
			"internal error: shard 3 is down"},
		{"a line that is an array", logsBody(logsRowOne, `["_msg","boom"]`), `["_msg","boom"]`},
		{"a line that is a bare string", logsBody(`"just text"`), `"just text"`},
		{"a line that is a number", logsBody("42"), "42"},
		{"a line that is null", logsBody("null"), "null"},
		{"a truncated object", logsBody(`{"_msg":"bo`), `{"_msg":"bo`},
		{"two objects on one line", logsBody(logsRowOne + logsRowTwo), logsRowTwo},
		{"an object with a trailing comma", logsBody(`{"a":"b",}`), `{"a":"b",}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsStreamSource(t, testCase.body)
			result, err := logsExecute(t, address, logsQueryRequest())
			var rejected *SourceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, MalformedResponse, rejected.Failure.ErrorType)
			require.Contains(t, rejected.Failure.Message, testCase.contains)
			// No rows are returned: a stream that failed is a failure, not a
			// short answer.
			require.Nil(t, result.Result)
			require.Zero(t, result.Rows)
			require.Empty(t, rejected.Failure.SQLState)
			require.Nil(t, rejected.Failure.Statement)
		})
	}
}

// The offending text is bounded like every other text the platform did not
// write.
func TestVictoriaLogsExecuteMalformedLineIsBounded(t *testing.T) {
	address, _ := logsStreamSource(t, logsBody(strings.Repeat("e", 8<<10)))
	_, err := logsExecute(t, address, logsQueryRequest())
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, MalformedResponse, rejected.Failure.ErrorType)
	require.Len(t, rejected.Failure.Message, maxErrorText)
}

const logsDiscoveryBody = `{"values":[{"value":"error","hits":1234567890123456789},` +
	`{"value":"","hits":0},{"value":"in\"fo","hits":3.5}]}`

// A discovery answer is one envelope: the value and hits pairs come back with
// their numbers exact and in the source's order.
func TestVictoriaLogsExecuteDiscoveryPassThrough(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		request    ExecuteRequest
		resultType string
	}{
		{"field names", ExecuteRequest{FieldNames: true, Match: "*"}, resultTypeFieldNames},
		{"field values", ExecuteRequest{FieldValues: "level", Match: "*"}, resultTypeFieldValues},
		{"streams", ExecuteRequest{Streams: true, Match: "*"}, resultTypeStreams},
		{"stream field names", ExecuteRequest{StreamFieldNames: true, Match: "*"}, resultTypeStreamFieldNames},
		{"stream field values", ExecuteRequest{StreamFieldValues: "host", Match: "*"}, resultTypeStreamFieldValues},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsSource(t, http.StatusOK, "application/json", logsDiscoveryBody)
			result, err := logsExecute(t, address, testCase.request)
			require.NoError(t, err)
			require.Equal(t, testCase.resultType, result.ResultType)
			require.Equal(t, `[{"value":"error","hits":1234567890123456789},`+
				`{"value":"","hits":0},{"value":"in\"fo","hits":3.5}]`, string(result.Result))
			require.Equal(t, int64(3), result.Rows)
			// Each item costs its decoded value text plus the digits of its
			// count: 5+19, 0+1 and 5+3.
			require.Equal(t, int64(33), result.Bytes)
			require.False(t, result.Truncated)
			require.Equal(t, int64(1), result.Statements)
		})
	}
}

func TestVictoriaLogsExecuteDiscoveryShapes(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		body   string
		result string
	}{
		{"an empty list", `{"values":[]}`, `[]`},
		{"members the platform does not know are skipped",
			`{"other":{"a":[1,2]},"values":[{"value":"a","hits":1,"extra":{"b":[1]}}],"after":3}`,
			`[{"value":"a","hits":1}]`},
		{"the members of an item may arrive in any order",
			`{"values":[{"hits":9,"value":"a"}]}`, `[{"value":"a","hits":9}]`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsSource(t, http.StatusOK, "application/json", testCase.body)
			result, err := logsExecute(t, address, ExecuteRequest{FieldNames: true, Match: "*"})
			require.NoError(t, err)
			require.Equal(t, testCase.result, string(result.Result))
		})
	}
}

// Items beyond a cap are dropped whole and the envelope is still read to its
// end, which is what makes the answer one the platform validated.
func TestVictoriaLogsExecuteDiscoveryTruncation(t *testing.T) {
	body := `{"values":[{"value":"a","hits":1},{"value":"b","hits":2},{"value":"c","hits":3}],"stats":{"a":1}}`
	address, _ := logsSource(t, http.StatusOK, "application/json", body)
	result, err := logsExecute(t, address, ExecuteRequest{FieldNames: true, Match: "*", MaxRows: 2})
	require.NoError(t, err)
	require.Equal(t, `[{"value":"a","hits":1},{"value":"b","hits":2}]`, string(result.Result))
	require.True(t, result.Truncated)
	require.Equal(t, int64(2), result.Rows)

	// The byte cap drops later items the same way, the first one always kept.
	wide := `{"values":[{"value":"` + strings.Repeat("x", 64) + `","hits":1},{"value":"y","hits":2}]}`
	address, _ = logsSource(t, http.StatusOK, "application/json", wide)
	result, err = logsExecute(t, address, ExecuteRequest{FieldNames: true, Match: "*", MaxRows: 100, MaxBytes: 8})
	require.NoError(t, err)
	require.Equal(t, int64(1), result.Rows)
	require.True(t, result.Truncated)

	// Reading continues past a dropped item: a malformed tail is still found.
	tail := `{"values":[{"value":"a","hits":1},{"value":"b","hits":2}],"stats":}`
	address, _ = logsSource(t, http.StatusOK, "application/json", tail)
	_, err = logsExecute(t, address, ExecuteRequest{FieldNames: true, Match: "*", MaxRows: 1})
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, MalformedResponse, rejected.Failure.ErrorType)
}

// An answer that is not the envelope the endpoint documents is a failure, never
// data the platform guessed at.
func TestVictoriaLogsExecuteDiscoveryMalformed(t *testing.T) {
	for _, testCase := range []struct{ name, body string }{
		{"an empty body", ""},
		{"a missing values member", `{"other":[]}`},
		{"a null values member", `{"values":null}`},
		{"a values member that is not an array", `{"values":{"a":1}}`},
		{"an item that is not an object", `{"values":["error"]}`},
		{"an item without a value", `{"values":[{"hits":1}]}`},
		{"an item without hits", `{"values":[{"value":"a"}]}`},
		{"a value that is not a string", `{"values":[{"value":1,"hits":1}]}`},
		{"hits that are not a number", `{"values":[{"value":"a","hits":"1"}]}`},
		{"a body that is an array", `[{"value":"a","hits":1}]`},
		{"a body that is plain text", "the query is invalid"},
		{"a second document after the envelope", `{"values":[]}{"values":[]}`},
		{"a truncated envelope", `{"values":[{"value":"a"`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsSource(t, http.StatusOK, "application/json", testCase.body)
			_, err := logsExecute(t, address, ExecuteRequest{FieldNames: true, Match: "*"})
			var rejected *SourceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, MalformedResponse, rejected.Failure.ErrorType)
			require.NotEmpty(t, rejected.Failure.Message)
		})
	}
}

// A discovery envelope beyond the ceiling fails rather than arriving cut short.
func TestVictoriaLogsExecuteDiscoveryBeyondTheCeiling(t *testing.T) {
	request := ExecuteRequest{FieldNames: true, Match: "*", MaxRows: 10, MaxBytes: auth.MinMaxBytes}
	padding := strings.Repeat("x", auth.MetricsBodyCeiling(request.MaxBytes))
	address, _ := logsSource(t, http.StatusOK, "application/json",
		`{"values":[{"value":"`+padding+`","hits":1}]}`)
	_, err := logsExecute(t, address, request)
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, ResponseTooLarge, rejected.Failure.ErrorType)
}

// Every non-200 answer is the source's own, classified by its status alone: the
// text is never searched for a word, so a 503 is the source's timeout and a 400
// its rejection without the platform reading either.
func TestVictoriaLogsExecuteStatusFailures(t *testing.T) {
	for _, testCase := range []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusBadRequest, "cannot parse query: unexpected token \"|\"", "http_400"},
		{http.StatusServiceUnavailable, "cannot execute query in 5.000 seconds; the timeout was reached", "http_503"},
		{http.StatusInternalServerError, "internal error", "http_500"},
		{http.StatusNotFound, "", "http_404"},
		{http.StatusBadGateway, "<html>upstream unavailable</html>", "http_502"},
	} {
		address, _ := logsSource(t, testCase.status, "text/plain", testCase.body)
		_, err := logsExecute(t, address, logsQueryRequest())
		var rejected *SourceError
		require.ErrorAs(t, err, &rejected)
		require.Equal(t, testCase.want, rejected.Failure.ErrorType)
		require.Equal(t, strings.TrimSpace(testCase.body), rejected.Failure.Message)
		require.Empty(t, rejected.Failure.SQLState)
		require.Nil(t, rejected.Failure.Statement)
		requireNoSentinel(t, err.Error())
	}
	// The source's text is bounded like every other text the platform did not
	// write.
	address, _ := logsSource(t, http.StatusBadRequest, "text/plain", strings.Repeat("e", 32<<10))
	_, err := logsExecute(t, address, logsQueryRequest())
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Len(t, rejected.Failure.Message, maxErrorText)
}

// The transport failures keep the categories the probe reports, so a caller can
// tell a refused credential from a source that is not there.
func TestVictoriaLogsExecuteTransportFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		address, _ := logsSource(t, status, "text/plain", "unauthorized")
		_, err := logsExecute(t, address, logsQueryRequest())
		require.ErrorIs(t, err, ErrAuthRejected, status)
		requireNoSentinel(t, err.Error())
	}

	// A redirect is refused rather than followed: following one would send the
	// secret and the tenant to a host no administrator configured.
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+logsQueryPath, http.StatusFound)
	}))
	t.Cleanup(source.Close)
	_, err := logsExecute(t, source.URL, logsQueryRequest())
	require.ErrorIs(t, err, ErrUnreachable)
	require.Zero(t, destinationCalls.Load())

	// A source that is not listening is unreachable, with no transport text in
	// the failure.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := closed.URL
	closed.Close()
	_, err = logsExecute(t, address, logsQueryRequest())
	require.ErrorIs(t, err, ErrUnreachable)
	requireNoSentinel(t, err.Error())
}

// A source that stops answering is cut by the client's own bound: the
// connection's timeout plus the documented grace, and not a moment longer.
func TestVictoriaLogsExecuteClientDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(stall(auth.MetricsGrace + 2*time.Second)))
	t.Cleanup(server.Close)
	started := time.Now()
	_, err := victoriaLogs{}.Execute(t.Context(), logsTarget(t, server.URL), "",
		ExecuteRequest{LogsQL: logsExpression, Timeout: 10 * time.Millisecond})
	elapsed := time.Since(started)
	require.ErrorIs(t, err, ErrTimeout)
	require.GreaterOrEqual(t, elapsed, auth.MetricsGrace)
	require.Less(t, elapsed, auth.MetricsGrace+3*time.Second)
}

// A source that writes rows and then stops is cut the same way: the deadline
// reached inside the stream is the timeout, never a malformed or partial answer.
func TestVictoriaLogsExecuteClientDeadlineWhileReadingRows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/stream+json")
		_, _ = io.WriteString(w, logsBody(logsRowOne, logsRowTwo))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		stall(auth.MetricsGrace+2*time.Second)(w, r)
	}))
	t.Cleanup(server.Close)
	started := time.Now()
	result, err := victoriaLogs{}.Execute(t.Context(), logsTarget(t, server.URL), "",
		ExecuteRequest{LogsQL: logsExpression, Timeout: 10 * time.Millisecond, MaxRows: 10})
	require.ErrorIs(t, err, ErrTimeout)
	require.Nil(t, result.Result)
	require.Less(t, time.Since(started), auth.MetricsGrace+3*time.Second)
}

// The caller's deadline is the service's backstop and produces the same code.
func TestVictoriaLogsExecuteRequestDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(stall(2 * time.Second)))
	t.Cleanup(server.Close)
	started := time.Now()
	_, err := victoriaLogs{}.Execute(probeContext(t, 300*time.Millisecond), logsTarget(t, server.URL), "",
		ExecuteRequest{LogsQL: logsExpression, Timeout: 30 * time.Second})
	require.ErrorIs(t, err, ErrTimeout)
	require.Less(t, time.Since(started), 3*time.Second)
}

// An input this provider does not take is refused before anything is dialled.
// The service refuses it first, with a hint naming the right input; this is the
// backstop that keeps a missed rule from reaching a source.
func TestVictoriaLogsExecuteRefusesUnsupportedInput(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		request ExecuteRequest
	}{
		{"no input at all", ExecuteRequest{}},
		{"sql", ExecuteRequest{SQL: "select 1"}},
		{"promql", ExecuteRequest{PromQL: "up"}},
		{"sql beside a log query", ExecuteRequest{SQL: "select 1", LogsQL: logsExpression}},
		{"promql beside a log query", ExecuteRequest{PromQL: "up", LogsQL: logsExpression}},
		{"a metrics discovery input beside a log one", ExecuteRequest{Labels: true, FieldNames: true, Match: "*"}},
		{"a label name beside a log query", ExecuteRequest{LabelValues: "job", LogsQL: logsExpression}},
		{"a series selector beside a log query", ExecuteRequest{Series: "up", LogsQL: logsExpression}},
		{"an instant time", ExecuteRequest{LogsQL: logsExpression, At: "now"}},
		{"a step", ExecuteRequest{LogsQL: logsExpression, Step: "1m"}},
		{"only a time", ExecuteRequest{Start: "-1h"}},
		{"two log discovery inputs", ExecuteRequest{FieldNames: true, Streams: true, Match: "*"}},
		{"a log query and a discovery input", ExecuteRequest{LogsQL: logsExpression, FieldNames: true, Match: "*"}},
		{"a match on a log query", ExecuteRequest{LogsQL: logsExpression, Match: "*"}},
		{"field names without a match", ExecuteRequest{FieldNames: true}},
		{"field values without a match", ExecuteRequest{FieldValues: "level"}},
		{"streams without a match", ExecuteRequest{Streams: true}},
		{"stream field names without a match", ExecuteRequest{StreamFieldNames: true}},
		{"stream field values without a match", ExecuteRequest{StreamFieldValues: "host"}},
		{"a limit on field names", ExecuteRequest{FieldNames: true, Match: "*", Limit: limit(10)}},
		{"a limit on stream field names", ExecuteRequest{StreamFieldNames: true, Match: "*", Limit: limit(10)}},
		{"a zero limit on field names is still a limit",
			ExecuteRequest{FieldNames: true, Match: "*", Limit: limit(0)}},
		{"a filter on a log query", ExecuteRequest{LogsQL: logsExpression, Filter: "err"}},
		{"a filter on streams", ExecuteRequest{Streams: true, Match: "*", Filter: "err"}},
		{"a negative limit", ExecuteRequest{LogsQL: logsExpression, Limit: limit(-1)}},
		{"a negative limit on discovery", ExecuteRequest{FieldValues: "level", Match: "*", Limit: limit(-5)}},
		{"a filter without an input", ExecuteRequest{Filter: "err"}},
		{"a limit without an input", ExecuteRequest{Limit: limit(1)}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, seen := logsStreamSource(t, logsBody(logsRowOne))
			_, err := logsExecute(t, address, testCase.request)
			require.ErrorIs(t, err, ErrUnsupportedInput)
			require.Zero(t, seen.count(), "no source may be contacted for an input the provider does not take")
		})
	}
}

// Neither the secret, nor the tenant, nor the caller's query may appear in a
// failure the platform produces: the source's block is the only text that
// travels, and it is the source's own.
func TestVictoriaLogsExecuteFailuresCarryNoInput(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status int
		body   string
	}{
		{"source rejection", http.StatusBadRequest, "cannot parse query"},
		{"gateway text", http.StatusBadGateway, "upstream unavailable"},
		{"refused credentials", http.StatusUnauthorized, "no"},
		{"a malformed line", http.StatusOK, "not json\n"},
		{"an unterminated malformed line", http.StatusOK, "{"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := logsSource(t, testCase.status, "text/plain", testCase.body)
			target, err := victoriaLogs{}.ParseTarget(map[string]string{keyURL: address, keyAuth: authBearer,
				keyAccountID: logsAccountID, keyProjectID: logsProjectID})
			require.NoError(t, err)
			_, err = victoriaLogs{}.Execute(probeContext(t, 10*time.Second), target, auth.Secret(sentinel),
				ExecuteRequest{LogsQL: logsExpression, Timeout: 30 * time.Second})
			require.Error(t, err)
			requireNoSentinel(t, err.Error())
			var rejected *SourceError
			if errors.As(err, &rejected) {
				requireNoSentinel(t, rejected.Failure.Message, rejected.Failure.ErrorType)
				for _, secret := range []string{logsAccountID, logsProjectID, address} {
					require.NotContains(t, rejected.Failure.Message, secret)
					require.NotContains(t, err.Error(), secret)
				}
			}
		})
	}
}

// A log input on another provider's connection is refused before anything is
// dialled, which is the mirror of this provider refusing SQL and PromQL.
func TestOtherProvidersRefuseLogInputs(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		request ExecuteRequest
	}{
		{"a log query", ExecuteRequest{LogsQL: logsExpression}},
		{"field names", ExecuteRequest{FieldNames: true, Match: "*"}},
		{"field values", ExecuteRequest{FieldValues: "level", Match: "*"}},
		{"streams", ExecuteRequest{Streams: true, Match: "*"}},
		{"stream field names", ExecuteRequest{StreamFieldNames: true, Match: "*"}},
		{"stream field values", ExecuteRequest{StreamFieldValues: "host", Match: "*"}},
		{"a limit", ExecuteRequest{Limit: limit(10)}},
		{"a filter", ExecuteRequest{Filter: "err"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// Beside the input each provider does take, so the refusal is about
			// the log input rather than about a missing one.
			sql := testCase.request
			sql.SQL = "select 1"
			require.False(t, postgresInput(sql))
			metrics := testCase.request
			metrics.PromQL = "up"
			require.False(t, metricsInput(metrics))
			// The metrics provider refuses it without contacting a source.
			address, seen := metricsJSON(t, metricsVector)
			_, err := metricsExecute(t, address, metrics)
			require.ErrorIs(t, err, ErrUnsupportedInput)
			require.Zero(t, seen.count())
		})
	}
	// The inputs each provider does take are unaffected.
	require.True(t, postgresInput(ExecuteRequest{SQL: "select 1"}))
	require.True(t, metricsInput(ExecuteRequest{PromQL: "up"}))
}
