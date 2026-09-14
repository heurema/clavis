package auth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

// sentinelSQL stands in for a caller's statement. It may never appear in an
// error's own text: only the source block carries what the source said.
const sentinelSQL = "select 'SENTINEL_STATEMENT_TEXT'"

func TestQueryResponseShape(t *testing.T) {
	empty := ""
	value := "42"
	response := auth.QueryResponse{
		Provider: auth.ProviderPostgreSQL,
		Results: []auth.QueryResult{{
			Command: "SELECT",
			Columns: []auth.QueryColumn{{Name: "n", Type: "numeric"}, {Name: "n", Type: "text"}},
			// A null pointer is SQL NULL and an empty string is an empty
			// string: the two must not collapse into one another.
			Rows:     [][]*string{{&value, nil}, {nil, &empty}},
			RowCount: 2,
		}, {
			// A statement without rows carries empty lists, never null, so a
			// caller can iterate both fields without a shape check.
			Command:  "UPDATE",
			Columns:  []auth.QueryColumn{},
			Rows:     [][]*string{},
			RowCount: 3,
		}},
		Truncated:  true,
		DurationMS: 17,
	}
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.JSONEq(t, `{"provider":"postgresql","results":[
		{"command":"SELECT","columns":[{"name":"n","type":"numeric"},{"name":"n","type":"text"}],
		 "rows":[["42",null],[null,""]],"rowCount":2,"truncated":false},
		{"command":"UPDATE","columns":[],"rows":[],"rowCount":3,"truncated":false}
	],"truncated":true,"durationMs":17}`, string(encoded))
	require.Contains(t, string(encoded), `"rows":[]`)
	require.Contains(t, string(encoded), `"columns":[]`)

	// One statement is still a list, so a caller never branches on the shape
	// of what it sent, and the metrics fields stay out of a SQL response.
	single, err := json.Marshal(auth.QueryResponse{Provider: auth.ProviderPostgreSQL, Results: []auth.QueryResult{{
		Command: "CREATE", Columns: []auth.QueryColumn{}, Rows: [][]*string{},
	}}})
	require.NoError(t, err)
	require.Contains(t, string(single), `"results":[{`)
	for _, key := range []string{"resultType", "result", "warnings", "infos", "isPartial"} {
		require.NotContains(t, string(single), `"`+key+`":`)
	}
	// The list belongs to the provider that answers it: a response carrying no
	// statement at all carries no results key either.
	none, err := json.Marshal(auth.QueryResponse{Provider: auth.ProviderPostgreSQL, Results: []auth.QueryResult{}})
	require.NoError(t, err)
	require.JSONEq(t, `{"provider":"postgresql","truncated":false,"durationMs":0}`, string(none))
}

// The metrics shape is the source's own answer: result travels verbatim, so
// what the caller reads is what the source rendered.
func TestQueryMetricsResponseShape(t *testing.T) {
	result := `[{"metric":{"__name__":"up","job":"api"},"value":[1435781451.781,"1"]}]`
	encoded, err := json.Marshal(auth.QueryResponse{
		Provider:   auth.ProviderVictoriaMetrics,
		ResultType: "vector",
		Result:     json.RawMessage(result),
		Warnings:   []string{"the query was rewritten"},
		Infos:      []string{"an info line"},
		IsPartial:  true,
		Truncated:  true,
		DurationMS: 12,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"provider":"victoriametrics","resultType":"vector","result":`+result+`,
		"warnings":["the query was rewritten"],"infos":["an info line"],"isPartial":true,
		"truncated":true,"durationMs":12}`, string(encoded))
	// Verbatim, not merely equivalent: the bytes the provider kept are the
	// bytes the caller reads, in the order the source wrote them.
	require.Contains(t, string(encoded), result)
	require.NotContains(t, string(encoded), `"results":`)

	// A source that attached nothing leaves nothing behind: no empty warning
	// list, no false partial flag, no results key from the other provider.
	quiet, err := json.Marshal(auth.QueryResponse{
		Provider: auth.ProviderVictoriaMetrics, ResultType: "labels", Result: json.RawMessage(`["up"]`),
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"provider":"victoriametrics","resultType":"labels","result":["up"],
		"truncated":false,"durationMs":0}`, string(quiet))
}

func TestQueryMetricsRequestShape(t *testing.T) {
	encoded, err := json.Marshal(auth.QueryRequest{
		Connection: "payments-metrics", PromQL: "rate(errors_total[5m])",
		Start: "-1h", End: "now", Step: "1m", MaxRows: 500,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"payments-metrics","promql":"rate(errors_total[5m])",
		"start":"-1h","end":"now","step":"1m","maxRows":500}`, string(encoded))

	// Every input the caller did not set is absent, so the service reads one
	// input rather than an empty string that looks like one.
	discovery, err := json.Marshal(auth.QueryRequest{
		Connection: "payments-metrics", Labels: true, Match: `{job="api"}`,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"payments-metrics","labels":true,"match":"{job=\"api\"}"}`, string(discovery))
	values, err := json.Marshal(auth.QueryRequest{Connection: "c", LabelValues: "__name__"})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"c","labelValues":"__name__"}`, string(values))
	series, err := json.Marshal(auth.QueryRequest{Connection: "c", Series: "up", At: "now"})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"c","series":"up","at":"now"}`, string(series))
}

// The bounds a metrics execution runs under are the platform's own numbers,
// documented so a caller can predict the ceiling from the connection's cap.
func TestQueryMetricsBounds(t *testing.T) {
	require.Equal(t, 5*time.Second, auth.MetricsGrace)
	require.Equal(t, 4*(1<<20)+1<<20, auth.MetricsBodyCeiling(1<<20))
	require.Equal(t, 4*1024+1<<20, auth.MetricsBodyCeiling(1024))
	// A missing cap is the documented default rather than a ceiling of one MiB
	// that would refuse an ordinary answer.
	require.Equal(t, auth.MetricsBodyCeiling(auth.DefaultMaxBytes), auth.MetricsBodyCeiling(0))
	require.Equal(t, auth.MetricsBodyCeiling(auth.DefaultMaxBytes), auth.MetricsBodyCeiling(-1))
}

func TestValidLabelName(t *testing.T) {
	for _, name := range []string{"a", "_", "up", "__name__", "job_1", "A_b9", strings.Repeat("a", 256)} {
		require.True(t, auth.ValidLabelName(name), name)
	}
	for _, name := range []string{
		"", "1up", "9", "-up", "up-down", "up.down", "up down", "up/values",
		"../secret", "up\n", "naïve", "up{}", strings.Repeat("a", 257),
	} {
		require.False(t, auth.ValidLabelName(name), name)
	}
}

func TestQueryRequestShape(t *testing.T) {
	encoded, err := json.Marshal(auth.QueryRequest{Connection: "payments-prod-reporting", SQL: sentinelSQL})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"payments-prod-reporting","sql":"select 'SENTINEL_STATEMENT_TEXT'"}`, string(encoded))
	encoded, err = json.Marshal(auth.QueryRequest{Connection: "payments", SQL: "select 1", MaxRows: 10})
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"maxRows":10`)
	require.Equal(t, "/api/query", auth.QueryPath)
	require.Equal(t, 256*1024, auth.MaxSQLBytes)
	require.Equal(t, 64*1024, auth.QueryEnvelopeAllowance)
}

func TestQueryFailureAllowlist(t *testing.T) {
	for code, expected := range map[string]int{
		auth.SourceError:         http.StatusUnprocessableEntity,
		auth.SourceTimeout:       http.StatusGatewayTimeout,
		auth.SourceUnreachable:   http.StatusBadGateway,
		auth.SourceAuthRejected:  http.StatusBadGateway,
		auth.ProviderUnsupported: http.StatusBadRequest,
	} {
		t.Run(code, func(t *testing.T) {
			status, failure, known := auth.LookupFailure(code)
			require.True(t, known)
			require.Equal(t, expected, status)
			require.NotEmpty(t, failure.Message)
			status, response := auth.FailureFor(&auth.Error{Code: code})
			require.Equal(t, expected, status)
			require.Equal(t, code, response.Error.Code)
			require.Equal(t, failure.Message, response.Error.Message)
		})
	}
}

func TestQuerySourceFailureEnvelope(t *testing.T) {
	failure := &auth.Error{
		Code: auth.SourceError,
		Hint: "check the statement",
		Source: &auth.SourceFailure{
			SQLState: "42601", Message: `syntax error at or near "slect"`,
			Detail: "detail text", Hint: "source hint", Position: 1, Statement: auth.StatementIndex(1),
		},
	}
	status, response := auth.FailureFor(failure)
	require.Equal(t, http.StatusUnprocessableEntity, status)
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.JSONEq(t, `{"error":{"code":"SOURCE_ERROR","message":"The source rejected the SQL",
		"hint":"check the statement","source":{"sqlstate":"42601",
		"message":"syntax error at or near \"slect\"","detail":"detail text","hint":"source hint",
		"position":1,"statement":1}}}`, string(encoded))

	// The envelope round-trips, so a strict client reads the source block back
	// exactly as the service produced it.
	var decoded auth.ErrorResponse
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, response, decoded)

	// A zero statement index is the first statement, not an absent one, so it
	// is rendered whenever it is set; the optional text and position are
	// omitted instead.
	_, minimal := auth.FailureFor(&auth.Error{Code: auth.SourceError, Source: &auth.SourceFailure{
		SQLState: "57014", Statement: auth.StatementIndex(0),
	}})
	encoded, err = json.Marshal(minimal)
	require.NoError(t, err)
	require.JSONEq(t, `{"error":{"code":"SOURCE_ERROR","message":"The source rejected the SQL",
		"source":{"sqlstate":"57014","statement":0}}}`, string(encoded))
}

// A source without statements carries its own classification instead: no
// sqlstate, no statement index, and a client reads the block back as it is.
func TestQuerySourceFailureWithoutStatement(t *testing.T) {
	_, response := auth.FailureFor(&auth.Error{
		Code: auth.SourceError,
		Hint: "check the expression",
		Source: &auth.SourceFailure{
			ErrorType: "bad_data",
			Message:   `unsupported operation "%" for ranges`,
		},
	})
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.JSONEq(t, `{"error":{"code":"SOURCE_ERROR","message":"The source rejected the SQL",
		"hint":"check the expression","source":{"errorType":"bad_data",
		"message":"unsupported operation \"%\" for ranges"}}}`, string(encoded))
	require.NotContains(t, string(encoded), `"statement"`)
	require.NotContains(t, string(encoded), `"sqlstate"`)
	var decoded auth.ErrorResponse
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, response, decoded)
	require.Nil(t, decoded.Source.Statement)
}

func TestQueryFailureWithoutSource(t *testing.T) {
	for _, code := range []string{auth.SourceTimeout, auth.SourceUnreachable, auth.SourceAuthRejected, auth.ProviderUnsupported} {
		_, response := auth.FailureFor(&auth.Error{Code: code, Hint: "run clavis connections check"})
		require.Nil(t, response.Source)
		encoded, err := json.Marshal(response)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), `"source":`)
		var decoded auth.ErrorResponse
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, response, decoded)
	}
	// An unknown key inside the error object is still a rejection: assembling
	// the envelope by hand must not have loosened the client's strict reading.
	var decoded auth.ErrorResponse
	require.Error(t, json.Unmarshal([]byte(`{"error":{"code":"SOURCE_ERROR","surprise":1}}`), &decoded))
}

func TestQueryErrorTextCarriesNoStatement(t *testing.T) {
	failure := &auth.Error{Code: auth.SourceError, Source: &auth.SourceFailure{
		SQLState: "42601", Message: "syntax error in " + sentinelSQL, Statement: auth.StatementIndex(0),
	}}
	// The error's own text is the allowlisted message: the source's words, and
	// with them any fragment of the caller's statement, travel only in the
	// source block that the service puts in the envelope.
	require.Equal(t, "The source rejected the SQL", failure.Error())
	require.NotContains(t, failure.Error(), "SENTINEL_STATEMENT_TEXT")
	require.NotContains(t, fmt.Sprintf("%v", failure), "SENTINEL_STATEMENT_TEXT")

	// The request is not secret-bearing, so it may travel as JSON in full.
	encoded, err := json.Marshal(auth.QueryRequest{Connection: "payments", SQL: sentinelSQL})
	require.NoError(t, err)
	require.True(t, strings.Contains(string(encoded), "SENTINEL_STATEMENT_TEXT"))
}

// The log inputs travel as their own keys, and an absent limit is absent from
// the wire while an explicit zero is a zero the source will read: the platform
// never invents a limit and never drops the one a caller wrote.
func TestQueryLogsRequestShape(t *testing.T) {
	zero, fifty, wide := int64(0), int64(50), int64(1)<<62
	encoded, err := json.Marshal(auth.QueryRequest{
		Connection: "payments-logs", LogsQL: "error | sort by (_time) desc",
		Start: "-1h", End: "now", Limit: &fifty, MaxRows: 500,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"payments-logs","logsql":"error | sort by (_time) desc",
		"start":"-1h","end":"now","limit":50,"maxRows":500}`, string(encoded))

	// Omitted versus explicit zero: the pointer is the whole difference.
	omitted, err := json.Marshal(auth.QueryRequest{Connection: "c", LogsQL: "*"})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"c","logsql":"*"}`, string(omitted))
	require.NotContains(t, string(omitted), `"limit"`)
	explicit, err := json.Marshal(auth.QueryRequest{Connection: "c", LogsQL: "*", Limit: &zero})
	require.NoError(t, err)
	require.JSONEq(t, `{"connection":"c","logsql":"*","limit":0}`, string(explicit))
	require.Contains(t, string(explicit), `"limit":0`)

	// A limit beyond what a float would hold keeps every digit, which is why it
	// is an integer rather than a number the platform rounds on the way through.
	large, err := json.Marshal(auth.QueryRequest{Connection: "c", LogsQL: "*", Limit: &wide})
	require.NoError(t, err)
	require.Contains(t, string(large), `"limit":4611686018427387904`)
	var round auth.QueryRequest
	require.NoError(t, json.Unmarshal(large, &round))
	require.Equal(t, wide, *round.Limit)
	// A decoded request tells absent from zero as the encoder does.
	var decodedZero, decodedAbsent auth.QueryRequest
	require.NoError(t, json.Unmarshal(explicit, &decodedZero))
	require.NoError(t, json.Unmarshal(omitted, &decodedAbsent))
	require.NotNil(t, decodedZero.Limit)
	require.Equal(t, int64(0), *decodedZero.Limit)
	require.Nil(t, decodedAbsent.Limit)

	// Each discovery input is its own key, and every one of them takes match as
	// the source's query.
	for _, testCase := range []struct {
		request auth.QueryRequest
		want    string
	}{
		{auth.QueryRequest{Connection: "c", FieldNames: true, Match: "*"},
			`{"connection":"c","fieldNames":true,"match":"*"}`},
		{auth.QueryRequest{Connection: "c", FieldValues: "level", Match: "*", Filter: "err"},
			`{"connection":"c","fieldValues":"level","match":"*","filter":"err"}`},
		{auth.QueryRequest{Connection: "c", Streams: true, Match: "*"},
			`{"connection":"c","streams":true,"match":"*"}`},
		{auth.QueryRequest{Connection: "c", StreamFieldNames: true, Match: "*"},
			`{"connection":"c","streamFieldNames":true,"match":"*"}`},
		{auth.QueryRequest{Connection: "c", StreamFieldValues: "host", Match: "*"},
			`{"connection":"c","streamFieldValues":"host","match":"*"}`},
	} {
		encoded, err := json.Marshal(testCase.request)
		require.NoError(t, err)
		require.JSONEq(t, testCase.want, string(encoded))
	}
}

// Adding the log inputs leaves the other two providers' requests as they were:
// a caller that sends SQL or PromQL sends no log key at all.
func TestQueryRequestShapesStayDisjoint(t *testing.T) {
	logKeys := []string{"logsql", "fieldNames", "fieldValues", "streams",
		"streamFieldNames", "streamFieldValues", "limit", "filter"}
	for _, request := range []auth.QueryRequest{
		{Connection: "c", SQL: sentinelSQL},
		{Connection: "c", PromQL: "up", Start: "-1h", Step: "1m"},
		{Connection: "c", Labels: true, Match: `{job="api"}`},
		{Connection: "c", LabelValues: "__name__"},
		{Connection: "c", Series: "up"},
	} {
		encoded, err := json.Marshal(request)
		require.NoError(t, err)
		for _, key := range logKeys {
			require.NotContains(t, string(encoded), `"`+key+`":`, key)
		}
	}
	// And a log request carries nothing of theirs.
	encoded, err := json.Marshal(auth.QueryRequest{Connection: "c", LogsQL: "*"})
	require.NoError(t, err)
	for _, key := range []string{"sql", "promql", "at", "step", "labels", "labelValues", "series"} {
		require.NotContains(t, string(encoded), `"`+key+`":`, key)
	}
}

// The log shape is the source's own answer: result travels verbatim under a
// name the platform gives the input, because a log source writes none itself.
func TestQueryLogsResponseShape(t *testing.T) {
	rows := `[{"_time":"2026-09-14T10:00:00Z","_msg":"boom","level":"error"},{"level":"info","n":12}]`
	encoded, err := json.Marshal(auth.QueryResponse{
		Provider: auth.ProviderVictoriaLogs, ResultType: "logs",
		Result: json.RawMessage(rows), Truncated: true, DurationMS: 9,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"provider":"victorialogs","resultType":"logs","result":`+rows+`,
		"truncated":true,"durationMs":9}`, string(encoded))
	require.Contains(t, string(encoded), rows)
	require.NotContains(t, string(encoded), `"results":`)
	// A log answer carries none of the metrics envelope's own members.
	for _, key := range []string{"warnings", "infos", "isPartial"} {
		require.NotContains(t, string(encoded), `"`+key+`":`)
	}
	for _, resultType := range []string{"fieldNames", "fieldValues", "streams",
		"streamFieldNames", "streamFieldValues"} {
		values, err := json.Marshal(auth.QueryResponse{
			Provider: auth.ProviderVictoriaLogs, ResultType: resultType,
			Result: json.RawMessage(`[{"value":"error","hits":1234567890123}]`),
		})
		require.NoError(t, err)
		require.JSONEq(t, `{"provider":"victorialogs","resultType":"`+resultType+`",
			"result":[{"value":"error","hits":1234567890123}],"truncated":false,"durationMs":0}`, string(values))
	}
}

func TestValidProviderTakesThree(t *testing.T) {
	for _, provider := range []auth.ProviderType{
		auth.ProviderPostgreSQL, auth.ProviderVictoriaMetrics, auth.ProviderVictoriaLogs,
	} {
		require.True(t, auth.ValidProvider(provider), string(provider))
	}
	for _, provider := range []string{"", "victoria", "VICTORIALOGS", "logs", "SENTINEL"} {
		require.False(t, auth.ValidProvider(auth.ProviderType(provider)), provider)
	}
}

// A tenant identifier travels as a request header the source reads as an
// identity, so it is one of the few inputs the platform validates itself.
func TestValidTenantID(t *testing.T) {
	for _, value := range []string{"0", "1", "12", "0012", "4294967295", "0000000000"} {
		require.True(t, auth.ValidTenantID(value), value)
	}
	for _, value := range []string{
		"", " ", "1 ", " 1", "+1", "-1", "1.0", "1e3", "0x10", "abc", "१२",
		"4294967296", "99999999999", "12345678901", "1\n", "1\x00", "1,2",
	} {
		require.False(t, auth.ValidTenantID(value), value)
	}
	require.Equal(t, 1024, auth.MaxFilterBytes)
}
