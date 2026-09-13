package auth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

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
	require.JSONEq(t, `{"results":[
		{"command":"SELECT","columns":[{"name":"n","type":"numeric"},{"name":"n","type":"text"}],
		 "rows":[["42",null],[null,""]],"rowCount":2,"truncated":false},
		{"command":"UPDATE","columns":[],"rows":[],"rowCount":3,"truncated":false}
	],"truncated":true,"durationMs":17}`, string(encoded))
	require.Contains(t, string(encoded), `"rows":[]`)
	require.Contains(t, string(encoded), `"columns":[]`)

	// One statement is still a list, so a caller never branches on the shape
	// of what it sent, and a response with no statement at all is an empty one.
	single, err := json.Marshal(auth.QueryResponse{Results: []auth.QueryResult{{
		Command: "CREATE", Columns: []auth.QueryColumn{}, Rows: [][]*string{},
	}}})
	require.NoError(t, err)
	require.Contains(t, string(single), `"results":[{`)
	none, err := json.Marshal(auth.QueryResponse{Results: []auth.QueryResult{}})
	require.NoError(t, err)
	require.Contains(t, string(none), `"results":[]`)
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
			Detail: "detail text", Hint: "source hint", Position: 1, Statement: 1,
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
	// is always rendered; the optional text and position are omitted instead.
	_, minimal := auth.FailureFor(&auth.Error{Code: auth.SourceError, Source: &auth.SourceFailure{SQLState: "57014"}})
	encoded, err = json.Marshal(minimal)
	require.NoError(t, err)
	require.JSONEq(t, `{"error":{"code":"SOURCE_ERROR","message":"The source rejected the SQL",
		"source":{"sqlstate":"57014","statement":0}}}`, string(encoded))
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
		SQLState: "42601", Message: "syntax error in " + sentinelSQL, Statement: 0,
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
