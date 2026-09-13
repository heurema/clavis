package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"
)

// The hints below are the fixture's application-owned guidance for the query
// route. They never echo the submitted statement, exactly as the contract
// requires of every message this command can produce.
const (
	queryNotFoundHint    = "List connections to see what you may use"
	queryDisabledHint    = "Ask an administrator to enable the connection"
	queryUnsupportedHint = "Only postgresql connections execute SQL"
	querySourceHint      = "Correct the statement and try again"
)

// serveQuery implements the design's execution route over the fixture's
// stores: strict decoding, the documented authorization order, the source
// failure nested in the envelope and the caller's own row bound.
func (f *cliAuthFixture) serveQuery(w http.ResponseWriter, r *http.Request, actor auth.Identity, body []byte, fail func(string)) {
	f.queryCalls++
	f.queryBody = body
	failWith := func(failure *auth.Error) {
		status, safe, _ := auth.LookupFailure(failure.Code)
		safe.Hint = failure.Hint
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe, Source: failure.Source})
	}
	var input auth.QueryRequest
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" ||
		!strictJSON(body, &input) || !auth.ValidConnectionRef(input.Connection) ||
		input.SQL == "" || len(input.SQL) > auth.MaxSQLBytes || input.MaxRows < 0 {
		fail(auth.InvalidArgument)
		return
	}
	if f.queryFailure != nil {
		failWith(f.queryFailure)
		return
	}
	role := actor.User.Role
	if i := f.userIndex(actor.User.ID); i >= 0 {
		role = f.users[i].Role
	}
	index := f.connectionIndex(input.Connection)
	// An ungranted connection is absent, not disclosed: a member sees the same
	// answer for one they may not use as for one that does not exist.
	if index < 0 || (role != auth.Admin && !f.grantedTo(actor.User.ID, f.connections[index].ID)) {
		failWith(&auth.Error{Code: auth.ConnectionNotFound, Hint: queryNotFoundHint})
		return
	}
	connection := f.connections[index]
	if !connection.Enabled {
		failWith(&auth.Error{Code: auth.ConnectionDisabled, Hint: queryDisabledHint})
		return
	}
	if connection.Provider != auth.ProviderPostgreSQL {
		failWith(&auth.Error{Code: auth.ProviderUnsupported, Hint: queryUnsupportedHint})
		return
	}
	_ = json.NewEncoder(w).Encode(lowerRows(f.queryResponse, input.MaxRows))
}

func (f *cliAuthFixture) grantedTo(userID, connectionID string) bool {
	for _, granted := range f.grantedConnections(userID) {
		if granted.ID == connectionID {
			return true
		}
	}
	return false
}

// lowerRows applies the caller's own bound the way the service does: rows past
// it are dropped and the result says so, at both levels.
func lowerRows(response auth.QueryResponse, maxRows int) auth.QueryResponse {
	if maxRows < 1 {
		return response
	}
	results := make([]auth.QueryResult, 0, len(response.Results))
	for _, result := range response.Results {
		if len(result.Rows) > maxRows {
			result.Rows, result.Truncated, response.Truncated = result.Rows[:maxRows], true, true
		}
		results = append(results, result)
	}
	response.Results = results
	return response
}

func value(text string) *string { return &text }

// queryRows is the documented result shape: exact values as strings, a NULL,
// and a second statement without rows.
func queryRows() auth.QueryResponse {
	return auth.QueryResponse{
		Results: []auth.QueryResult{{
			Command: "SELECT",
			Columns: []auth.QueryColumn{{Name: "id", Type: "int8"}, {Name: "label", Type: "text"}},
			Rows: [][]*string{
				{value("1"), value("alpha")},
				{value("22"), nil},
				{value("333"), value("")},
			},
			RowCount: 3,
		}, {
			Command: "UPDATE", Columns: []auth.QueryColumn{}, Rows: [][]*string{}, RowCount: 2,
		}},
		DurationMS: 17,
	}
}

// queryFixture signs an administrator in against a fixture holding one enabled
// PostgreSQL connection, one disabled one and one VictoriaMetrics one, which
// is every authorization branch the route documents.
func queryFixture(t *testing.T) (*cliAuthFixture, *httptest.Server) {
	t.Helper()
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	fixture.mu.Lock()
	granted := testConnection("payments-prod-reporting")
	disabled := testConnection("warehouse-primary")
	disabled.ID, disabled.Name, disabled.Enabled = testUserID(), "warehouse-primary", false
	metrics := testConnection("metrics-prod")
	metrics.ID, metrics.Name, metrics.Provider = testUserID(), "metrics-prod", auth.ProviderVictoriaMetrics
	fixture.connections = append(fixture.connections, granted, disabled, metrics)
	fixture.queryResponse = queryRows()
	fixture.mu.Unlock()
	return fixture, server
}

func queryRun(t *testing.T, server *httptest.Server, args ...string) (int, Result, string) {
	t.Helper()
	return cliInvoke(t, "", append(args, "--server", server.URL)...)
}

func queryText(t *testing.T, server *httptest.Server, stdin string, args ...string) (int, string) {
	t.Helper()
	var out, prompt bytes.Buffer
	arguments := append([]string{"clavis", "--output=text"}, append(args, "--server", server.URL)...)
	exit := RunWithIO(context.Background(), arguments, IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &prompt, ReadPassword: ReadTerminalPassword,
	})
	require.Empty(t, prompt.String())
	return exit, out.String()
}

// The inline statement is sent as one request and answered with the documented
// document: a list of results, columns with the source's type names and rows
// of strings with null for NULL.
func TestQueryInlineReturnsTheResultsDocument(t *testing.T) {
	fixture, server := queryFixture(t)
	exit, result, output := queryRun(t, server, "query", "--connection", "payments-prod-reporting",
		"--sql", "select id, label from notes")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.True(t, result.OK)
	document := result.Data.(map[string]any)
	results := document["results"].([]any)
	require.Len(t, results, 2)
	first := results[0].(map[string]any)
	require.Equal(t, "SELECT", first["command"])
	require.Equal(t, []any{map[string]any{"name": "id", "type": "int8"},
		map[string]any{"name": "label", "type": "text"}}, first["columns"])
	require.Equal(t, []any{"1", "alpha"}, first["rows"].([]any)[0])
	require.Equal(t, []any{"22", nil}, first["rows"].([]any)[1])
	require.Equal(t, float64(3), first["rowCount"])
	require.Equal(t, false, document["truncated"])
	require.Equal(t, float64(17), document["durationMs"])
	// The statement is sent once, unchanged, and never echoed back.
	expected, err := json.Marshal(auth.QueryRequest{Connection: "payments-prod-reporting", SQL: "select id, label from notes"})
	require.NoError(t, err)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, 1, fixture.queryCalls)
	require.Equal(t, string(expected), string(fixture.queryBody))
	require.NotContains(t, output, "from notes")
}

// A heredoc is the shape an agent drives the command with, and a file is the
// shape a stored script takes; both reach the server byte for byte.
func TestQueryReadsStdinAndFiles(t *testing.T) {
	fixture, server := queryFixture(t)
	script := "insert into notes values ('x');\nselect count(*) from notes;\n"
	exit, output := queryText(t, server, script, "query", "--connection", "payments-prod-reporting", "--sql-stdin")
	require.Equal(t, 0, exit, output)
	fixture.mu.Lock()
	var sent auth.QueryRequest
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	fixture.mu.Unlock()
	require.Equal(t, script, sent.SQL)

	path := filepath.Join(t.TempDir(), "report.sql")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o644))
	exit, result, _ := queryRun(t, server, "query", "--connection", "payments-prod-reporting", "--sql-file", path)
	require.Equal(t, 0, exit, "%+v", result.Error)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	require.Equal(t, script, sent.SQL)
	// A world-readable script is fine: SQL is not a secret.
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

// The caller's own bound is sent and the truncated answer is still a success.
func TestQueryLowersTheRowBoundAndReportsTruncation(t *testing.T) {
	fixture, server := queryFixture(t)
	exit, result, _ := queryRun(t, server, "query", "--connection", "payments-prod-reporting",
		"--sql", "select id, label from notes", "--max-rows", "1")
	require.Equal(t, 0, exit, "%+v", result.Error)
	document := result.Data.(map[string]any)
	require.Equal(t, true, document["truncated"])
	first := document["results"].([]any)[0].(map[string]any)
	require.Len(t, first["rows"].([]any), 1)
	require.Equal(t, true, first["truncated"])
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	var sent auth.QueryRequest
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	require.Equal(t, 1, sent.MaxRows)
}

// The text rendering is the agent-facing one: an aligned table per result, a
// distinct NULL, the kept-row count, the command tag for statements without
// rows, then the truncation notice and the duration.
func TestQueryTextRendering(t *testing.T) {
	truncated := queryRows()
	truncated.Results[0].Rows = truncated.Results[0].Rows[:1]
	truncated.Results[0].Truncated, truncated.Truncated = true, true
	empty := auth.QueryResponse{
		Results:    []auth.QueryResult{{Columns: []auth.QueryColumn{}, Rows: [][]*string{}}},
		DurationMS: 1,
	}
	noRows := auth.QueryResponse{
		Results: []auth.QueryResult{{Command: "SELECT",
			Columns: []auth.QueryColumn{{Name: "id", Type: "int8"}}, Rows: [][]*string{}}},
		DurationMS: 2,
	}
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"table": {success(queryRows()),
			"id   label\n" +
				"1    alpha\n" +
				"22   ∅\n" +
				"333  \n" +
				"(3 rows)\n" +
				"UPDATE 2\n" +
				"Duration: 17 ms\n"},
		"truncated": {success(truncated),
			"id  label\n1   alpha\n(1 rows)\nUPDATE 2\nTruncated: true\nDuration: 17 ms\n"},
		"empty-statement": {success(empty), "(empty statement) 0\nDuration: 1 ms\n"},
		"no-rows":         {success(noRows), "id\n(0 rows)\nDuration: 2 ms\n"},
		"source-error": {failureWithSource(auth.SourceError, "The source rejected the SQL", querySourceHint,
			&auth.SourceFailure{SQLState: "42601", Message: `syntax error at or near "selec"`,
				Detail: "the parser stopped here", Hint: "check the spelling", Position: 1, Statement: auth.StatementIndex(0)}),
			"SOURCE_ERROR: The source rejected the SQL\nHint: " + querySourceHint + "\n" +
				"ERROR: 42601 syntax error at or near \"selec\"\n" +
				"DETAIL: the parser stopped here\nHINT: check the spelling\nPosition: 1\nStatement: 0\n"},
		"source-minimal": {failureWithSource(auth.SourceError, "The source rejected the SQL", "",
			&auth.SourceFailure{SQLState: "42703", Message: "column x does not exist", Statement: auth.StatementIndex(1)}),
			"SOURCE_ERROR: The source rejected the SQL\nERROR: 42703 column x does not exist\nStatement: 1\n"},
		"timeout": {failureWithHint(auth.SourceTimeout, "The statement timeout was exceeded", "The bound is 1000 ms"),
			"SOURCE_TIMEOUT: The statement timeout was exceeded\nHint: The bound is 1000 ms\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, render(&out, tc.result, "text"))
			require.Equal(t, tc.want, out.String())
			var encoded bytes.Buffer
			require.NoError(t, render(&encoded, tc.result, "json"))
			require.Equal(t, 1, decode(t, encoded.String()).SchemaVersion)
		})
	}
}

// failureWithSource is only used by the rendering table above; the transport
// builds the same envelope from the server's own error.source block.
func failureWithSource(code, message, hint string, source *auth.SourceFailure) Result {
	result := failureWithHint(code, message, hint)
	result.Error.Source = source
	return result
}

// Every local rejection exits 2, names the rule and reaches no request at all.
func TestQueryArgumentsRejectedBeforeIO(t *testing.T) {
	fixture, server := queryFixture(t)
	path := filepath.Join(t.TempDir(), "script.sql")
	require.NoError(t, os.WriteFile(path, []byte("select 1"), 0o644))
	fixture.mu.Lock()
	before := fixture.queryCalls
	fixture.mu.Unlock()
	for _, tc := range []struct {
		name string
		args []string
		hint string
	}{
		{"no input", []string{"query", "--connection", "payments-prod-reporting"}, sqlInputHint},
		{"two inputs", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--sql-file", path}, sqlInputHint},
		{"stdin and inline", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--sql-stdin"}, sqlInputHint},
		{"relative file", []string{"query", "--connection", "payments-prod-reporting", "--sql-file", "script.sql"}, sqlInputHint},
		{"missing file", []string{"query", "--connection", "payments-prod-reporting", "--sql-file", filepath.Join(t.TempDir(), "absent.sql")}, sqlInputHint},
		{"directory", []string{"query", "--connection", "payments-prod-reporting", "--sql-file", t.TempDir()}, sqlInputHint},
		{"empty sql", []string{"query", "--connection", "payments-prod-reporting", "--sql", ""}, sqlBoundHint},
		{"oversized sql", []string{"query", "--connection", "payments-prod-reporting", "--sql", strings.Repeat("x", auth.MaxSQLBytes+1)}, sqlBoundHint},
		{"no connection", []string{"query", "--sql", "select 1"}, connectionRefHint},
		{"invalid connection", []string{"query", "--connection", "PAYMENTS", "--sql", "select 1"}, connectionRefHint},
		{"zero max rows", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--max-rows", "0"}, maxRowsHint},
		{"negative max rows", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--max-rows", "-1"}, maxRowsHint},
		{"non-numeric max rows", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--max-rows", "abc"}, ""},
		{"max rows above ceiling", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--max-rows", "100001"}, maxRowsHint},
		{"positional argument", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "extra"}, ""},
		{"unknown flag", []string{"query", "--connection", "payments-prod-reporting", "--statement", "select 1"}, ""},
		{"zero timeout", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--timeout=0"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, result, output := queryRun(t, server, tc.args...)
			require.Equal(t, 2, exit)
			require.Equal(t, auth.InvalidArgument, result.Error.Code)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
			if tc.hint != "" {
				require.Equal(t, tc.hint, result.Error.Hint)
			}
			require.NotContains(t, output, "select 1")
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.queryCalls, "no request may be made")
}

// An oversized statement on stdin is refused locally too, so a script that
// could never be accepted is never uploaded.
func TestQueryBoundsStdinLocally(t *testing.T) {
	fixture, server := queryFixture(t)
	fixture.mu.Lock()
	before := fixture.queryCalls
	fixture.mu.Unlock()
	exit, result, _ := cliInvoke(t, strings.Repeat("x", auth.MaxSQLBytes+1),
		"query", "--connection", "payments-prod-reporting", "--sql-stdin", "--server", server.URL)
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, sqlBoundHint, result.Error.Hint)
	fixture.mu.Lock()
	require.Equal(t, before, fixture.queryCalls)
	fixture.mu.Unlock()
	// A statement filling the bound exactly is still accepted and sent.
	exit, result, _ = cliInvoke(t, "select '"+strings.Repeat("x", auth.MaxSQLBytes-len("select ''"))+"'",
		"query", "--connection", "payments-prod-reporting", "--sql-stdin", "--server", server.URL)
	require.Equal(t, 0, exit, "%+v", result.Error)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	var sent auth.QueryRequest
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	require.Len(t, sent.SQL, auth.MaxSQLBytes)
}

func TestQueryRequiresACachedSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t, testToken())
	exit, result, _ := queryRun(t, server, "query", "--connection", "payments-prod-reporting", "--sql", "select 1")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Unauthenticated, result.Error.Code)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.queryCalls)
}

// Every documented code passes through with its hint and exits 1.
func TestQueryDocumentedFailures(t *testing.T) {
	fixture, server := queryFixture(t)
	for _, tc := range []struct {
		name, connection, code, hint string
	}{
		{"absent", "no-such-connection", auth.ConnectionNotFound, queryNotFoundHint},
		{"disabled", "warehouse-primary", auth.ConnectionDisabled, queryDisabledHint},
		{"unsupported", "metrics-prod", auth.ProviderUnsupported, queryUnsupportedHint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, result, _ := queryRun(t, server, "query", "--connection", tc.connection, "--sql", "select 1")
			require.Equal(t, 1, exit)
			require.Equal(t, tc.code, result.Error.Code)
			require.Equal(t, tc.hint, result.Error.Hint)
		})
	}
	for _, tc := range []struct {
		failure *auth.Error
		source  bool
	}{
		{&auth.Error{Code: auth.SourceError, Hint: querySourceHint, Source: &auth.SourceFailure{
			SQLState: "42601", Message: `syntax error at or near "selec"`, Position: 1,
			Statement: auth.StatementIndex(0)}}, true},
		{&auth.Error{Code: auth.SourceTimeout, Hint: "The bound is 1000 ms"}, false},
		{&auth.Error{Code: auth.SourceUnreachable, Hint: "Run connections check"}, false},
		{&auth.Error{Code: auth.SourceAuthRejected, Hint: "Run connections check"}, false},
		{&auth.Error{Code: auth.CredentialsUnavailable, Hint: "Set the credential again"}, false},
		{&auth.Error{Code: auth.Forbidden}, false},
		{&auth.Error{Code: auth.Unauthenticated}, false},
	} {
		t.Run(tc.failure.Code, func(t *testing.T) {
			fixture.mu.Lock()
			fixture.queryFailure = tc.failure
			fixture.mu.Unlock()
			defer func() {
				fixture.mu.Lock()
				fixture.queryFailure = nil
				fixture.mu.Unlock()
			}()
			exit, result, output := queryRun(t, server, "query", "--connection", "payments-prod-reporting", "--sql", "select 1")
			require.Equal(t, 1, exit)
			require.Equal(t, tc.failure.Code, result.Error.Code)
			require.Equal(t, tc.failure.Hint, result.Error.Hint)
			require.NotContains(t, output, "select 1")
			if !tc.source {
				require.Nil(t, result.Error.Source)
				return
			}
			require.NotNil(t, result.Error.Source)
			require.Equal(t, "42601", result.Error.Source.SQLState)
			require.Equal(t, 1, result.Error.Source.Position)
			// Zero is meaningful and is always carried.
			require.NotNil(t, result.Error.Source.Statement)
			require.Equal(t, 0, *result.Error.Source.Statement)
		})
	}
}

// A source error in text output prints the source's own lines and exits 1,
// without repeating the statement that caused it.
func TestQuerySourceErrorAsText(t *testing.T) {
	fixture, server := queryFixture(t)
	fixture.mu.Lock()
	fixture.queryFailure = &auth.Error{Code: auth.SourceError, Hint: querySourceHint,
		Source: &auth.SourceFailure{SQLState: "42703", Message: "column x does not exist", Statement: auth.StatementIndex(1)}}
	fixture.mu.Unlock()
	exit, output := queryText(t, server, "", "query", "--connection", "payments-prod-reporting", "--sql", "select x from notes")
	require.Equal(t, 1, exit)
	require.Equal(t, "SOURCE_ERROR: The source rejected the SQL\nHint: "+querySourceHint+"\n"+
		"ERROR: 42703 column x does not exist\nStatement: 1\n", output)
	require.NotContains(t, output, "from notes")
}

// The truncated table is a success in text output too, with the notice visible.
func TestQueryTruncatedTextExitsZero(t *testing.T) {
	_, server := queryFixture(t)
	exit, output := queryText(t, server, "", "query", "--connection", "payments-prod-reporting",
		"--sql", "select id, label from notes", "--max-rows", "2")
	require.Equal(t, 0, exit)
	require.Equal(t, "id  label\n1   alpha\n22  ∅\n(2 rows)\nUPDATE 2\nTruncated: true\nDuration: 17 ms\n", output)
}

// hostileQuery answers every request with one canned document, which is how a
// malformed or undocumented response is exercised without the fixture.
func hostileQuery(t *testing.T, status int, contentType, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func sendQuery(t *testing.T, server *httptest.Server, output *auth.QueryResponse) *Result {
	t.Helper()
	route := apiCall{http.MethodPost, auth.QueryPath, "", http.StatusOK}
	return (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(),
		&auth.QueryRequest{Connection: "payments-prod-reporting", SQL: "select 1"}, output)
}

// A results document that is not the documented shape is refused rather than
// rendered with missing, extra or mismatched members.
func TestQueryTransportStrictResponses(t *testing.T) {
	valid := `{"results":[{"command":"SELECT","columns":[{"name":"id","type":"int8"}],` +
		`"rows":[["1"],[null]],"rowCount":2,"truncated":false}],"truncated":false,"durationMs":4}`
	for name, tc := range map[string]struct {
		body  string
		valid bool
	}{
		"valid":            {valid, true},
		"empty command":    {strings.Replace(valid, `"command":"SELECT"`, `"command":""`, 1), true},
		"unknown member":   {strings.Replace(valid, `"durationMs":4`, `"durationMs":4,"extra":1`, 1), false},
		"case alias":       {strings.Replace(valid, `"durationMs"`, `"DurationMs"`, 1), false},
		"numeric row":      {strings.Replace(valid, `[["1"],[null]]`, `[[1],[null]]`, 1), false},
		"object row":       {strings.Replace(valid, `[["1"],[null]]`, `[[{"v":1}],[null]]`, 1), false},
		"short row":        {strings.Replace(valid, `[["1"],[null]]`, `[[]]`, 1), false},
		"long row":         {strings.Replace(valid, `[["1"],[null]]`, `[["1","2"]]`, 1), false},
		"rows no columns":  {strings.Replace(valid, `"columns":[{"name":"id","type":"int8"}]`, `"columns":[]`, 1), false},
		"blank column":     {strings.Replace(valid, `"name":"id"`, `"name":""`, 1), false},
		"control column":   {strings.Replace(valid, `"name":"id"`, "\"name\":\"a\ab\"", 1), false},
		"negative count":   {strings.Replace(valid, `"rowCount":2`, `"rowCount":-1`, 1), false},
		"negative runtime": {strings.Replace(valid, `"durationMs":4`, `"durationMs":-4`, 1), false},
		"hidden truncation": {strings.Replace(valid, `"rowCount":2,"truncated":false}],"truncated":false`,
			`"rowCount":2,"truncated":true}],"truncated":false`, 1), false},
		"results object": {`{"results":{},"truncated":false,"durationMs":4}`, false},
		"not an object":  {`["results"]`, false},
	} {
		t.Run(name, func(t *testing.T) {
			server := hostileQuery(t, http.StatusOK, "application/json", tc.body)
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			if tc.valid {
				require.Nil(t, failed)
				require.Len(t, response.Results, 1)
				return
			}
			require.NotNil(t, failed)
			require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
		})
	}
}

// A body above the route's own response bound is reported rather than
// partially displayed, and one inside it passes even though it is far above
// the general limit.
func TestQueryResponseBoundIsTheRouteBound(t *testing.T) {
	require.Equal(t, 2*auth.MaxMaxBytes+auth.QueryEnvelopeAllowance, responseLimit(http.MethodPost, auth.QueryPath))
	require.Equal(t, auth.MaxResponseBody, responseLimit(http.MethodPost, auth.LogoutPath))
	require.Equal(t, auth.MaxListingBody, responseLimit(http.MethodGet, auth.GrantsPath))
	require.Equal(t, auth.MaxSQLBytes+queryBodyAllowance, requestLimit(auth.QueryPath))
	require.Equal(t, auth.MaxCredentialBody, requestLimit(auth.GrantsPath))

	large := `{"results":[{"command":"SELECT","columns":[{"name":"v","type":"text"}],"rows":[["` +
		strings.Repeat("x", auth.MaxResponseBody*2) + `"]],"rowCount":1,"truncated":false}],` +
		`"truncated":false,"durationMs":4}`
	server := hostileQuery(t, http.StatusOK, "application/json", large)
	var response auth.QueryResponse
	require.Nil(t, sendQuery(t, server, &response))
	require.Len(t, *response.Results[0].Rows[0][0], auth.MaxResponseBody*2)

	oversized := `{"results":[{"command":"SELECT","columns":[{"name":"v","type":"text"}],"rows":[["` +
		strings.Repeat("x", responseLimit(http.MethodPost, auth.QueryPath)) + `"]],"rowCount":1,"truncated":false}],` +
		`"truncated":false,"durationMs":4}`
	server = hostileQuery(t, http.StatusOK, "application/json", oversized)
	failed := sendQuery(t, server, &response)
	require.NotNil(t, failed)
	require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
}

// A request above the route's own bound is refused locally: the CLI never
// uploads a body the route would reject.
func TestQueryRequestBoundIsLocal(t *testing.T) {
	server := hostileQuery(t, http.StatusOK, "application/json", `{"results":[],"truncated":false,"durationMs":1}`)
	var response auth.QueryResponse
	route := apiCall{http.MethodPost, auth.QueryPath, "", http.StatusOK}
	input := auth.QueryRequest{Connection: "payments-prod-reporting", SQL: strings.Repeat("x", auth.MaxSQLBytes+queryBodyAllowance)}
	failed := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), &input, &response)
	require.NotNil(t, failed)
	require.Equal(t, auth.InvalidArgument, failed.Error.Code)
}

// An undocumented code on the query route, and a query code on another route,
// are both refused: the allowlist is per route in both directions.
func TestQueryFailureAllowlistIsPerRoute(t *testing.T) {
	for _, code := range []string{auth.UserNotFound, auth.ConnectionExists, auth.ConnectionInUse,
		auth.UsernameTaken, auth.LastAdministrator, auth.SelfTarget} {
		t.Run("query/"+code, func(t *testing.T) {
			status, safe, _ := auth.LookupFailure(code)
			body, err := json.Marshal(auth.ErrorResponse{Error: safe})
			require.NoError(t, err)
			server := hostileQuery(t, status, "application/json", string(body))
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			require.NotNil(t, failed)
			require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
		})
	}
	for _, code := range []string{auth.SourceError, auth.SourceTimeout, auth.SourceUnreachable,
		auth.SourceAuthRejected, auth.ProviderUnsupported} {
		for _, route := range []apiCall{
			{http.MethodGet, auth.GrantsPath, "", http.StatusOK},
			{http.MethodPost, auth.GrantsPath, "", http.StatusCreated},
			{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK},
			{http.MethodGet, auth.WhoAmIPath, "", http.StatusOK},
			{http.MethodPost, auth.UsersPath, "", http.StatusCreated},
		} {
			t.Run(code+"/"+route.path, func(t *testing.T) {
				status, safe, _ := auth.LookupFailure(code)
				body, err := json.Marshal(auth.ErrorResponse{Error: safe})
				require.NoError(t, err)
				server := hostileQuery(t, status, "application/json", string(body))
				var list auth.GrantList
				failed := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), nil, &list)
				require.NotNil(t, failed)
				require.Equal(t, "INVALID_RESPONSE", failed.Error.Code, code)
			})
		}
	}
}

// The source block is accepted only where it is documented, and only when it
// is itself well formed.
func TestQuerySourceBlockIsStrict(t *testing.T) {
	envelope := func(code string, source string) string {
		_, safe, _ := auth.LookupFailure(code)
		return `{"error":{"code":"` + safe.Code + `","message":"` + safe.Message + `","source":` + source + `}}`
	}
	good := `{"sqlstate":"42601","message":"syntax error","statement":0}`
	for name, tc := range map[string]struct {
		code, source string
		valid        bool
	}{
		"well formed":     {auth.SourceError, good, true},
		"no sqlstate":     {auth.SourceError, `{"message":"syntax error","statement":0}`, true},
		"bad sqlstate":    {auth.SourceError, `{"sqlstate":"4260","message":"x","statement":0}`, false},
		"lowercase state": {auth.SourceError, `{"sqlstate":"42a01","message":"x","statement":0}`, false},
		"no message":      {auth.SourceError, `{"sqlstate":"42601","statement":0}`, false},
		"control message": {auth.SourceError, "{\"sqlstate\":\"42601\",\"message\":\"a\ab\",\"statement\":0}", false},
		"negative offset": {auth.SourceError, `{"sqlstate":"42601","message":"x","position":-1,"statement":0}`, false},
		"unknown member":  {auth.SourceError, `{"sqlstate":"42601","message":"x","statement":0,"severity":"ERROR"}`, false},
		"wrong code":      {auth.SourceTimeout, good, false},
		"other failure":   {auth.ConnectionNotFound, good, false},
	} {
		t.Run(name, func(t *testing.T) {
			status, _, _ := auth.LookupFailure(tc.code)
			server := hostileQuery(t, status, "application/json", envelope(tc.code, tc.source))
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			require.NotNil(t, failed)
			if !tc.valid {
				require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
				return
			}
			require.Equal(t, tc.code, failed.Error.Code)
			require.NotNil(t, failed.Error.Source)
			require.Equal(t, "syntax error", failed.Error.Source.Message)
		})
	}
	// A source block on the query route but on another route's transport is
	// still refused, which is what keeps the block route-scoped.
	server := hostileQuery(t, http.StatusUnprocessableEntity, "application/json", envelope(auth.SourceError, good))
	var list auth.GrantList
	route := apiCall{http.MethodGet, auth.GrantsPath, "", http.StatusOK}
	failed := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), nil, &list)
	require.NotNil(t, failed)
	require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
}

// Execution is the one command that waits on an external source, so its
// whole-request deadline defaults to the execution budget rather than the five
// seconds every other command takes. Every command still accepts --timeout.
func TestQueryTimeoutDefaultsToTheExecutionBudget(t *testing.T) {
	commands := authCommands(IO{}, func(*urfave.Command) error { return nil }, func(Result) {})
	defaults := map[string]time.Duration{}
	for _, command := range commands {
		for _, flag := range command.Flags {
			duration, ok := flag.(*urfave.DurationFlag)
			if ok && duration.Name == "timeout" {
				defaults[command.Name] = duration.Value
			}
		}
	}
	require.Equal(t, auth.QueryRequestBudget, defaults["query"])
	require.Equal(t, 20*time.Minute+10*time.Second, auth.QueryRequestBudget)
	for _, name := range []string{"login", "logout", "whoami"} {
		require.Equal(t, sharedTimeout, defaults[name], name)
	}
	// The usage text says why, so an agent reading help knows what the default
	// covers rather than guessing at it.
	for _, command := range commands {
		if command.Name != "query" {
			continue
		}
		for _, flag := range command.Flags {
			if duration, ok := flag.(*urfave.DurationFlag); ok && duration.Name == "timeout" {
				require.Equal(t, queryTimeoutUsage, duration.Usage)
			}
		}
	}
}

// A member runs a query on a connection granted to them and is refused on one
// that is not, with the same answer an absent connection gives.
func TestQueryIsScopedToGrantsForMembers(t *testing.T) {
	fixture, server, memberID, token := memberFixture(t)
	fixture.mu.Lock()
	fixture.queryResponse = queryRows()
	fixture.mu.Unlock()
	runAs(t, server, token, auth.Identity{
		User:      auth.User{ID: memberID, Username: "alice", Role: auth.Member},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	})
	exit, result, _ := queryRun(t, server, "query", "--connection", "payments-prod-reporting", "--sql", "select 1")
	require.Equal(t, 0, exit, "%+v", result.Error)
	exit, result, _ = queryRun(t, server, "query", "--connection", "warehouse-primary", "--sql", "select 1")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.ConnectionNotFound, result.Error.Code)
}
