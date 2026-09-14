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
	queryWantsSQLHint    = "This connection is postgresql: send sql"
	queryWantsPromQLHint = "This connection is victoriametrics: send promql, labels, labelValues or series"
	queryWantsLogsQLHint = "This connection is victorialogs: send logsql or a log discovery input"
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
	inputs := 0
	strict := strictJSON(body, &input)
	for _, set := range []bool{input.SQL != "", input.PromQL != "", input.Labels,
		input.LabelValues != "", input.Series != "", input.LogsQL != "", input.FieldNames,
		input.FieldValues != "", input.Streams, input.StreamFieldNames, input.StreamFieldValues != ""} {
		if set {
			inputs++
		}
	}
	logs := input.LogsQL != "" || input.FieldNames || input.FieldValues != "" ||
		input.Streams || input.StreamFieldNames || input.StreamFieldValues != ""
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" ||
		!strict || !auth.ValidConnectionRef(input.Connection) || inputs != 1 ||
		len(input.SQL)+len(input.PromQL) > auth.MaxSQLBytes || input.MaxRows < 0 {
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
	// The input must fit the connection's provider, exactly as the service
	// decides it on the record.
	if connection.Provider == auth.ProviderVictoriaLogs {
		if !logs {
			failWith(&auth.Error{Code: auth.InvalidArgument, Hint: queryWantsLogsQLHint})
			return
		}
		_ = json.NewEncoder(w).Encode(f.queryResponse)
		return
	}
	if connection.Provider == auth.ProviderVictoriaMetrics {
		if input.SQL != "" || logs {
			failWith(&auth.Error{Code: auth.InvalidArgument, Hint: queryWantsPromQLHint})
			return
		}
		_ = json.NewEncoder(w).Encode(f.queryResponse)
		return
	}
	if input.SQL == "" {
		failWith(&auth.Error{Code: auth.InvalidArgument, Hint: queryWantsSQLHint})
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
		Provider: auth.ProviderPostgreSQL,
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
	logs := testConnection("logs-prod")
	logs.ID, logs.Name, logs.Provider = testUserID(), "logs-prod", auth.ProviderVictoriaLogs
	fixture.connections = append(fixture.connections, granted, disabled, metrics, logs)
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
		"source-error": {failureWithSource(auth.SourceError, "The source rejected the query", querySourceHint,
			&auth.SourceFailure{SQLState: "42601", Message: `syntax error at or near "selec"`,
				Detail: "the parser stopped here", Hint: "check the spelling", Position: 1, Statement: auth.StatementIndex(0)}),
			"SOURCE_ERROR: The source rejected the query\nHint: " + querySourceHint + "\n" +
				"ERROR: 42601 syntax error at or near \"selec\"\n" +
				"DETAIL: the parser stopped here\nHINT: check the spelling\nPosition: 1\nStatement: 0\n"},
		"source-minimal": {failureWithSource(auth.SourceError, "The source rejected the query", "",
			&auth.SourceFailure{SQLState: "42703", Message: "column x does not exist", Statement: auth.StatementIndex(1)}),
			"SOURCE_ERROR: The source rejected the query\nERROR: 42703 column x does not exist\nStatement: 1\n"},
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
		{"no input", []string{"query", "--connection", "payments-prod-reporting"}, queryInputHint},
		{"two inputs", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--sql-file", path}, queryInputHint},
		{"stdin and inline", []string{"query", "--connection", "payments-prod-reporting", "--sql", "select 1", "--sql-stdin"}, queryInputHint},
		{"relative file", []string{"query", "--connection", "payments-prod-reporting", "--sql-file", "script.sql"}, queryInputHint},
		{"missing file", []string{"query", "--connection", "payments-prod-reporting", "--sql-file", filepath.Join(t.TempDir(), "absent.sql")}, queryInputHint},
		{"directory", []string{"query", "--connection", "payments-prod-reporting", "--sql-file", t.TempDir()}, queryInputHint},
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
		{&auth.Error{Code: auth.ProviderUnsupported, Hint: queryUnsupportedHint}, false},
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
	require.Equal(t, "SOURCE_ERROR: The source rejected the query\nHint: "+querySourceHint+"\n"+
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
	valid := `{"provider":"postgresql","results":[{"command":"SELECT","columns":[{"name":"id","type":"int8"}],` +
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

	large := `{"provider":"postgresql","results":[{"command":"SELECT","columns":[{"name":"v","type":"text"}],"rows":[["` +
		strings.Repeat("x", auth.MaxResponseBody*2) + `"]],"rowCount":1,"truncated":false}],` +
		`"truncated":false,"durationMs":4}`
	server := hostileQuery(t, http.StatusOK, "application/json", large)
	var response auth.QueryResponse
	require.Nil(t, sendQuery(t, server, &response))
	require.Len(t, *response.Results[0].Rows[0][0], auth.MaxResponseBody*2)

	oversized := `{"provider":"postgresql","results":[{"command":"SELECT","columns":[{"name":"v","type":"text"}],"rows":[["` +
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
	server := hostileQuery(t, http.StatusOK, "application/json", `{"provider":"postgresql","results":[],"truncated":false,"durationMs":1}`)
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

// metricsRows is the other documented document: the source's own vector under
// the provider that named it, with the source's warning beside it.
func metricsRows() auth.QueryResponse {
	return auth.QueryResponse{
		Provider:   auth.ProviderVictoriaMetrics,
		ResultType: "vector",
		Result: json.RawMessage(`[{"metric":{"__name__":"up","job":"api","instance":"a:9090"},"value":[1700000000,"1"]},` +
			`{"metric":{"__name__":"up","job":"db"},"value":[1700000001,"0"]}]`),
		Warnings:   []string{"the range is long"},
		DurationMS: 9,
	}
}

func metricsAnswer(resultType, result string) auth.QueryResponse {
	return auth.QueryResponse{Provider: auth.ProviderVictoriaMetrics, ResultType: resultType,
		Result: json.RawMessage(result), DurationMS: 9}
}

func metricsFixture(t *testing.T) (*cliAuthFixture, *httptest.Server) {
	t.Helper()
	fixture, server := queryFixture(t)
	fixture.mu.Lock()
	fixture.queryResponse = metricsRows()
	fixture.mu.Unlock()
	return fixture, server
}

// Every metrics input is sent as one request carrying only the fields that
// were given: the expression, the times, the step and the selectors travel
// exactly as typed, because the source parses them and the platform does not.
func TestQueryMetricsInputsAreSentAsTyped(t *testing.T) {
	for name, tc := range map[string]struct {
		args    []string
		request auth.QueryRequest
	}{
		"instant": {[]string{"--promql", "up"}, auth.QueryRequest{PromQL: "up"}},
		"pinned instant": {[]string{"--promql", "up", "--at", "2026-09-13T00:00:00Z"},
			auth.QueryRequest{PromQL: "up", At: "2026-09-13T00:00:00Z"}},
		"range": {[]string{"--promql", "rate(errors_total[5m])", "--start", "-1h", "--step", "1m"},
			auth.QueryRequest{PromQL: "rate(errors_total[5m])", Start: "-1h", Step: "1m"}},
		"bounded range": {[]string{"--promql", "up", "--start", "-1h", "--end", "now", "--step", "1m", "--max-rows", "10"},
			auth.QueryRequest{PromQL: "up", Start: "-1h", End: "now", Step: "1m", MaxRows: 10}},
		"labels": {[]string{"--labels", "--match", `{job="api"}`},
			auth.QueryRequest{Labels: true, Match: `{job="api"}`}},
		"label values": {[]string{"--label-values", "__name__", "--start", "-1h", "--end", "now"},
			auth.QueryRequest{LabelValues: "__name__", Start: "-1h", End: "now"}},
		"series": {[]string{"--series", `{__name__=~"up"}`, "--match", `{job="api"}`},
			auth.QueryRequest{Series: `{__name__=~"up"}`, Match: `{job="api"}`}},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, server := metricsFixture(t)
			exit, result, _ := queryRun(t, server, append([]string{"query", "--connection", "metrics-prod"}, tc.args...)...)
			require.Equal(t, 0, exit, "%+v", result.Error)
			tc.request.Connection = "metrics-prod"
			expected, err := json.Marshal(tc.request)
			require.NoError(t, err)
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			require.Equal(t, string(expected), string(fixture.queryBody))
		})
	}
}

// The expression inputs take the same three channels the SQL inputs take, and
// the expression is bounded on all of them before anything is sent.
func TestQueryReadsPromQLFromEveryChannel(t *testing.T) {
	fixture, server := metricsFixture(t)
	expression := "sum(rate(http_requests_total[5m])) by (job)"
	exit, output := queryText(t, server, expression, "query", "--connection", "metrics-prod", "--promql-stdin")
	require.Equal(t, 0, exit, output)
	fixture.mu.Lock()
	var sent auth.QueryRequest
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	fixture.mu.Unlock()
	require.Equal(t, expression, sent.PromQL)
	require.Empty(t, sent.SQL)

	path := filepath.Join(t.TempDir(), "expression.promql")
	require.NoError(t, os.WriteFile(path, []byte(expression), 0o644))
	exit, result, _ := queryRun(t, server, "query", "--connection", "metrics-prod", "--promql-file", path)
	require.Equal(t, 0, exit, "%+v", result.Error)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	require.Equal(t, expression, sent.PromQL)
}

// The metrics document reaches the caller as the source rendered it: the
// provider names the shape and the result is passed through unchanged.
func TestQueryMetricsDocumentAsJSON(t *testing.T) {
	_, server := metricsFixture(t)
	exit, result, _ := queryRun(t, server, "query", "--connection", "metrics-prod", "--promql", "up")
	require.Equal(t, 0, exit, "%+v", result.Error)
	document := result.Data.(map[string]any)
	require.Equal(t, "victoriametrics", document["provider"])
	require.Equal(t, "vector", document["resultType"])
	require.Equal(t, []any{"the range is long"}, document["warnings"])
	samples := document["result"].([]any)
	require.Len(t, samples, 2)
	require.Equal(t, map[string]any{"__name__": "up", "job": "api", "instance": "a:9090"},
		samples[0].(map[string]any)["metric"])
	require.Equal(t, []any{float64(1700000000), "1"}, samples[0].(map[string]any)["value"])
	require.Nil(t, document["results"], "a metrics answer carries no results list")
}

// The text rendering is the agent-facing one: the source's warnings first,
// then one line per sample with sorted labels, a block per matrix series, one
// line per discovery item, and the platform's own notices last.
func TestQueryMetricsTextRendering(t *testing.T) {
	partial := metricsRows()
	partial.Truncated, partial.IsPartial = true, true
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"vector": {success(metricsRows()),
			"Warning: the range is long\n" +
				"up{instance=\"a:9090\",job=\"api\"} 1 @1700000000\n" +
				"up{job=\"db\"} 0 @1700000001\n" +
				"Duration: 9 ms\n"},
		"truncated vector": {success(partial),
			"Warning: the range is long\n" +
				"up{instance=\"a:9090\",job=\"api\"} 1 @1700000000\n" +
				"up{job=\"db\"} 0 @1700000001\n" +
				"Truncated: true\nPartial: true\nDuration: 9 ms\n"},
		"matrix": {success(metricsAnswer("matrix",
			`[{"metric":{"__name__":"up","job":"api"},"values":[[1700000000,"1"],[1700000060,"2"]]},`+
				`{"metric":{},"values":[]}]`)),
			"up{job=\"api\"}\n1700000000 1\n1700000060 2\n{}\nDuration: 9 ms\n"},
		"scalar":  {success(metricsAnswer("scalar", `[1700000000,"42"]`)), "42 @1700000000\nDuration: 9 ms\n"},
		"string":  {success(metricsAnswer("string", `[1700000000,"hello"]`)), "hello @1700000000\nDuration: 9 ms\n"},
		"labels":  {success(metricsAnswer("labels", `["__name__","job"]`)), "__name__\njob\nDuration: 9 ms\n"},
		"metrics": {success(metricsAnswer("labelValues", `["up","go_info"]`)), "up\ngo_info\nDuration: 9 ms\n"},
		"series": {success(metricsAnswer("series", `[{"__name__":"up","job":"api"},{"job":"db"}]`)),
			"up{job=\"api\"}\n{job=\"db\"}\nDuration: 9 ms\n"},
		"promql-error": {failureWithSource(auth.SourceError, "The source rejected the query", querySourceHint,
			&auth.SourceFailure{ErrorType: "bad_data", Message: `unsupported expression`}),
			"SOURCE_ERROR: The source rejected the query\nHint: " + querySourceHint + "\n" +
				"ERROR: bad_data unsupported expression\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, render(&out, tc.result, "text"))
			require.Equal(t, tc.want, out.String())
		})
	}
}

// A discovery listing as text is one item per line, and the truncation notice
// appears only when the server reported it.
func TestQueryMetricNamesAsText(t *testing.T) {
	fixture, server := metricsFixture(t)
	fixture.mu.Lock()
	fixture.queryResponse = metricsAnswer("labelValues", `["up","go_info"]`)
	fixture.mu.Unlock()
	exit, output := queryText(t, server, "", "query", "--connection", "metrics-prod", "--label-values", "__name__")
	require.Equal(t, 0, exit, output)
	require.Equal(t, "up\ngo_info\nDuration: 9 ms\n", output)

	truncated := metricsAnswer("labelValues", `["up"]`)
	truncated.Truncated = true
	fixture.mu.Lock()
	fixture.queryResponse = truncated
	fixture.mu.Unlock()
	exit, output = queryText(t, server, "", "query", "--connection", "metrics-prod", "--label-values", "__name__")
	require.Equal(t, 0, exit, output)
	require.Equal(t, "up\nTruncated: true\nDuration: 9 ms\n", output)
}

// A PromQL failure prints the source's own classification and message, with no
// position and no statement line, and never repeats the expression.
func TestQueryPromQLSourceErrorAsText(t *testing.T) {
	fixture, server := metricsFixture(t)
	fixture.mu.Lock()
	fixture.queryFailure = &auth.Error{Code: auth.SourceError, Hint: querySourceHint,
		Source: &auth.SourceFailure{ErrorType: "bad_data", Message: "cannot parse the expression"}}
	fixture.mu.Unlock()
	exit, output := queryText(t, server, "", "query", "--connection", "metrics-prod", "--promql", "up ~~ sentinel")
	require.Equal(t, 1, exit)
	require.Equal(t, "SOURCE_ERROR: The source rejected the query\nHint: "+querySourceHint+"\n"+
		"ERROR: bad_data cannot parse the expression\n", output)
	require.NotContains(t, output, "sentinel")
}

// A mismatch the server decides on the record passes through as the invalid
// argument it is, with the hint naming the input that connection takes.
func TestQueryProviderMismatchPassesThrough(t *testing.T) {
	_, server := metricsFixture(t)
	exit, result, output := queryRun(t, server, "query", "--connection", "metrics-prod", "--sql", "select 1")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, queryWantsPromQLHint, result.Error.Hint)
	require.NotContains(t, output, "select 1")

	fixture, server := queryFixture(t)
	fixture.mu.Lock()
	fixture.queryResponse = queryRows()
	fixture.mu.Unlock()
	exit, result, _ = queryRun(t, server, "query", "--connection", "payments-prod-reporting", "--promql", "up")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, queryWantsSQLHint, result.Error.Hint)
}

// Every metrics argument rule is decided locally, exits 2 and reaches no
// request at all.
func TestQueryMetricsArgumentsRejectedBeforeIO(t *testing.T) {
	fixture, server := metricsFixture(t)
	fixture.mu.Lock()
	before := fixture.queryCalls
	fixture.mu.Unlock()
	for _, tc := range []struct {
		name string
		args []string
		hint string
	}{
		{"two inputs", []string{"--promql", "up", "--labels"}, queryInputHint},
		{"expression and sql", []string{"--sql", "select 1", "--promql", "up"}, queryInputHint},
		{"two expression channels", []string{"--promql", "up", "--promql-stdin"}, queryInputHint},
		{"two discovery inputs", []string{"--labels", "--series", "up"}, queryInputHint},
		{"relative expression file", []string{"--promql-file", "expression.promql"}, queryInputHint},
		{"empty expression", []string{"--promql", ""}, sqlBoundHint},
		{"oversized expression", []string{"--promql", strings.Repeat("u", auth.MaxSQLBytes+1)}, sqlBoundHint},
		{"oversized selector", []string{"--series", strings.Repeat("u", auth.MaxSQLBytes+1)}, sqlBoundHint},
		{"oversized match", []string{"--labels", "--match", strings.Repeat("u", auth.MaxSQLBytes+1)}, sqlBoundHint},
		{"at with start", []string{"--promql", "up", "--at", "now", "--start", "-1h"}, queryTimeHint},
		{"at with discovery", []string{"--labels", "--at", "now"}, queryTimeHint},
		{"at with sql", []string{"--sql", "select 1", "--at", "now"}, queryTimeHint},
		{"step without start", []string{"--promql", "up", "--step", "1m"}, queryTimeHint},
		{"step on discovery", []string{"--labels", "--start", "-1h", "--step", "1m"}, queryTimeHint},
		{"match with promql", []string{"--promql", "up", "--match", "up"}, queryTimeHint},
		{"end without start", []string{"--promql", "up", "--end", "now"}, queryTimeHint},
		{"start with sql", []string{"--sql", "select 1", "--start", "-1h"}, queryTimeHint},
		{"end with sql", []string{"--sql", "select 1", "--end", "now"}, queryTimeHint},
		{"match with sql", []string{"--sql", "select 1", "--match", "up"}, queryTimeHint},
		{"invalid label name", []string{"--label-values", "9metric"}, queryLabelHint},
		{"pathy label name", []string{"--label-values", "../admin"}, queryLabelHint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, result, output := queryRun(t, server,
				append([]string{"query", "--connection", "metrics-prod"}, tc.args...)...)
			require.Equal(t, 2, exit)
			require.Equal(t, auth.InvalidArgument, result.Error.Code)
			require.Equal(t, tc.hint, result.Error.Hint)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.queryCalls, "no request may be made")
}

// A metrics document that is not the documented shape is refused rather than
// rendered, and neither provider's document may carry the other's members.
func TestQueryMetricsTransportStrictResponses(t *testing.T) {
	valid := `{"provider":"victoriametrics","resultType":"vector",` +
		`"result":[{"metric":{"job":"a"},"value":[1,"1"]}],"truncated":false,"durationMs":4}`
	for name, tc := range map[string]struct {
		body  string
		valid bool
	}{
		"vector":  {valid, true},
		"partial": {strings.Replace(valid, `"truncated":false`, `"isPartial":true,"truncated":false`, 1), true},
		"warned":  {strings.Replace(valid, `"truncated":false`, `"warnings":["long range"],"truncated":false`, 1), true},
		"matrix": {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`,
			`"matrix","result":[{"metric":{"job":"a"},"values":[[1,"1"]],"truncated":true}]`, 1), true},
		"empty matrix series": {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`,
			`"matrix","result":[{"metric":{"job":"a"},"values":[],"truncated":true}]`, 1), true},
		"source member":  {strings.Replace(valid, `"value":[1,"1"]`, `"value":[1,"1"],"histogram":{}`, 1), true},
		"scalar":         {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`, `"scalar","result":[1,"1"]`, 1), true},
		"string":         {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`, `"string","result":[1,"text"]`, 1), true},
		"labels":         {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`, `"labels","result":["job"]`, 1), true},
		"empty labels":   {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`, `"labelValues","result":[]`, 1), true},
		"series":         {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`, `"series","result":[{"job":"a"}]`, 1), true},
		"unknown type":   {strings.Replace(valid, `"vector"`, `"histogram"`, 1), false},
		"missing type":   {strings.Replace(valid, `"resultType":"vector",`, ``, 1), false},
		"missing result": {strings.Replace(valid, `"result":[{"metric":{"job":"a"},"value":[1,"1"]}],`, ``, 1), false},
		"null result":    {strings.Replace(valid, `[{"metric":{"job":"a"},"value":[1,"1"]}]`, `null`, 1), false},
		"vector samples": {strings.Replace(valid, `"value":[1,"1"]`, `"values":[[1,"1"]]`, 1), false},
		"matrix sample": {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`,
			`"matrix","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`, 1), false},
		"missing metric":   {strings.Replace(valid, `"metric":{"job":"a"},`, ``, 1), false},
		"numeric label":    {strings.Replace(valid, `{"job":"a"}`, `{"job":1}`, 1), false},
		"numeric value":    {strings.Replace(valid, `[1,"1"]`, `[1,1]`, 1), false},
		"quoted timestamp": {strings.Replace(valid, `[1,"1"]`, `["1","1"]`, 1), false},
		"long sample":      {strings.Replace(valid, `[1,"1"]`, `[1,"1",true]`, 1), false},
		"short sample":     {strings.Replace(valid, `[1,"1"]`, `[1]`, 1), false},
		"labels of numbers": {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`,
			`"labels","result":[1]`, 1), false},
		"series of strings": {strings.Replace(valid, `"vector","result":[{"metric":{"job":"a"},"value":[1,"1"]}]`,
			`"series","result":["up"]`, 1), false},
		"control warning": {strings.Replace(valid, `"truncated":false`, "\"warnings\":[\"a\ab\"],\"truncated\":false", 1), false},
		"results list":    {strings.Replace(valid, `"truncated":false`, `"results":[],"truncated":false`, 1), false},
		"no provider":     {strings.Replace(valid, `"provider":"victoriametrics",`, ``, 1), false},
		"other provider":  {strings.Replace(valid, `"victoriametrics"`, `"mysql"`, 1), false},
		"metrics members on a SQL answer": {`{"provider":"postgresql","results":[],"resultType":"vector",` +
			`"result":[],"truncated":false,"durationMs":4}`, false},
		"partial on a SQL answer": {`{"provider":"postgresql","results":[],"isPartial":true,"truncated":false,"durationMs":4}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			server := hostileQuery(t, http.StatusOK, "application/json", tc.body)
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			if tc.valid {
				require.Nil(t, failed)
				require.Equal(t, auth.ProviderVictoriaMetrics, response.Provider)
				return
			}
			require.NotNil(t, failed)
			require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
		})
	}
}

// A metrics source classifies its own failure; a block carrying both words, or
// one carrying an unrenderable classification, is not the documented shape.
func TestQueryMetricsSourceBlockIsStrict(t *testing.T) {
	envelope := func(source string) string {
		_, safe, _ := auth.LookupFailure(auth.SourceError)
		return `{"error":{"code":"` + safe.Code + `","message":"` + safe.Message + `","source":` + source + `}}`
	}
	for name, tc := range map[string]struct {
		source string
		valid  bool
	}{
		"errorType":          {`{"errorType":"bad_data","message":"cannot parse"}`, true},
		"http status":        {`{"errorType":"http_500","message":"cannot parse"}`, true},
		"both words":         {`{"errorType":"bad_data","sqlstate":"42601","message":"cannot parse"}`, false},
		"control errorType":  {"{\"errorType\":\"a\ab\",\"message\":\"cannot parse\"}", false},
		"no message":         {`{"errorType":"bad_data"}`, false},
		"statement absent":   {`{"errorType":"bad_data","message":"cannot parse"}`, true},
		"statement provided": {`{"errorType":"bad_data","message":"cannot parse","statement":0}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			status, _, _ := auth.LookupFailure(auth.SourceError)
			server := hostileQuery(t, status, "application/json", envelope(tc.source))
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			require.NotNil(t, failed)
			if !tc.valid {
				require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
				return
			}
			require.Equal(t, auth.SourceError, failed.Error.Code)
			require.NotNil(t, failed.Error.Source)
			require.Equal(t, "cannot parse", failed.Error.Source.Message)
		})
	}
}

// logsRows is the third documented document: the source's own rows under the
// provider that named them, with every field and value type as it wrote them.
func logsRows() auth.QueryResponse {
	return auth.QueryResponse{
		Provider:   auth.ProviderVictoriaLogs,
		ResultType: "logs",
		Result: json.RawMessage(`[{"_time":"2026-09-14T10:00:00Z","_msg":"boom","level":"error",` +
			`"_stream":"{job=\"api\"}"},{"_time":"2026-09-14T10:00:01Z","_msg":"again","level":"warn"}]`),
		DurationMS: 12,
	}
}

func logsAnswer(resultType, result string) auth.QueryResponse {
	return auth.QueryResponse{Provider: auth.ProviderVictoriaLogs, ResultType: resultType,
		Result: json.RawMessage(result), DurationMS: 12}
}

func logsFixture(t *testing.T) (*cliAuthFixture, *httptest.Server) {
	t.Helper()
	fixture, server := queryFixture(t)
	fixture.mu.Lock()
	fixture.queryResponse = logsRows()
	fixture.mu.Unlock()
	return fixture, server
}

// Every log input is sent as one request carrying only the fields that were
// given: the query, the times, the match, the filter and the caller's own limit
// travel exactly as typed, and a limit that was not given is absent altogether
// because the platform never adds one.
func TestQueryLogInputsAreSentAsTyped(t *testing.T) {
	zero, five, fifty := int64(0), int64(5), int64(50)
	for name, tc := range map[string]struct {
		args    []string
		request auth.QueryRequest
	}{
		"logsql": {[]string{"--logsql", "error | sort by (_time) desc"},
			auth.QueryRequest{LogsQL: "error | sort by (_time) desc"}},
		"bounded": {[]string{"--logsql", "error", "--start", "-1h", "--end", "now", "--limit", "50"},
			auth.QueryRequest{LogsQL: "error", Start: "-1h", End: "now", Limit: &fifty}},
		"explicit zero": {[]string{"--logsql", "error", "--limit", "0"},
			auth.QueryRequest{LogsQL: "error", Limit: &zero}},
		"field names": {[]string{"--field-names", "--match", "*", "--filter", "err"},
			auth.QueryRequest{FieldNames: true, Match: "*", Filter: "err"}},
		"field values": {[]string{"--field-values", "level", "--match", "*", "--limit", "5", "--max-rows", "10"},
			auth.QueryRequest{FieldValues: "level", Match: "*", Limit: &five, MaxRows: 10}},
		"streams": {[]string{"--streams", "--match", `{job="api"}`, "--limit", "50"},
			auth.QueryRequest{Streams: true, Match: `{job="api"}`, Limit: &fifty}},
		"stream field names": {[]string{"--stream-field-names", "--match", "*", "--filter", "j"},
			auth.QueryRequest{StreamFieldNames: true, Match: "*", Filter: "j"}},
		"stream field values": {[]string{"--stream-field-values", "job", "--match", "*", "--filter", "api"},
			auth.QueryRequest{StreamFieldValues: "job", Match: "*", Filter: "api"}},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, server := logsFixture(t)
			exit, result, _ := queryRun(t, server, append([]string{"query", "--connection", "logs-prod"}, tc.args...)...)
			require.Equal(t, 0, exit, "%+v", result.Error)
			tc.request.Connection = "logs-prod"
			expected, err := json.Marshal(tc.request)
			require.NoError(t, err)
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			require.Equal(t, string(expected), string(fixture.queryBody))
		})
	}
	// A query without --limit carries no limit at all: absent and zero are two
	// different requests, and the CLI invents neither.
	fixture, server := logsFixture(t)
	exit, result, _ := queryRun(t, server, "query", "--connection", "logs-prod", "--logsql", "error")
	require.Equal(t, 0, exit, "%+v", result.Error)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.NotContains(t, string(fixture.queryBody), "limit")
}

// The LogsQL input takes the same three channels the SQL and PromQL inputs
// take, and the query is bounded on all of them before anything is sent.
func TestQueryReadsLogsQLFromEveryChannel(t *testing.T) {
	fixture, server := logsFixture(t)
	query := "error | stats by (level) count() as n"
	exit, output := queryText(t, server, query, "query", "--connection", "logs-prod", "--logsql-stdin")
	require.Equal(t, 0, exit, output)
	fixture.mu.Lock()
	var sent auth.QueryRequest
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	fixture.mu.Unlock()
	require.Equal(t, query, sent.LogsQL)
	require.Empty(t, sent.SQL)
	require.Empty(t, sent.PromQL)

	path := filepath.Join(t.TempDir(), "query.logsql")
	require.NoError(t, os.WriteFile(path, []byte(query), 0o644))
	exit, result, _ := queryRun(t, server, "query", "--connection", "logs-prod", "--logsql-file", path)
	require.Equal(t, 0, exit, "%+v", result.Error)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.NoError(t, json.Unmarshal(fixture.queryBody, &sent))
	require.Equal(t, query, sent.LogsQL)
}

// The log document reaches the caller as the source wrote it: the provider
// names the shape and the rows pass through with their own fields.
func TestQueryLogDocumentAsJSON(t *testing.T) {
	_, server := logsFixture(t)
	exit, result, _ := queryRun(t, server, "query", "--connection", "logs-prod", "--logsql", "error", "--limit", "20")
	require.Equal(t, 0, exit, "%+v", result.Error)
	document := result.Data.(map[string]any)
	require.Equal(t, "victorialogs", document["provider"])
	require.Equal(t, "logs", document["resultType"])
	rows := document["result"].([]any)
	require.Len(t, rows, 2)
	require.Equal(t, map[string]any{"_time": "2026-09-14T10:00:00Z", "_msg": "boom",
		"level": "error", "_stream": `{job="api"}`}, rows[0])
	require.Nil(t, document["results"], "a log answer carries no results list")
	require.Nil(t, document["warnings"], "a log source writes no warnings")
}

// The text rendering is the agent-facing one: one physical line per row, the
// time first, the message after it, the remaining fields sorted and the stream
// fields last, with Go quoting wherever a bare value would be ambiguous.
func TestQueryLogTextRendering(t *testing.T) {
	truncated := logsRows()
	truncated.Truncated = true
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"rows": {success(logsRows()),
			"2026-09-14T10:00:00Z boom level=error _stream=\"{job=\\\"api\\\"}\"\n" +
				"2026-09-14T10:00:01Z again level=warn\n" +
				"Duration: 12 ms\n"},
		"truncated": {success(truncated),
			"2026-09-14T10:00:00Z boom level=error _stream=\"{job=\\\"api\\\"}\"\n" +
				"2026-09-14T10:00:01Z again level=warn\n" +
				"Truncated: true\nDuration: 12 ms\n"},
		// A message spanning two lines stays one physical line, quoted.
		"multiline message": {success(logsAnswer("logs",
			`[{"_time":"2026-09-14T10:00:00Z","_msg":"line one\nline two","_stream_id":"0000"}]`)),
			"2026-09-14T10:00:00Z \"line one\\nline two\" _stream_id=0000\nDuration: 12 ms\n"},
		// A value carrying the separator, an empty one and a name with a space
		// are each quoted, so the line stays readable as pairs.
		"quoted values": {success(logsAnswer("logs",
			`[{"_time":"t","expr":"a=b","empty":"","two words":"x"}]`)),
			"t empty=\"\" expr=\"a=b\" \"two words\"=x\nDuration: 12 ms\n"},
		// A value the source did not write as a string is printed as the JSON
		// it wrote, so a count stays a count and an object stays an object.
		"typed values": {success(logsAnswer("logs",
			`[{"_time":"t","n":12,"ok":true,"nested":{"a":1},"none":null}]`)),
			"t n=12 nested=\"{\\\"a\\\":1}\" none=null ok=true\nDuration: 12 ms\n"},
		// An aggregate row has neither time nor message and prints as pairs.
		"aggregate": {success(logsAnswer("logs", `[{"level":"error","n":12}]`)),
			"level=error n=12\nDuration: 12 ms\n"},
		"empty": {success(logsAnswer("logs", `[]`)), "Duration: 12 ms\n"},
		// Discovery is the source's value and its own hit count, one per line.
		"field names": {success(logsAnswer("fieldNames",
			`[{"value":"level","hits":12},{"value":"_msg","hits":300}]`)),
			"level\t12\n_msg\t300\nDuration: 12 ms\n"},
		"field values": {success(logsAnswer("fieldValues",
			`[{"value":"","hits":0},{"value":"a b","hits":9007199254740993}]`)),
			"\"\"\t0\n\"a b\"\t9007199254740993\nDuration: 12 ms\n"},
		"logsql-error": {failureWithSource(auth.SourceError, "The source rejected the query", querySourceHint,
			&auth.SourceFailure{ErrorType: "http_400", Message: "cannot parse the query"}),
			"SOURCE_ERROR: The source rejected the query\nHint: " + querySourceHint + "\n" +
				"ERROR: http_400 cannot parse the query\n"},
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

// The rendering reaches the caller through the command as well: a two-line
// message stays one line and the truncation notice appears only when the
// server reported it.
func TestQueryLogRowsAsText(t *testing.T) {
	fixture, server := logsFixture(t)
	answer := logsAnswer("logs", `[{"_time":"2026-09-14T10:00:00Z","_msg":"line one\nline two",`+
		`"level":"error","_stream":"{job=\"api\"}"}]`)
	answer.Truncated = true
	fixture.mu.Lock()
	fixture.queryResponse = answer
	fixture.mu.Unlock()
	exit, output := queryText(t, server, "", "query", "--connection", "logs-prod", "--logsql", "error")
	require.Equal(t, 0, exit, output)
	require.Equal(t, "2026-09-14T10:00:00Z \"line one\\nline two\" level=error "+
		"_stream=\"{job=\\\"api\\\"}\"\nTruncated: true\nDuration: 12 ms\n", output)
	require.Len(t, strings.Split(strings.TrimSuffix(output, "\n"), "\n"), 3,
		"the row, the notice and the duration are three physical lines")
}

// Discovery as text is the source's value and its hit count per line, and the
// command exits 0 with the notice only when the server reported truncation.
func TestQueryLogDiscoveryAsText(t *testing.T) {
	fixture, server := logsFixture(t)
	fixture.mu.Lock()
	fixture.queryResponse = logsAnswer("fieldValues", `[{"value":"error","hits":12},{"value":"warn","hits":3}]`)
	fixture.mu.Unlock()
	exit, output := queryText(t, server, "", "query", "--connection", "logs-prod",
		"--field-values", "level", "--match", "*")
	require.Equal(t, 0, exit, output)
	require.Equal(t, "error\t12\nwarn\t3\nDuration: 12 ms\n", output)
}

// A LogsQL failure prints the status the platform named and the source's own
// text, with no position and no statement line, and never repeats the query.
func TestQueryLogsQLSourceErrorAsText(t *testing.T) {
	fixture, server := logsFixture(t)
	fixture.mu.Lock()
	fixture.queryFailure = &auth.Error{Code: auth.SourceError, Hint: querySourceHint,
		Source: &auth.SourceFailure{ErrorType: "http_400", Message: "cannot parse the query"}}
	fixture.mu.Unlock()
	exit, output := queryText(t, server, "", "query", "--connection", "logs-prod", "--logsql", "error ~~ sentinel")
	require.Equal(t, 1, exit)
	require.Equal(t, "SOURCE_ERROR: The source rejected the query\nHint: "+querySourceHint+"\n"+
		"ERROR: http_400 cannot parse the query\n", output)
	require.NotContains(t, output, "sentinel")
}

// A mismatch the server decides on the record passes through both ways, with
// the hint naming the input that connection takes.
func TestQueryLogProviderMismatchPassesThrough(t *testing.T) {
	_, server := logsFixture(t)
	exit, result, output := queryRun(t, server, "query", "--connection", "logs-prod", "--sql", "select 1")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, queryWantsLogsQLHint, result.Error.Hint)
	require.NotContains(t, output, "select 1")

	exit, result, _ = queryRun(t, server, "query", "--connection", "payments-prod-reporting", "--logsql", "error")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, queryWantsSQLHint, result.Error.Hint)

	exit, result, _ = queryRun(t, server, "query", "--connection", "metrics-prod", "--logsql", "error")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, queryWantsPromQLHint, result.Error.Hint)
}

// Every log argument rule is decided locally, exits 2 and reaches no request.
func TestQueryLogArgumentsRejectedBeforeIO(t *testing.T) {
	fixture, server := logsFixture(t)
	fixture.mu.Lock()
	before := fixture.queryCalls
	fixture.mu.Unlock()
	for _, tc := range []struct {
		name string
		args []string
		hint string
	}{
		{"two log inputs", []string{"--logsql", "error", "--streams", "--match", "*"}, queryInputHint},
		{"two discovery inputs", []string{"--field-names", "--streams", "--match", "*"}, queryInputHint},
		{"log and sql", []string{"--sql", "select 1", "--logsql", "error"}, queryInputHint},
		{"log and promql", []string{"--promql", "up", "--logsql", "error"}, queryInputHint},
		{"two query channels", []string{"--logsql", "error", "--logsql-stdin"}, queryInputHint},
		{"relative query file", []string{"--logsql-file", "query.logsql"}, queryInputHint},
		{"empty query", []string{"--logsql", ""}, sqlBoundHint},
		{"oversized query", []string{"--logsql", strings.Repeat("e", auth.MaxSQLBytes+1)}, sqlBoundHint},
		{"oversized field name", []string{"--field-values", strings.Repeat("f", auth.MaxSQLBytes+1), "--match", "*"}, sqlBoundHint},
		{"oversized match", []string{"--field-names", "--match", strings.Repeat("m", auth.MaxSQLBytes+1)}, sqlBoundHint},
		{"discovery without match", []string{"--field-values", "level"}, queryMatchHint},
		{"streams without match", []string{"--streams"}, queryMatchHint},
		{"field names without match", []string{"--field-names"}, queryMatchHint},
		{"stream field names without match", []string{"--stream-field-names"}, queryMatchHint},
		{"stream field values without match", []string{"--stream-field-values", "job"}, queryMatchHint},
		{"match with logsql", []string{"--logsql", "error", "--match", "*"}, queryMatchHint},
		{"limit on field names", []string{"--field-names", "--match", "*", "--limit", "5"}, queryLimitHint},
		{"limit on stream field names", []string{"--stream-field-names", "--match", "*", "--limit", "5"}, queryLimitHint},
		{"limit on sql", []string{"--sql", "select 1", "--limit", "5"}, queryLimitHint},
		{"limit on promql", []string{"--promql", "up", "--limit", "5"}, queryLimitHint},
		{"negative limit", []string{"--logsql", "error", "--limit", "-1"}, queryLimitHint},
		{"filter on logsql", []string{"--logsql", "error", "--filter", "err"}, queryFilterHint},
		{"filter on streams", []string{"--streams", "--match", "*", "--filter", "err"}, queryFilterHint},
		{"filter on sql", []string{"--sql", "select 1", "--filter", "err"}, queryFilterHint},
		{"oversized filter", []string{"--field-names", "--match", "*",
			"--filter", strings.Repeat("f", auth.MaxFilterBytes+1)}, queryFilterHint},
		{"at with logsql", []string{"--logsql", "error", "--at", "now"}, queryTimeHint},
		{"step with logsql", []string{"--logsql", "error", "--start", "-1h", "--step", "1m"}, queryTimeHint},
		{"at with discovery", []string{"--field-names", "--match", "*", "--at", "now"}, queryTimeHint},
		{"step with discovery", []string{"--streams", "--match", "*", "--start", "-1h", "--step", "1m"}, queryTimeHint},
		{"non-numeric limit", []string{"--logsql", "error", "--limit", "abc"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, result, output := queryRun(t, server,
				append([]string{"query", "--connection", "logs-prod"}, tc.args...)...)
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

// A log document that is not the documented shape is refused rather than
// rendered, and no provider's document may carry another's members.
func TestQueryLogsTransportStrictResponses(t *testing.T) {
	valid := `{"provider":"victorialogs","resultType":"logs",` +
		`"result":[{"_time":"t","_msg":"m"}],"truncated":false,"durationMs":4}`
	discovery := func(body string) string {
		return strings.Replace(valid, `"logs","result":[{"_time":"t","_msg":"m"}]`, body, 1)
	}
	for name, tc := range map[string]struct {
		body  string
		valid bool
	}{
		"rows":                    {valid, true},
		"empty rows":              {strings.Replace(valid, `[{"_time":"t","_msg":"m"}]`, `[]`, 1), true},
		"any fields":              {strings.Replace(valid, `{"_time":"t","_msg":"m"}`, `{"level":"error","n":12,"ok":true,"o":{"a":1}}`, 1), true},
		"empty row":               {strings.Replace(valid, `{"_time":"t","_msg":"m"}`, `{}`, 1), true},
		"truncated rows":          {strings.Replace(valid, `"truncated":false`, `"truncated":true`, 1), true},
		"field names":             {discovery(`"fieldNames","result":[{"value":"level","hits":12}]`), true},
		"field values":            {discovery(`"fieldValues","result":[{"value":"","hits":0}]`), true},
		"streams":                 {discovery(`"streams","result":[{"value":"{job=\"api\"}","hits":3}]`), true},
		"stream fields":           {discovery(`"streamFieldNames","result":[]`), true},
		"stream values":           {discovery(`"streamFieldValues","result":[{"value":"api","hits":1}]`), true},
		"unknown type":            {strings.Replace(valid, `"logs"`, `"hits"`, 1), false},
		"metrics type":            {strings.Replace(valid, `"logs"`, `"vector"`, 1), false},
		"missing type":            {strings.Replace(valid, `"resultType":"logs",`, ``, 1), false},
		"missing result":          {strings.Replace(valid, `"result":[{"_time":"t","_msg":"m"}],`, ``, 1), false},
		"null result":             {strings.Replace(valid, `[{"_time":"t","_msg":"m"}]`, `null`, 1), false},
		"rows of strings":         {strings.Replace(valid, `[{"_time":"t","_msg":"m"}]`, `["line"]`, 1), false},
		"null row":                {strings.Replace(valid, `{"_time":"t","_msg":"m"}`, `null`, 1), false},
		"row not a list":          {strings.Replace(valid, `[{"_time":"t","_msg":"m"}]`, `{"_time":"t"}`, 1), false},
		"discovery without hits":  {discovery(`"fieldNames","result":[{"value":"level"}]`), false},
		"discovery without value": {discovery(`"fieldNames","result":[{"hits":1}]`), false},
		"quoted hits":             {discovery(`"fieldNames","result":[{"value":"level","hits":"12"}]`), false},
		"numeric value":           {discovery(`"fieldNames","result":[{"value":1,"hits":1}]`), false},
		"discovery of strings":    {discovery(`"fieldNames","result":["level"]`), false},
		"rows on discovery":       {discovery(`"fieldNames","result":[{"_time":"t"}]`), false},
		"warnings":                {strings.Replace(valid, `"truncated":false`, `"warnings":["long"],"truncated":false`, 1), false},
		"infos":                   {strings.Replace(valid, `"truncated":false`, `"infos":["note"],"truncated":false`, 1), false},
		"partial":                 {strings.Replace(valid, `"truncated":false`, `"isPartial":true,"truncated":false`, 1), false},
		"results list":            {strings.Replace(valid, `"truncated":false`, `"results":[],"truncated":false`, 1), false},
		"unknown member":          {strings.Replace(valid, `"durationMs":4`, `"durationMs":4,"extra":1`, 1), false},
		"no provider":             {strings.Replace(valid, `"provider":"victorialogs",`, ``, 1), false},
		"log members on a SQL answer": {`{"provider":"postgresql","results":[],"resultType":"logs",` +
			`"result":[],"truncated":false,"durationMs":4}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			server := hostileQuery(t, http.StatusOK, "application/json", tc.body)
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			if tc.valid {
				require.Nil(t, failed)
				require.Equal(t, auth.ProviderVictoriaLogs, response.Provider)
				return
			}
			require.NotNil(t, failed)
			require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
		})
	}
}

// A log source classifies nothing itself: the platform names the status, and a
// block carrying a SQLSTATE or a statement index is not the documented shape.
func TestQueryLogSourceBlockIsStrict(t *testing.T) {
	envelope := func(source string) string {
		_, safe, _ := auth.LookupFailure(auth.SourceError)
		return `{"error":{"code":"` + safe.Code + `","message":"` + safe.Message + `","source":` + source + `}}`
	}
	for name, tc := range map[string]struct {
		source  string
		message string
		valid   bool
	}{
		"http status":       {`{"errorType":"http_400","message":"cannot parse"}`, "cannot parse", true},
		"malformed":         {`{"errorType":"malformed_response","message":"no such field"}`, "no such field", true},
		"too large":         {`{"errorType":"response_too_large","message":"past the ceiling"}`, "past the ceiling", true},
		"with sqlstate":     {`{"errorType":"http_400","sqlstate":"42601","message":"cannot parse"}`, "", false},
		"with statement":    {`{"errorType":"http_400","message":"cannot parse","statement":0}`, "", false},
		"no classification": {`{"message":"cannot parse"}`, "cannot parse", true},
		"no message":        {`{"errorType":"http_400"}`, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			status, _, _ := auth.LookupFailure(auth.SourceError)
			server := hostileQuery(t, status, "application/json", envelope(tc.source))
			var response auth.QueryResponse
			failed := sendQuery(t, server, &response)
			require.NotNil(t, failed)
			if !tc.valid {
				require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
				return
			}
			require.Equal(t, auth.SourceError, failed.Error.Code)
			require.NotNil(t, failed.Error.Source)
			require.Equal(t, tc.message, failed.Error.Source.Message)
		})
	}
}
