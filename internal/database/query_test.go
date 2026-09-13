package database

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file is fixture setup, fault injection, or an independent
// assertion against persisted state. Application operations use LocalAuth.
//
// The test instance is both the platform database and the external source, as
// it is for the probe tests. The platform pool reaches its own random schema
// through search_path; an execution arrives on a fresh connection without it,
// so every table an execution touches is named with that schema explicitly.

// sentinelColumn is submitted inside the SQL. It may appear in the source's
// own rejection, which is the caller's own text coming back, and nowhere else.
const sentinelColumn = "sentinel_column_never_in_logs"

func currentSchema(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var schema string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema))
	return pgx.Identifier{schema}.Sanitize()
}

// queryConnection points a connection at the test instance itself: the same
// role and password, with the password stored only as the sealed secret.
func queryConnection(t *testing.T, s *LocalAuth, admin auth.Session, name string) auth.Connection {
	t.Helper()
	target, password := testDatabaseTarget(t)
	request := connectionRequest(name)
	request.Target, request.Secret = target, password
	return createConnection(t, s, admin, request)
}

// unreachableConnection points a connection at a port nothing listens on, so a
// request that reaches the source fails at once instead of spending a deadline.
func unreachableConnection(t *testing.T, s *LocalAuth, admin auth.Session, name string) auth.Connection {
	t.Helper()
	request := connectionRequest(name)
	request.Target = map[string]string{
		"url": "postgres://reader@" + closedPort(t) + "/ledger?sslmode=disable",
	}
	return createConnection(t, s, admin, request)
}

func grantConnection(t *testing.T, s *LocalAuth, admin auth.Session, user, connection string) {
	t.Helper()
	_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: user, Connection: connection}, false)
	require.NoError(t, err)
}

// queryError drops the response so a refusal reads as one expression.
func queryError(_ auth.QueryResponse, err error) error { return err }

// platformCounts is every row an execution must leave alone.
func platformCounts(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range []string{"users", "sessions", "connections", "grants"} {
		counts[table] = countRows(t, pool, table)
	}
	return counts
}

func sourceOf(t *testing.T, err error) auth.SourceFailure {
	t.Helper()
	_, response := auth.FailureFor(err)
	require.NotNil(t, response.Source)
	return *response.Source
}

func TestExecuteQueryRunsScriptsForAdministratorsAndGrantedMembers(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")
	schema := currentSchema(t, pool)
	member, memberInput := createMember(t, s, admin, "reporting-member")
	grantConnection(t, s, admin, member.ID, record.ID)
	memberSession := session(t, s, login(t, s, memberInput), auth.CLI)
	counts := platformCounts(t, pool)

	response, err := s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name,
		SQL: "create table " + schema + ".notes(id int primary key, body text);" +
			" insert into " + schema + ".notes values (1, 'first'), (2, null);",
	})
	require.NoError(t, err)
	require.Len(t, response.Results, 2, "the list shape is one entry per statement, in order")
	require.Equal(t, "CREATE", response.Results[0].Command)
	require.Empty(t, response.Results[0].Columns)
	require.Empty(t, response.Results[0].Rows)
	require.Equal(t, "INSERT", response.Results[1].Command)
	require.Equal(t, int64(2), response.Results[1].RowCount)
	require.False(t, response.Truncated)
	require.GreaterOrEqual(t, response.DurationMS, int64(0))

	// A granted member reaches the same connection by id, under the same
	// credentials, runs a script of their own and sees the rows the
	// administrator's script committed.
	response, err = s.ExecuteQuery(t.Context(), memberSession, auth.QueryRequest{
		Connection: record.ID,
		SQL:        "select count(*) from " + schema + ".notes; select id, body from " + schema + ".notes order by id;",
	})
	require.NoError(t, err)
	require.Len(t, response.Results, 2)
	require.Equal(t, "2", *response.Results[0].Rows[0][0])
	result := response.Results[1]
	require.Equal(t, "SELECT", result.Command)
	require.Equal(t, []auth.QueryColumn{{Name: "id", Type: "int4"}, {Name: "body", Type: "text"}}, result.Columns)
	require.Equal(t, int64(2), result.RowCount)
	require.Len(t, result.Rows, 2)
	require.Equal(t, "first", *result.Rows[0][1])
	require.Nil(t, result.Rows[1][1], "NULL stays distinguishable from an empty string")
	require.False(t, result.Truncated)

	require.Equal(t, counts, platformCounts(t, pool), "an execution writes no platform row")
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), sentinelSecret)
}

func TestExecuteQueryRefusesUngrantedDisabledAndRevokedCallers(t *testing.T) {
	pool, s, admin, input := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")
	_, plainInput := createMember(t, s, admin, "plain-member")
	plain := session(t, s, login(t, s, plainInput), auth.CLI)
	granted, grantedInput := createMember(t, s, admin, "granted-member")
	grantConnection(t, s, admin, granted.ID, record.ID)
	grantedSession := session(t, s, login(t, s, grantedInput), auth.CLI)
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	request := auth.QueryRequest{Connection: record.Name, SQL: "select 1"}
	// Every write this test makes has happened by now except the revocation
	// below, so a refused execution may change nothing from here on.
	counts := platformCounts(t, pool)

	code(t, queryError(s.ExecuteQuery(t.Context(), plain, request)), auth.ConnectionNotFound)
	// An unknown reference answers exactly like an ungranted one.
	code(t, queryError(s.ExecuteQuery(t.Context(), plain,
		auth.QueryRequest{Connection: "no-such-connection", SQL: "select 1"})), auth.ConnectionNotFound)

	_, err := s.SetConnectionEnabled(t.Context(), admin, record.ID, false, false)
	require.NoError(t, err)
	for name, actor := range map[string]auth.Session{"administrator": admin, "granted member": grantedSession} {
		failure := queryError(s.ExecuteQuery(t.Context(), actor, request))
		code(t, failure, auth.ConnectionDisabled, name)
		require.Equal(t, hintConnectionDisabled, hintOf(t, failure), name)
	}
	_, err = s.SetConnectionEnabled(t.Context(), admin, record.ID, true, false)
	require.NoError(t, err)

	code(t, queryError(s.ExecuteQuery(t.Context(), revoked, request)), auth.Unauthenticated)
	code(t, queryError(s.ExecuteQuery(t.Context(), auth.Session{}, request)), auth.Unauthenticated)
	require.Equal(t, counts, platformCounts(t, pool), "a refused execution writes no platform row")

	// A revoked grant refuses the next request without any connection kept
	// open on the member's behalf.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: granted.ID, Connection: record.ID}, false)
	require.NoError(t, err)
	counts["grants"]--
	code(t, queryError(s.ExecuteQuery(t.Context(), grantedSession, request)), auth.ConnectionNotFound)
	require.Equal(t, counts, platformCounts(t, pool))
}

func TestExecuteQueryRefusesMismatchedInputsBeforeOpeningTheSecret(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	source := newMetricsSource(t)
	metrics := metricsConnection(t, s, admin, "metrics-query", source.url, 0)
	ledger := queryConnection(t, s, admin, "ledger-query")

	// SQL for a metrics connection and an expression for a SQL one are both
	// refused with the input the connection's own provider takes.
	failure := queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: metrics.Name, SQL: "select 1"}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryWantsMetrics, hintOf(t, failure))
	failure = queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: ledger.Name, PromQL: "up"}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryWantsSQL, hintOf(t, failure))
	require.Empty(t, source.seen(), "a mismatched input never reaches the source")

	// An envelope nothing can open would answer CREDENTIALS_UNAVAILABLE if the
	// secret were opened first; the refusal has to come before that.
	execSQL(t, pool, `UPDATE connections SET secret_envelope=$1 WHERE id=$2`, "not-an-envelope", ledger.ID)
	failure = queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: ledger.Name, Labels: true}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryWantsSQL, hintOf(t, failure))
	require.NotContains(t, failure.Error(), sentinelSecret)
	require.NotContains(t, failure.Error(), sentinelHost)
}

func TestExecuteQueryFailsClosedWithoutTheKey(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")

	other, err := NewLocalAuth(pool, s.checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	failure := queryError(other.WithKeyring(newTestKeyring(t)).ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, SQL: "select 1"}))
	code(t, failure, auth.CredentialsUnavailable)
	require.Equal(t, hintCredentials, hintOf(t, failure))

	// Without a keyring at all the service fails the same way.
	bare, err := NewLocalAuth(pool, s.checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	code(t, queryError(bare.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, SQL: "select 1"})), auth.CredentialsUnavailable)
}

func TestExecuteQueryValidatesLocallyWithoutContactingTheSource(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	record := unreachableConnection(t, s, admin, "unreachable-query")

	for name, testCase := range map[string]struct {
		request auth.QueryRequest
		hint    string
	}{
		"malformed reference": {auth.QueryRequest{Connection: "Not A Reference", SQL: "select 1"}, hintConnectionNotFound},
		"no input":            {auth.QueryRequest{Connection: record.Name}, hintQueryInput},
		"blank sql":           {auth.QueryRequest{Connection: record.Name, SQL: " \n\t "}, hintQuerySQL},
		"oversized sql": {auth.QueryRequest{Connection: record.Name,
			SQL: "select " + strings.Repeat("1", auth.MaxSQLBytes)}, hintQuerySQL},
		// The input rules are the platform's own and are decided before any
		// record is read, so they hold for every connection.
		"two inputs": {auth.QueryRequest{Connection: record.Name, SQL: "select 1", PromQL: "up"}, hintQueryInput},
		"two metrics inputs": {auth.QueryRequest{Connection: record.Name, Labels: true,
			Series: `{job="api"}`}, hintQueryInput},
		"oversized time": {auth.QueryRequest{Connection: record.Name, PromQL: "up",
			Start: strings.Repeat("1", maxQueryTimeBytes+1)}, hintQueryTime},
		"at with start":      {auth.QueryRequest{Connection: record.Name, PromQL: "up", At: "now", Start: "-1h"}, hintQueryTime},
		"at with sql":        {auth.QueryRequest{Connection: record.Name, SQL: "select 1", At: "now"}, hintQueryTime},
		"at on discovery":    {auth.QueryRequest{Connection: record.Name, Labels: true, At: "now"}, hintQueryTime},
		"step without start": {auth.QueryRequest{Connection: record.Name, PromQL: "up", Step: "1m"}, hintQueryTime},
		"step on discovery": {auth.QueryRequest{Connection: record.Name, LabelValues: "__name__",
			Start: "-1h", Step: "1m"}, hintQueryTime},
		"match with promql":  {auth.QueryRequest{Connection: record.Name, PromQL: "up", Match: `{job="api"}`}, hintQueryTime},
		"end without start":  {auth.QueryRequest{Connection: record.Name, PromQL: "up", End: "now"}, hintQueryTime},
		"start with sql":     {auth.QueryRequest{Connection: record.Name, SQL: "select 1", Start: "-1h"}, hintQueryTime},
		"end with sql":       {auth.QueryRequest{Connection: record.Name, SQL: "select 1", End: "now"}, hintQueryTime},
		"match with sql":     {auth.QueryRequest{Connection: record.Name, SQL: "select 1", Match: "up"}, hintQueryTime},
		"invalid label name": {auth.QueryRequest{Connection: record.Name, LabelValues: "1bad"}, hintQueryLabel},
		"blank expression":   {auth.QueryRequest{Connection: record.Name, PromQL: "  "}, hintQueryExpression},
		"oversized expression": {auth.QueryRequest{Connection: record.Name,
			PromQL: strings.Repeat("u", auth.MaxSQLBytes+1)}, hintQueryExpression},
		"oversized selector": {auth.QueryRequest{Connection: record.Name, Labels: true,
			Match: strings.Repeat("u", auth.MaxSQLBytes+1)}, hintQueryExpression},
		"negative rows": {auth.QueryRequest{Connection: record.Name, SQL: "select 1", MaxRows: -1}, hintQueryRows},
		"rows above the cap": {auth.QueryRequest{Connection: record.Name, SQL: "select 1",
			MaxRows: record.MaxRows + 1}, hintQueryCap(record.MaxRows)},
	} {
		failure := queryError(s.ExecuteQuery(t.Context(), admin, testCase.request))
		code(t, failure, auth.InvalidArgument, name)
		require.Equal(t, testCase.hint, hintOf(t, failure), name)
	}

	// The connection cannot be reached at all, so every refusal above was
	// decided before anything left the process.
	code(t, queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, SQL: "select 1"})), auth.SourceUnreachable)
}

func TestExecuteQueryTruncatesAndDrains(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")
	schema := currentSchema(t, pool)
	execSQL(t, pool, `CREATE TABLE numbers(n int)`)
	execSQL(t, pool, `INSERT INTO numbers SELECT generate_series(1, 2000)`)
	execSQL(t, pool, `CREATE TABLE marker(n int)`)

	response, err := s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, MaxRows: 10,
		SQL: "select n from " + schema + ".numbers order by n;" +
			" insert into " + schema + ".marker values (7);",
	})
	require.NoError(t, err)
	require.True(t, response.Truncated)
	require.Len(t, response.Results, 2)
	require.True(t, response.Results[0].Truncated)
	require.Len(t, response.Results[0].Rows, 10)
	require.Equal(t, int64(10), response.Results[0].RowCount, "rowCount describes the rows in the response")
	require.Equal(t, "1", *response.Results[0].Rows[0][0])
	require.Equal(t, "INSERT", response.Results[1].Command)
	require.False(t, response.Results[1].Truncated)
	require.Equal(t, 1, countRows(t, pool, "marker"),
		"the statement after the cut still ran and committed: the drain never cancels")

	// Without a request cap the connection's own cap applies.
	five := 5
	_, err = s.UpdateConnection(t.Context(), admin, record.ID, auth.UpdateConnectionRequest{MaxRows: &five}, false)
	require.NoError(t, err)
	response, err = s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select n from " + schema + ".numbers order by n",
	})
	require.NoError(t, err)
	require.True(t, response.Truncated)
	require.Len(t, response.Results[0].Rows, 5)

	// A request may lower that cap further, never raise it.
	response, err = s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, MaxRows: 2, SQL: "select n from " + schema + ".numbers order by n",
	})
	require.NoError(t, err)
	require.Len(t, response.Results[0].Rows, 2)
	failure := queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, MaxRows: 6, SQL: "select 1",
	}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryCap(5), hintOf(t, failure))
}

func TestExecuteQueryReportsSourceRejections(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")

	// The second statement fails on analysis, so one result completed before it.
	failure := queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select 1; select " + sentinelColumn + ";",
	}))
	code(t, failure, auth.SourceError)
	rejection := sourceOf(t, failure)
	require.Equal(t, "42703", rejection.SQLState)
	require.NotNil(t, rejection.Statement)
	require.Equal(t, 1, *rejection.Statement)
	require.Contains(t, rejection.Message, sentinelColumn, "the source's own message reaches the caller unchanged")
	require.NotContains(t, failure.Error(), sentinelColumn, "the platform's error text stays fixed")
	require.NotContains(t, failure.Error(), sentinelSecret)
	require.Empty(t, hintOf(t, failure))

	// A syntax error is caught when the whole string is parsed, before any
	// statement has run, so nothing completed and the index is zero.
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select 1; selec 2;",
	}))
	code(t, failure, auth.SourceError)
	rejection = sourceOf(t, failure)
	require.Equal(t, "42601", rejection.SQLState)
	require.NotNil(t, rejection.Statement)
	require.Equal(t, 0, *rejection.Statement)
	require.NotZero(t, rejection.Position)

	// A privilege the role lacks is the source's rejection too, not ours.
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select * from pg_catalog.no_such_catalog_relation",
	}))
	code(t, failure, auth.SourceError)
	encoded, err := json.Marshal(sourceOf(t, failure))
	require.NoError(t, err)
	require.NotContains(t, string(encoded), sentinelSecret)
}

func TestExecuteQueryReportsTimeoutUnreachableAndRefusedCredentials(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")
	bound := 1000
	_, err := s.UpdateConnection(t.Context(), admin, record.ID,
		auth.UpdateConnectionRequest{StatementTimeoutMS: &bound}, false)
	require.NoError(t, err)

	started := time.Now()
	failure := queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select pg_sleep(5)",
	}))
	code(t, failure, auth.SourceTimeout)
	require.Equal(t, hintQueryTimeout(bound), hintOf(t, failure))
	require.Contains(t, hintOf(t, failure), "1000 ms")
	require.Less(t, time.Since(started), 5*time.Second, "the source aborted the statement at its own bound")

	_, err = s.SetConnectionCredentials(t.Context(), admin, record.ID, auth.Secret(sentinelSecret), false)
	require.NoError(t, err)
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select 1",
	}))
	code(t, failure, auth.SourceAuthRejected)
	require.Equal(t, hintQueryCheck, hintOf(t, failure))
	require.NotContains(t, failure.Error(), sentinelSecret)

	closed := map[string]string{"url": "postgres://reader@" + closedPort(t) + "/ledger?sslmode=disable"}
	_, err = s.UpdateConnection(t.Context(), admin, record.ID,
		auth.UpdateConnectionRequest{Target: &closed}, false)
	require.NoError(t, err)
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select 1",
	}))
	code(t, failure, auth.SourceUnreachable)
	require.Equal(t, hintQueryCheck, hintOf(t, failure))
}

func TestExecuteQueryHoldsNoPlatformTransactionWhileTheSourceWorks(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")
	// The platform pool names every one of its backends after the test's own
	// schema, so the platform's connections are exactly the ones to inspect.
	var schema string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema))
	external := "clavis:" + record.Name + ":" + admin.User.Username
	counts := platformCounts(t, pool)

	done := make(chan error, 1)
	go func() {
		done <- queryError(s.ExecuteQuery(context.Background(), admin,
			auth.QueryRequest{Connection: record.Name, SQL: "select pg_sleep(2)"}))
	}()

	observed := false
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-done:
			require.NoError(t, err)
			require.True(t, observed, "the external statement was never seen running")
			require.Equal(t, counts, platformCounts(t, pool))
			return
		default:
		}
		require.True(t, time.Now().Before(deadline), "the execution never finished")
		var open, running int
		require.NoError(t, pool.QueryRow(t.Context(), `
			SELECT count(*) FILTER (WHERE application_name = $1 AND xact_start IS NOT NULL AND pid <> pg_backend_pid()),
			       count(*) FILTER (WHERE application_name = $2 AND state = 'active')
			FROM pg_stat_activity`, schema, external).Scan(&open, &running))
		require.Zero(t, open, "a platform transaction was open while the source was working")
		if running > 0 {
			observed = true
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestExecuteQueryNamesTheApplicationForTheSource(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	record := queryConnection(t, s, admin, "ledger-query")

	response, err := s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name,
		SQL:        "select current_setting('application_name'), current_setting('client_encoding')",
	})
	require.NoError(t, err)
	require.Len(t, response.Results, 1)
	require.Len(t, response.Results[0].Rows, 1)
	require.Equal(t, "clavis:"+record.Name+":"+admin.User.Username, *response.Results[0].Rows[0][0])
	require.Equal(t, "UTF8", *response.Results[0].Rows[0][1])

	// No session state survives a request: the connection is a fresh one.
	_, err = s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "create temporary table ephemeral(n int)",
	})
	require.NoError(t, err)
	failure := queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, SQL: "select n from ephemeral",
	}))
	code(t, failure, auth.SourceError)
	require.Equal(t, "42P01", sourceOf(t, failure).SQLState)
}

// metricsRequest is one request as the fake source received it: the method,
// the path and every parameter, whether it arrived in the query string or in a
// form body, so a test can prove what the platform forwarded.
type metricsRequest struct {
	method string
	path   string
	values url.Values
}

// metricsSource is a fake VictoriaMetrics. It is the metrics half of what the
// test instance is for SQL: an external source the platform reaches over the
// wire, with nothing of the platform's in it.
type metricsSource struct {
	url    string
	mu     sync.Mutex
	calls  []metricsRequest
	answer func(http.ResponseWriter, *http.Request)
}

func newMetricsSource(t *testing.T) *metricsSource {
	t.Helper()
	source := &metricsSource{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		source.mu.Lock()
		source.calls = append(source.calls, metricsRequest{r.Method, r.URL.Path, r.Form})
		answer := source.answer
		source.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if answer != nil {
			answer(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	t.Cleanup(server.Close)
	source.url = server.URL
	return source
}

func (m *metricsSource) reply(answer func(http.ResponseWriter, *http.Request)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answer = answer
}

func (m *metricsSource) seen() []metricsRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]metricsRequest(nil), m.calls...)
}

func (m *metricsSource) last(t *testing.T) metricsRequest {
	t.Helper()
	calls := m.seen()
	require.NotEmpty(t, calls)
	return calls[len(calls)-1]
}

// jsonAnswer replies with one fixed envelope, which is how every shape and
// every source failure is exercised without a real source.
func jsonAnswer(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }
}

func metricsConnection(t *testing.T, s *LocalAuth, admin auth.Session, name, url string, maxRows int) auth.Connection {
	t.Helper()
	return createConnection(t, s, admin, auth.CreateConnectionRequest{
		Name: name, Title: "Metrics", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": url, "auth": "none"}, Labels: map[string]string{}, MaxRows: maxRows,
	})
}

func TestExecuteQueryForwardsMetricsInputsAndReturnsTheSourceAnswer(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	source := newMetricsSource(t)
	record := metricsConnection(t, s, admin, "metrics-query", source.url, 0)
	member, memberInput := createMember(t, s, admin, "metrics-member")
	grantConnection(t, s, admin, member.ID, record.ID)
	memberSession := session(t, s, login(t, s, memberInput), auth.CLI)
	counts := platformCounts(t, pool)

	// A granted member's instant query reaches the query endpoint with the
	// expression and the pinned time exactly as submitted, and the source's
	// own answer comes back beside its own warning and partial flag.
	source.reply(jsonAnswer(`{"status":"success","warnings":["the range is long"],"isPartial":true,` +
		`"data":{"resultType":"vector","result":[{"metric":{"__name__":"up","job":"api"},"value":[1700000000,"1"]}]}}`))
	expression := "sum(rate(http_requests_total[5m])) by (job)"
	response, err := s.ExecuteQuery(t.Context(), memberSession, auth.QueryRequest{
		Connection: record.Name, PromQL: expression, At: "2026-09-13T00:00:00Z",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderVictoriaMetrics, response.Provider)
	require.Equal(t, "vector", response.ResultType)
	require.JSONEq(t, `[{"metric":{"__name__":"up","job":"api"},"value":[1700000000,"1"]}]`, string(response.Result))
	require.Equal(t, []string{"the range is long"}, response.Warnings)
	require.Nil(t, response.Infos)
	require.True(t, response.IsPartial)
	require.False(t, response.Truncated)
	require.Empty(t, response.Results, "a metrics answer carries no results list")
	require.GreaterOrEqual(t, response.DurationMS, int64(0))
	call := source.last(t)
	require.Equal(t, "/api/v1/query", call.path)
	require.Equal(t, expression, call.values.Get("query"))
	require.Equal(t, "2026-09-13T00:00:00Z", call.values.Get("time"))
	require.Empty(t, call.values.Get("start"))

	for name, tc := range map[string]struct {
		request    auth.QueryRequest
		body       string
		path       string
		resultType string
		values     map[string]string
	}{
		"range query": {
			auth.QueryRequest{Connection: record.Name, PromQL: "up", Start: "-1h", End: "now", Step: "1m"},
			`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"api"},"values":[[1,"1"]]}]}}`,
			"/api/v1/query_range", "matrix",
			map[string]string{"query": "up", "start": "-1h", "end": "now", "step": "1m"},
		},
		"labels": {
			auth.QueryRequest{Connection: record.Name, Labels: true, Match: `{job="api"}`},
			`{"status":"success","data":["__name__","job"]}`,
			"/api/v1/labels", "labels",
			map[string]string{"match[]": `{job="api"}`},
		},
		"label values": {
			auth.QueryRequest{Connection: record.Name, LabelValues: "__name__", Start: "-1h", End: "now"},
			`{"status":"success","data":["up","go_info"]}`,
			"/api/v1/label/__name__/values", "labelValues",
			map[string]string{"start": "-1h", "end": "now"},
		},
		"series": {
			auth.QueryRequest{Connection: record.Name, Series: `{__name__=~"up"}`, Match: `{job="api"}`},
			`{"status":"success","data":[{"__name__":"up","job":"api"}]}`,
			"/api/v1/series", "series",
			map[string]string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			source.reply(jsonAnswer(tc.body))
			answer, err := s.ExecuteQuery(t.Context(), memberSession, tc.request)
			require.NoError(t, err)
			require.Equal(t, tc.resultType, answer.ResultType)
			require.False(t, answer.Truncated)
			require.Nil(t, answer.Warnings)
			require.False(t, answer.IsPartial)
			call := source.last(t)
			require.Equal(t, tc.path, call.path)
			for key, want := range tc.values {
				require.Equal(t, want, call.values.Get(key), key)
			}
		})
	}
	// A series request carries its selector and the optional match as the two
	// match[] parameters the source documents, in that order.
	selectors := []string(nil)
	for _, call := range source.seen() {
		if call.path == "/api/v1/series" {
			selectors = call.values["match[]"]
		}
	}
	require.Equal(t, []string{`{__name__=~"up"}`, `{job="api"}`}, selectors)
	require.Equal(t, counts, platformCounts(t, pool), "an execution writes no platform row")
}

func TestExecuteQueryBoundsMetricsSamplesAndReportsSourceFailures(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	source := newMetricsSource(t)
	record := metricsConnection(t, s, admin, "metrics-query", source.url, 3)
	matrix := `{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"],[3,"3"],[4,"4"]]},` +
		`{"metric":{"job":"b"},"values":[[5,"5"]]}]}}`

	// The row cap is a sample cap: the first series keeps what fits, the one
	// after it keeps nothing, and both say so inside the answer.
	source.reply(jsonAnswer(matrix))
	response, err := s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, PromQL: "up", Start: "-1h", Step: "1m",
	})
	require.NoError(t, err)
	require.True(t, response.Truncated)
	require.JSONEq(t, `[{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"],[3,"3"]],"truncated":true},`+
		`{"metric":{"job":"b"},"values":[],"truncated":true}]`, string(response.Result))

	// A request may lower that cap further, never raise it.
	response, err = s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, PromQL: "up", Start: "-1h", Step: "1m", MaxRows: 1,
	})
	require.NoError(t, err)
	require.True(t, response.Truncated)
	require.JSONEq(t, `[{"metric":{"job":"a"},"values":[[1,"1"]],"truncated":true},`+
		`{"metric":{"job":"b"},"values":[],"truncated":true}]`, string(response.Result))
	failure := queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{
		Connection: record.Name, PromQL: "up", MaxRows: 4,
	}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryCap(3), hintOf(t, failure))

	// The source's own rejection is passed through with its own classification
	// and no statement index, because a metrics source has no statements.
	source.reply(jsonAnswer(`{"status":"error","errorType":"bad_data","error":"unparsed data in query"}`))
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: record.Name, PromQL: "up ~~"}))
	code(t, failure, auth.SourceError)
	rejection := sourceOf(t, failure)
	require.Equal(t, "bad_data", rejection.ErrorType)
	require.Equal(t, "unparsed data in query", rejection.Message)
	require.Empty(t, rejection.SQLState)
	require.Nil(t, rejection.Statement)
	require.NotContains(t, failure.Error(), "unparsed data")

	// A source that stops answering is cut at the connection's own bound plus
	// the documented grace, and reported as the timeout it looks like.
	bound := 1000
	_, err = s.UpdateConnection(t.Context(), admin, record.ID,
		auth.UpdateConnectionRequest{StatementTimeoutMS: &bound}, false)
	require.NoError(t, err)
	source.reply(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	started := time.Now()
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: record.Name, PromQL: "up"}))
	code(t, failure, auth.SourceTimeout)
	require.Equal(t, hintQueryTimeout(bound), hintOf(t, failure))
	elapsed := time.Since(started)
	require.Greater(t, elapsed, time.Second, "the bound is the connection's, not an instant refusal")
	require.Less(t, elapsed, auth.MetricsGrace+5*time.Second)
	// The bound the source was asked to apply to itself is the same one.
	require.Equal(t, "1s", source.last(t).values.Get("timeout"))
}

func TestExecuteQueryRefusesMetricsCallersWithoutAccess(t *testing.T) {
	_, s, admin, input := connectionFixture(t)
	source := newMetricsSource(t)
	record := metricsConnection(t, s, admin, "metrics-query", source.url, 0)
	_, plainInput := createMember(t, s, admin, "plain-member")
	plain := session(t, s, login(t, s, plainInput), auth.CLI)
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	request := auth.QueryRequest{Connection: record.Name, PromQL: "up"}

	code(t, queryError(s.ExecuteQuery(t.Context(), plain, request)), auth.ConnectionNotFound)
	_, err := s.SetConnectionEnabled(t.Context(), admin, record.ID, false, false)
	require.NoError(t, err)
	failure := queryError(s.ExecuteQuery(t.Context(), admin, request))
	code(t, failure, auth.ConnectionDisabled)
	require.Equal(t, hintConnectionDisabled, hintOf(t, failure))
	code(t, queryError(s.ExecuteQuery(t.Context(), revoked, request)), auth.Unauthenticated)
	require.Empty(t, source.seen(), "a refused request never reaches the source")
}
