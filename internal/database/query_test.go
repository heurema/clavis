package database

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/provider"
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
	require.Empty(t, hintOf(t, failure), "the source's own rejection carries no platform hint")

	// The two failures the platform classifies itself carry the next step.
	// A cap of one KiB puts the ceiling a little over one MiB, so a body of
	// one MiB plus eight KiB is beyond it.
	bytesCap := auth.MinMaxBytes
	_, err = s.UpdateConnection(t.Context(), admin, record.ID,
		auth.UpdateConnectionRequest{MaxBytes: &bytesCap}, false)
	require.NoError(t, err)
	filler := strings.Repeat("x", 1<<20+8<<10)
	source.reply(jsonAnswer(`{"status":"success","data":{"resultType":"vector","result":[` +
		`{"metric":{"job":"` + filler + `"},"value":[1,"1"]}]}}`))
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: record.Name, PromQL: "up"}))
	code(t, failure, auth.SourceError)
	require.Equal(t, provider.ResponseTooLarge, sourceOf(t, failure).ErrorType)
	require.Equal(t, hintQueryCeiling, hintOf(t, failure))
	source.reply(jsonAnswer(`{"status":"success","data":{"resultType":"vector","result":[`))
	failure = queryError(s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: record.Name, PromQL: "up"}))
	code(t, failure, auth.SourceError)
	require.Equal(t, provider.MalformedResponse, sourceOf(t, failure).ErrorType)
	require.Equal(t, hintQueryMalformed, hintOf(t, failure))

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

// logsRequest is one request as the fake log source received it: the method,
// the path, every parameter and the headers, so a test can prove what the
// platform forwarded and under whose tenant.
type logsRequest struct {
	method string
	path   string
	values url.Values
	header http.Header
}

// logsSource is a fake VictoriaLogs. Like the metrics one it is an external
// source the platform reaches over the wire, with nothing of the platform's in
// it; unlike it, it can be asked to write an unbounded stream and to report
// whether the platform cut the connection.
type logsSource struct {
	url    string
	mu     sync.Mutex
	calls  []logsRequest
	cut    bool
	answer func(http.ResponseWriter, *http.Request)
}

func newLogsSource(t *testing.T) *logsSource {
	t.Helper()
	source := &logsSource{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		source.mu.Lock()
		source.calls = append(source.calls, logsRequest{r.Method, r.URL.Path, r.Form, r.Header.Clone()})
		answer := source.answer
		source.mu.Unlock()
		// The log API writes JSON lines for the stream and one object for
		// discovery; neither carries the metrics envelope.
		w.Header().Set("Content-Type", "application/stream+json")
		if answer != nil {
			answer(w, r)
		}
	}))
	t.Cleanup(server.Close)
	source.url = server.URL
	return source
}

func (l *logsSource) reply(answer func(http.ResponseWriter, *http.Request)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.answer = answer
}

func (l *logsSource) seen() []logsRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]logsRequest(nil), l.calls...)
}

func (l *logsSource) last(t *testing.T) logsRequest {
	t.Helper()
	calls := l.seen()
	require.NotEmpty(t, calls)
	return calls[len(calls)-1]
}

func (l *logsSource) observedCut() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cut
}

// linesAnswer writes the stream the way the source does: one JSON object per
// line, with no envelope around them.
func linesAnswer(lines ...string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		for _, line := range lines {
			_, _ = io.WriteString(w, line+"\n")
		}
	}
}

// endlessAnswer writes rows until the platform stops reading, then records that
// it saw the connection close, which is what stopping at the cap looks like
// from the source's side.
func (l *logsSource) endlessAnswer() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for index := range 5000 {
			if _, err := io.WriteString(w,
				`{"_time":"2026-09-14T10:00:00Z","_msg":"row `+strconv.Itoa(index)+`"}`+"\n"); err != nil {
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			if r.Context().Err() != nil {
				break
			}
		}
		select {
		case <-r.Context().Done():
			l.mu.Lock()
			l.cut = true
			l.mu.Unlock()
		case <-time.After(10 * time.Second):
		}
	}
}

// textAnswer is the source's own failure: a status and plain text, never an
// envelope, which is every failing answer a log source writes.
func textAnswer(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func logsConnection(t *testing.T, s *LocalAuth, admin auth.Session, name, url string,
	maxRows int, tenant map[string]string) auth.Connection {
	t.Helper()
	target := map[string]string{"url": url, "auth": "none"}
	for key, value := range tenant {
		target[key] = value
	}
	return createConnection(t, s, admin, auth.CreateConnectionRequest{
		Name: name, Title: "Logs", Provider: auth.ProviderVictoriaLogs,
		Target: target, Labels: map[string]string{}, MaxRows: maxRows,
	})
}

func logsLimit(value int64) *int64 { return &value }

func TestExecuteQueryForwardsLogInputsAndReturnsTheSourceRows(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	source := newLogsSource(t)
	record := logsConnection(t, s, admin, "logs-query", source.url, 0, nil)
	member, memberInput := createMember(t, s, admin, "logs-member")
	grantConnection(t, s, admin, member.ID, record.ID)
	memberSession := session(t, s, login(t, s, memberInput), auth.CLI)
	counts := platformCounts(t, pool)

	// A granted member's query reaches the log endpoint with the query, the
	// bounds and the caller's own limit exactly as submitted, and the rows come
	// back as one array in arrival order with every field the source wrote.
	source.reply(linesAnswer(
		`{"_time":"2026-09-14T10:00:00Z","_msg":"boom","level":"error","_stream":"{job=\"api\"}"}`,
		`{"_time":"2026-09-14T10:00:01Z","_msg":"again","level":"warn","n":12}`))
	query := "error _time:1h | sort by (_time) desc"
	response, err := s.ExecuteQuery(t.Context(), memberSession, auth.QueryRequest{
		Connection: record.Name, LogsQL: query, Start: "-1h", End: "now", Limit: logsLimit(100),
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderVictoriaLogs, response.Provider)
	require.Equal(t, "logs", response.ResultType)
	require.JSONEq(t, `[{"_time":"2026-09-14T10:00:00Z","_msg":"boom","level":"error","_stream":"{job=\"api\"}"},`+
		`{"_time":"2026-09-14T10:00:01Z","_msg":"again","level":"warn","n":12}]`, string(response.Result))
	require.False(t, response.Truncated)
	require.Empty(t, response.Results, "a log answer carries no results list")
	require.Nil(t, response.Warnings)
	require.Nil(t, response.Infos)
	require.False(t, response.IsPartial)
	call := source.last(t)
	require.Equal(t, http.MethodGet, call.method)
	require.Equal(t, "/select/logsql/query", call.path)
	require.Equal(t, query, call.values.Get("query"))
	require.Equal(t, "-1h", call.values.Get("start"))
	require.Equal(t, "now", call.values.Get("end"))
	require.Equal(t, "100", call.values.Get("limit"))
	require.NotEmpty(t, call.values.Get("timeout"))
	require.Empty(t, call.header.Get("AccountID"), "a connection without a tenant sends no tenant header")

	// An explicit zero is the caller's own "no limit" and travels as a sent
	// zero; a request that names none sends no parameter at all.
	source.reply(linesAnswer())
	_, err = s.ExecuteQuery(t.Context(), memberSession, auth.QueryRequest{
		Connection: record.Name, LogsQL: "error", Limit: logsLimit(0)})
	require.NoError(t, err)
	require.Equal(t, "0", source.last(t).values.Get("limit"))
	_, err = s.ExecuteQuery(t.Context(), memberSession, auth.QueryRequest{Connection: record.Name, LogsQL: "error"})
	require.NoError(t, err)
	_, sent := source.last(t).values["limit"]
	require.False(t, sent, "the platform never adds a limit of its own")

	// An empty stream is an empty answer rather than a missing one.
	response, err = s.ExecuteQuery(t.Context(), memberSession, auth.QueryRequest{Connection: record.Name, LogsQL: "none"})
	require.NoError(t, err)
	require.JSONEq(t, `[]`, string(response.Result))

	for name, tc := range map[string]struct {
		request    auth.QueryRequest
		body       string
		path       string
		resultType string
		values     map[string]string
	}{
		"field names": {
			auth.QueryRequest{Connection: record.Name, FieldNames: true, Match: "*", Filter: "err"},
			`{"values":[{"value":"level","hits":12}]}`,
			"/select/logsql/field_names", "fieldNames",
			map[string]string{"query": "*", "filter": "err"},
		},
		"field values": {
			auth.QueryRequest{Connection: record.Name, FieldValues: "level", Match: "*",
				Filter: "err", Limit: logsLimit(5), Start: "-1h"},
			`{"values":[{"value":"error","hits":12}]}`,
			"/select/logsql/field_values", "fieldValues",
			map[string]string{"query": "*", "field": "level", "filter": "err", "limit": "5", "start": "-1h"},
		},
		"streams": {
			auth.QueryRequest{Connection: record.Name, Streams: true, Match: `{job="api"}`, Limit: logsLimit(5)},
			`{"values":[{"value":"{job=\"api\"}","hits":3}]}`,
			"/select/logsql/streams", "streams",
			map[string]string{"query": `{job="api"}`, "limit": "5"},
		},
		"stream field names": {
			auth.QueryRequest{Connection: record.Name, StreamFieldNames: true, Match: "*"},
			`{"values":[{"value":"job","hits":3}]}`,
			"/select/logsql/stream_field_names", "streamFieldNames",
			map[string]string{"query": "*"},
		},
		"stream field values": {
			auth.QueryRequest{Connection: record.Name, StreamFieldValues: "job", Match: "*", Filter: "api"},
			`{"values":[{"value":"api","hits":3}]}`,
			"/select/logsql/stream_field_values", "streamFieldValues",
			map[string]string{"query": "*", "field": "job", "filter": "api"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			source.reply(jsonAnswer(tc.body))
			answer, err := s.ExecuteQuery(t.Context(), memberSession, tc.request)
			require.NoError(t, err)
			require.Equal(t, tc.resultType, answer.ResultType)
			require.False(t, answer.Truncated)
			require.Empty(t, answer.Results)
			call := source.last(t)
			require.Equal(t, tc.path, call.path)
			for key, want := range tc.values {
				require.Equal(t, want, call.values.Get(key), key)
			}
		})
	}
	require.Equal(t, counts, platformCounts(t, pool), "an execution writes no platform row")
}

// The tenant is connection configuration: both headers travel on every request
// beside the stored authentication, and an omitted one sends no header.
func TestExecuteQuerySendsTheConnectionTenantHeaders(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	source := newLogsSource(t)
	tenant := logsConnection(t, s, admin, "logs-tenant", source.url, 0,
		map[string]string{"accountId": "12", "projectId": "3"})
	single := logsConnection(t, s, admin, "logs-single", source.url, 0,
		map[string]string{"accountId": "7"})

	source.reply(linesAnswer(`{"_time":"t","_msg":"m"}`))
	_, err := s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: tenant.Name, LogsQL: "error"})
	require.NoError(t, err)
	call := source.last(t)
	require.Equal(t, "12", call.header.Get("AccountID"))
	require.Equal(t, "3", call.header.Get("ProjectID"))

	_, err = s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: single.Name, LogsQL: "error"})
	require.NoError(t, err)
	call = source.last(t)
	require.Equal(t, "7", call.header.Get("AccountID"))
	require.Empty(t, call.header.Get("ProjectID"), "an omitted setting sends no header")
}

// The log stream is unbounded unless the caller bounds it, so the platform
// stops at the cap, closes the connection and says the completion was never
// observed; a stream that ends inside the cap is complete.
func TestExecuteQueryStopsTheLogStreamAtTheCap(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	source := newLogsSource(t)
	record := logsConnection(t, s, admin, "logs-query", source.url, 3, nil)

	source.reply(source.endlessAnswer())
	response, err := s.ExecuteQuery(t.Context(), admin, auth.QueryRequest{Connection: record.Name, LogsQL: "error"})
	require.NoError(t, err)
	require.True(t, response.Truncated)
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(response.Result, &rows))
	require.Len(t, rows, 3)
	require.Equal(t, "row 0", rows[0]["_msg"], "the rows kept are the first ones, in arrival order")
	require.Eventually(t, source.observedCut, 10*time.Second, 20*time.Millisecond,
		"the source sees the platform close the connection")

	// A request may lower the cap further, never raise it.
	failure := queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, LogsQL: "error", MaxRows: 4}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryCap(3), hintOf(t, failure))

	// A stream the source ends inside the cap is complete, also when the kept
	// count equals the cap exactly is not claimed: the end was observed.
	source.reply(linesAnswer(`{"_time":"t","_msg":"a"}`, `{"_time":"t","_msg":"b"}`))
	response, err = s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, LogsQL: "error", Limit: logsLimit(2)})
	require.NoError(t, err)
	require.False(t, response.Truncated)
	require.JSONEq(t, `[{"_time":"t","_msg":"a"},{"_time":"t","_msg":"b"}]`, string(response.Result))
}

// Every failing answer a log source writes is its own: the platform names the
// status and passes the text through, and only its own expired deadline is a
// timeout.
func TestExecuteQueryReportsLogSourceFailures(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	source := newLogsSource(t)
	record := logsConnection(t, s, admin, "logs-query", source.url, 0, nil)

	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"rejected query": {http.StatusBadRequest, "cannot parse [error ~~]: unexpected token", "http_400"},
		"source timeout": {http.StatusServiceUnavailable, "cannot execute query in 5.000 seconds", "http_503"},
	} {
		t.Run(name, func(t *testing.T) {
			source.reply(textAnswer(tc.status, tc.body))
			failure := queryError(s.ExecuteQuery(t.Context(), admin,
				auth.QueryRequest{Connection: record.Name, LogsQL: "error"}))
			code(t, failure, auth.SourceError)
			rejection := sourceOf(t, failure)
			require.Equal(t, tc.want, rejection.ErrorType)
			require.Equal(t, tc.body, rejection.Message)
			require.Empty(t, rejection.SQLState)
			require.Nil(t, rejection.Statement)
			require.Empty(t, hintOf(t, failure), "the source's own rejection carries no platform hint")
			require.NotContains(t, failure.Error(), tc.body)
		})
	}

	// A line that is not one JSON object fails the whole request, with no rows
	// and the platform's own next step.
	source.reply(linesAnswer(`{"_time":"t","_msg":"a"}`, `error: cannot read field level`))
	failure := queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, LogsQL: "error"}))
	code(t, failure, auth.SourceError)
	require.Equal(t, provider.MalformedResponse, sourceOf(t, failure).ErrorType)
	require.Equal(t, hintQueryMalformed, hintOf(t, failure))

	// A row beyond the reading ceiling is refused rather than presented cut,
	// and the hint names the limit the caller can pass.
	bytesCap := auth.MinMaxBytes
	_, err := s.UpdateConnection(t.Context(), admin, record.ID,
		auth.UpdateConnectionRequest{MaxBytes: &bytesCap}, false)
	require.NoError(t, err)
	source.reply(linesAnswer(`{"_msg":"` + strings.Repeat("x", 1<<20+8<<10) + `"}`))
	failure = queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, LogsQL: "error"}))
	code(t, failure, auth.SourceError)
	require.Equal(t, provider.ResponseTooLarge, sourceOf(t, failure).ErrorType)
	require.Equal(t, hintQueryCeiling, hintOf(t, failure))
	require.Contains(t, hintQueryCeiling, "fewer fields")

	// A source that stops answering is cut at the connection's own bound plus
	// the documented grace, and the bound it was asked to apply is the same one.
	bound := 1000
	_, err = s.UpdateConnection(t.Context(), admin, record.ID,
		auth.UpdateConnectionRequest{StatementTimeoutMS: &bound}, false)
	require.NoError(t, err)
	source.reply(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	started := time.Now()
	failure = queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: record.Name, LogsQL: "error"}))
	code(t, failure, auth.SourceTimeout)
	require.Equal(t, hintQueryTimeout(bound), hintOf(t, failure))
	elapsed := time.Since(started)
	require.Greater(t, elapsed, time.Second, "the bound is the connection's, not an instant refusal")
	require.Less(t, elapsed, auth.MetricsGrace+5*time.Second)
	require.Equal(t, "1s", source.last(t).values.Get("timeout"))
}

// An input that does not fit the connection's provider is refused on the
// record, before the secret is opened and before anything is dialled.
func TestExecuteQueryRefusesMismatchedLogInputsBeforeOpeningTheSecret(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	source := newLogsSource(t)
	metricsFake := newMetricsSource(t)
	logs := logsConnection(t, s, admin, "logs-query", source.url, 0, nil)
	metrics := metricsConnection(t, s, admin, "metrics-query", metricsFake.url, 0)
	ledger := queryConnection(t, s, admin, "ledger-query")

	for name, tc := range map[string]struct {
		request auth.QueryRequest
		hint    string
	}{
		"sql on a log connection":    {auth.QueryRequest{Connection: logs.Name, SQL: "select 1"}, hintQueryWantsLogs},
		"promql on a log connection": {auth.QueryRequest{Connection: logs.Name, PromQL: "up"}, hintQueryWantsLogs},
		"labels on a log connection": {auth.QueryRequest{Connection: logs.Name, Labels: true}, hintQueryWantsLogs},
		"logsql on a metrics one":    {auth.QueryRequest{Connection: metrics.Name, LogsQL: "error"}, hintQueryWantsMetrics},
		"streams on a metrics one":   {auth.QueryRequest{Connection: metrics.Name, Streams: true, Match: "*"}, hintQueryWantsMetrics},
		"logsql on a SQL connection": {auth.QueryRequest{Connection: ledger.Name, LogsQL: "error"}, hintQueryWantsSQL},
		"fieldNames on a SQL one":    {auth.QueryRequest{Connection: ledger.Name, FieldNames: true, Match: "*"}, hintQueryWantsSQL},
	} {
		failure := queryError(s.ExecuteQuery(t.Context(), admin, tc.request))
		code(t, failure, auth.InvalidArgument, name)
		require.Equal(t, tc.hint, hintOf(t, failure), name)
	}
	require.Empty(t, source.seen(), "a mismatched input never reaches the log source")
	require.Empty(t, metricsFake.seen(), "a mismatched input never reaches the metrics source")

	// An envelope nothing can open would answer CREDENTIALS_UNAVAILABLE if the
	// secret were opened first; the refusal has to come before that.
	execSQL(t, pool, `UPDATE connections SET secret_envelope=$1 WHERE id=$2`, "not-an-envelope", logs.ID)
	failure := queryError(s.ExecuteQuery(t.Context(), admin,
		auth.QueryRequest{Connection: logs.Name, SQL: "select 1"}))
	code(t, failure, auth.InvalidArgument)
	require.Equal(t, hintQueryWantsLogs, hintOf(t, failure))
	require.Empty(t, source.seen())
}

// Every log input rule is the platform's own and is decided before any record
// is read, so none of them reaches a source.
func TestExecuteQueryValidatesLogRulesWithoutContactingTheSource(t *testing.T) {
	_, s, admin, _ := connectionFixture(t)
	source := newLogsSource(t)
	record := logsConnection(t, s, admin, "logs-query", source.url, 0, nil)

	for name, testCase := range map[string]struct {
		request auth.QueryRequest
		hint    string
	}{
		"two log inputs": {auth.QueryRequest{Connection: record.Name, LogsQL: "error",
			Streams: true, Match: "*"}, hintQueryInput},
		"log and sql":             {auth.QueryRequest{Connection: record.Name, SQL: "select 1", LogsQL: "error"}, hintQueryInput},
		"discovery without match": {auth.QueryRequest{Connection: record.Name, FieldValues: "level"}, hintQueryMatch},
		"streams without match":   {auth.QueryRequest{Connection: record.Name, Streams: true}, hintQueryMatch},
		"match with logsql":       {auth.QueryRequest{Connection: record.Name, LogsQL: "error", Match: "*"}, hintQueryMatch},
		"limit on field names": {auth.QueryRequest{Connection: record.Name, FieldNames: true,
			Match: "*", Limit: logsLimit(5)}, hintQueryLimit},
		"limit on stream field names": {auth.QueryRequest{Connection: record.Name, StreamFieldNames: true,
			Match: "*", Limit: logsLimit(5)}, hintQueryLimit},
		"limit on sql":    {auth.QueryRequest{Connection: record.Name, SQL: "select 1", Limit: logsLimit(5)}, hintQueryLimit},
		"limit on promql": {auth.QueryRequest{Connection: record.Name, PromQL: "up", Limit: logsLimit(5)}, hintQueryLimit},
		"negative limit":  {auth.QueryRequest{Connection: record.Name, LogsQL: "error", Limit: logsLimit(-1)}, hintQueryLimit},
		"filter with logsql": {auth.QueryRequest{Connection: record.Name, LogsQL: "error",
			Filter: "err"}, hintQueryFilter},
		"filter on streams": {auth.QueryRequest{Connection: record.Name, Streams: true,
			Match: "*", Filter: "err"}, hintQueryFilter},
		"filter on sql": {auth.QueryRequest{Connection: record.Name, SQL: "select 1", Filter: "err"}, hintQueryFilter},
		"oversized filter": {auth.QueryRequest{Connection: record.Name, FieldNames: true, Match: "*",
			Filter: strings.Repeat("f", auth.MaxFilterBytes+1)}, hintQueryFilter},
		"at with logsql":   {auth.QueryRequest{Connection: record.Name, LogsQL: "error", At: "now"}, hintQueryTime},
		"step with logsql": {auth.QueryRequest{Connection: record.Name, LogsQL: "error", Start: "-1h", Step: "1m"}, hintQueryTime},
		"at with discovery": {auth.QueryRequest{Connection: record.Name, FieldNames: true,
			Match: "*", At: "now"}, hintQueryTime},
		"oversized query": {auth.QueryRequest{Connection: record.Name,
			LogsQL: strings.Repeat("e", auth.MaxSQLBytes+1)}, hintQueryExpression},
		"oversized field name": {auth.QueryRequest{Connection: record.Name,
			FieldValues: strings.Repeat("f", auth.MaxSQLBytes+1), Match: "*"}, hintQueryExpression},
		"blank query": {auth.QueryRequest{Connection: record.Name, LogsQL: "  "}, hintQueryExpression},
	} {
		failure := queryError(s.ExecuteQuery(t.Context(), admin, testCase.request))
		code(t, failure, auth.InvalidArgument, name)
		require.Equal(t, testCase.hint, hintOf(t, failure), name)
	}
	require.Empty(t, source.seen(), "every rule above was decided before anything left the process")
}
