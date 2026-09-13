package database

import (
	"context"
	"encoding/json"
	"strings"
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

func TestExecuteQueryRefusesUnsupportedProvidersBeforeOpeningTheSecret(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	metrics := createConnection(t, s, admin, auth.CreateConnectionRequest{
		Name: "metrics-query", Title: "Metrics", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": "https://" + sentinelHost, "auth": "bearer"},
		Secret: auth.Secret(sentinelSecret),
	})
	request := auth.QueryRequest{Connection: metrics.Name, SQL: "select 1"}

	failure := queryError(s.ExecuteQuery(t.Context(), admin, request))
	code(t, failure, auth.ProviderUnsupported)
	require.Equal(t, hintQueryUnsupported, hintOf(t, failure))

	// An envelope nothing can open would answer CREDENTIALS_UNAVAILABLE if the
	// secret were opened first; the refusal has to come before that.
	execSQL(t, pool, `UPDATE connections SET secret_envelope=$1 WHERE id=$2`, "not-an-envelope", metrics.ID)
	failure = queryError(s.ExecuteQuery(t.Context(), admin, request))
	code(t, failure, auth.ProviderUnsupported)
	require.Equal(t, hintQueryUnsupported, hintOf(t, failure))
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
		"empty sql":           {auth.QueryRequest{Connection: record.Name}, hintQuerySQL},
		"blank sql":           {auth.QueryRequest{Connection: record.Name, SQL: " \n\t "}, hintQuerySQL},
		"oversized sql": {auth.QueryRequest{Connection: record.Name,
			SQL: "select " + strings.Repeat("1", auth.MaxSQLBytes)}, hintQuerySQL},
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
	require.Equal(t, 1, rejection.Statement)
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
	require.Equal(t, 0, rejection.Statement)
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
