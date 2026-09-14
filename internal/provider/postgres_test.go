package provider

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestPostgresParseTarget(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  map[string]string
		want map[string]string
	}{
		{
			name: "defaults",
			raw:  map[string]string{keyURL: "postgres://app@db.example.com/analytics"},
			want: map[string]string{
				keyHost: "db.example.com", keyPort: "5432", keyDatabase: "analytics",
				keyRole: "app", keySSLMode: "prefer",
			},
		},
		{
			name: "explicit port and sslmode",
			raw:  map[string]string{keyURL: "postgresql://reader@10.0.0.5:6432/metrics?sslmode=verify-full"},
			want: map[string]string{
				keyHost: "10.0.0.5", keyPort: "6432", keyDatabase: "metrics",
				keyRole: "reader", keySSLMode: "verify-full",
			},
		},
		{
			name: "bracketed ipv6 loses its brackets",
			raw:  map[string]string{keyURL: "postgres://app@[2001:db8::1]:5433/analytics?sslmode=disable"},
			want: map[string]string{
				keyHost: "2001:db8::1", keyPort: "5433", keyDatabase: "analytics",
				keyRole: "app", keySSLMode: "disable",
			},
		},
		{
			name: "percent-encoded role and database",
			raw:  map[string]string{keyURL: "postgres://read%20only@db/an%20alytics?sslmode=require"},
			want: map[string]string{
				keyHost: "db", keyPort: "5432", keyDatabase: "an alytics",
				keyRole: "read only", keySSLMode: "require",
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target, err := postgreSQL{}.ParseTarget(testCase.raw)
			require.NoError(t, err)
			require.Equal(t, testCase.want, target)
			// The canonical target is a fixed point: storing and reparsing is
			// never needed, but nothing secret may have survived parsing.
			require.NotContains(t, fmt.Sprint(target), "@")
		})
	}
}

func TestPostgresParseTargetRejections(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  map[string]string
	}{
		{"no settings", map[string]string{}},
		{"empty url", map[string]string{keyURL: ""}},
		{"unknown key", map[string]string{keyURL: "postgres://app@db/analytics", sentinel: sentinel}},
		{"embedded password", map[string]string{keyURL: "postgres://app:" + sentinel + "@db/analytics"}},
		{"empty embedded password", map[string]string{keyURL: "postgres://app:@db/analytics"}},
		{"unknown query parameter", map[string]string{keyURL: "postgres://app@db/analytics?options=" + sentinel}},
		{"extra query parameter", map[string]string{keyURL: "postgres://app@db/analytics?sslmode=require&application_name=" + sentinel}},
		{"repeated sslmode", map[string]string{keyURL: "postgres://app@db/analytics?sslmode=require&sslmode=disable"}},
		{"unknown sslmode", map[string]string{keyURL: "postgres://app@db/analytics?sslmode=" + sentinel}},
		{"uppercase sslmode", map[string]string{keyURL: "postgres://app@db/analytics?sslmode=REQUIRE"}},
		{"empty query", map[string]string{keyURL: "postgres://app@db/analytics?"}},
		{"fragment", map[string]string{keyURL: "postgres://app@db/analytics#" + sentinel}},
		{"missing role", map[string]string{keyURL: "postgres://db." + sentinel + ".example/analytics"}},
		{"empty role", map[string]string{keyURL: "postgres://@db/analytics"}},
		{"missing database", map[string]string{keyURL: "postgres://app@db.example.com"}},
		{"empty database", map[string]string{keyURL: "postgres://app@db.example.com/"}},
		{"extra path segment", map[string]string{keyURL: "postgres://app@db/analytics/" + sentinel}},
		{"zero port", map[string]string{keyURL: "postgres://app@db:0/analytics"}},
		{"port above range", map[string]string{keyURL: "postgres://app@db:99999/analytics"}},
		{"non-numeric port", map[string]string{keyURL: "postgres://app@db:" + sentinel + "/analytics"}},
		{"unknown scheme", map[string]string{keyURL: "mysql://app@db/analytics"}},
		{"uppercase scheme", map[string]string{keyURL: "POSTGRES://app@db/analytics"}},
		{"opaque url", map[string]string{keyURL: "postgres:" + sentinel}},
		{"leading whitespace", map[string]string{keyURL: " postgres://app@db/analytics"}},
		{"trailing whitespace", map[string]string{keyURL: "postgres://app@db/analytics "}},
		{"embedded newline", map[string]string{keyURL: "postgres://app@db/analytics\n" + sentinel}},
		{"two hosts", map[string]string{keyURL: "postgres://app@db1," + sentinel + "/analytics"}},
		{"missing host", map[string]string{keyURL: "postgres://app@/analytics"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target, err := postgreSQL{}.ParseTarget(testCase.raw)
			require.Nil(t, target)
			requireRejected(t, err)
		})
	}
}

func TestPostgresValidateSecret(t *testing.T) {
	require.NoError(t, postgreSQL{}.ValidateSecret(nil, auth.Secret(sentinel)))
	for _, secret := range []auth.Secret{
		"",
		auth.Secret(sentinel + "\n"),
		auth.Secret(sentinel + "\x00"),
		auth.Secret(strings.Repeat("x", auth.MaxSecretBytes+1)),
	} {
		requireRejected(t, postgreSQL{}.ValidateSecret(nil, secret))
	}
}

// testDSN is the shared local database the real-PostgreSQL tests use.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("CLAVIS_BACKEND_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set CLAVIS_BACKEND_TEST_DATABASE_URL to isolated PostgreSQL")
	}
	return dsn
}

// postgresTarget builds a canonical target from the supplied test database.
func postgresTarget(t *testing.T) (map[string]string, auth.Secret) {
	t.Helper()
	config, err := pgx.ParseConfig(testDSN(t))
	require.NoError(t, err)
	require.NotEmpty(t, config.Password, "the test database URL must carry the role's password")
	target, err := postgreSQL{}.ParseTarget(map[string]string{keyURL: fmt.Sprintf(
		"postgres://%s@%s:%d/%s?sslmode=disable", config.User, config.Host, config.Port, config.Database,
	)})
	require.NoError(t, err)
	return target, auth.Secret(config.Password)
}

func TestPostgresProbeReachable(t *testing.T) {
	target, secret := postgresTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.Equal(t, auth.CheckReachable, postgreSQL{}.Probe(ctx, target, secret))
}

func TestPostgresProbeWrongPassword(t *testing.T) {
	target, _ := postgresTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	outcome := postgreSQL{}.Probe(ctx, target, auth.Secret(sentinel+"-wrong-password"))
	require.Equal(t, auth.CheckAuthRejected, outcome)
	requireNoSentinel(t, outcome)
}

func TestPostgresProbeUnknownDatabase(t *testing.T) {
	target, secret := postgresTarget(t)
	missing := maps.Clone(target)
	missing[keyDatabase] = "absent-" + sentinel
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.Equal(t, auth.CheckUnreachable, postgreSQL{}.Probe(ctx, missing, secret))
}

// closedTarget points at a port that was bound and released, so a dial is
// refused immediately.
func closedTarget(t *testing.T) map[string]string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	return map[string]string{
		keyHost: "127.0.0.1", keyPort: port, keyDatabase: "clavis",
		keyRole: "clavis", keySSLMode: "disable",
	}
}

func TestPostgresProbeClosedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := time.Now()
	require.Equal(t, auth.CheckUnreachable, postgreSQL{}.Probe(ctx, closedTarget(t), auth.Secret(sentinel)))
	require.Less(t, time.Since(started), 3*time.Second)
}

func TestPostgresProbeExpiredContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	started := time.Now()
	require.Equal(t, auth.CheckUnreachable, postgreSQL{}.Probe(ctx, closedTarget(t), auth.Secret(sentinel)))
	require.Less(t, time.Since(started), time.Second)
}

// silentListener accepts connections and never answers, which is how a
// black-holed source behaves: only the deadline ends the probe.
func silentListener(t *testing.T) map[string]string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mutex sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			accepted = append(accepted, conn)
			mutex.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mutex.Lock()
		defer mutex.Unlock()
		for _, conn := range accepted {
			_ = conn.Close()
		}
	})
	return map[string]string{
		keyHost:     "127.0.0.1",
		keyPort:     strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
		keyDatabase: "clavis", keyRole: "clavis", keySSLMode: "disable",
	}
}

func TestPostgresProbeHonoursDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	require.Equal(t, auth.CheckUnreachable, postgreSQL{}.Probe(ctx, silentListener(t), auth.Secret(sentinel)))
	elapsed := time.Since(started)
	require.GreaterOrEqual(t, elapsed, 150*time.Millisecond)
	require.Less(t, elapsed, 2*time.Second)
}

func TestPostgresProbeIsConcurrencySafe(t *testing.T) {
	target, secret := postgresTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	outcomes := make(chan auth.CheckOutcome, 4)
	for range cap(outcomes) {
		go func() { outcomes <- postgreSQL{}.Probe(ctx, target, secret) }()
	}
	for range cap(outcomes) {
		require.Equal(t, auth.CheckReachable, <-outcomes)
	}
}

var schemaSequence atomic.Int64

// querySchema creates an isolated schema for one test and drops it with
// everything in it afterwards, so tests sharing the local database never see
// each other's tables.
func querySchema(t *testing.T) string {
	t.Helper()
	dsn := testDSN(t)
	name := fmt.Sprintf("clavis_query_%d_%d", os.Getpid(), schemaSequence.Add(1))
	adminExec(t, dsn, "create schema "+name)
	t.Cleanup(func() { adminExec(t, dsn, "drop schema "+name+" cascade") })
	return name
}

// adminExec runs setup and verification SQL on a connection of its own, so no
// test checks the code under test with the code under test.
func adminExec(t *testing.T, dsn, sql string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, sql)
	require.NoError(t, err)
}

// adminValue reads one value the same way.
func adminValue[T any](t *testing.T, dsn, sql string) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	var value T
	require.NoError(t, conn.QueryRow(ctx, sql).Scan(&value))
	return value
}

// executeRequest is the shape the service sends: the connection's own bounds
// and the application name the service composes for the source to display.
func executeRequest(sql string) ExecuteRequest {
	return ExecuteRequest{
		SQL: sql, Timeout: 10 * time.Second, MaxRows: auth.DefaultMaxRows,
		MaxBytes: auth.DefaultMaxBytes, Application: "clavis:payments-prod-reporting:alice",
	}
}

func execute(t *testing.T, request ExecuteRequest) (ExecuteResult, error) {
	t.Helper()
	target, secret := postgresTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	return postgreSQL{}.Execute(ctx, target, secret, request)
}

// text renders kept rows as plain values with a marker for NULL, so the
// expectations stay readable while NULL stays distinguishable.
func text(rows [][]*string) [][]string {
	rendered := make([][]string, 0, len(rows))
	for _, row := range rows {
		values := make([]string, len(row))
		for index, value := range row {
			values[index] = "<null>"
			if value != nil {
				values[index] = *value
			}
		}
		rendered = append(rendered, values)
	}
	return rendered
}

func commands(result ExecuteResult) []string {
	tags := make([]string, 0, len(result.Results))
	for _, one := range result.Results {
		tags = append(tags, one.Command)
	}
	return tags
}

func ptr(value string) *string { return &value }

func TestPostgresExecuteSingleStatement(t *testing.T) {
	result, err := execute(t, executeRequest("select 1 as one, 'two'::text as two"))
	require.NoError(t, err)
	require.False(t, result.Truncated)
	require.Equal(t, int64(1), result.Statements)
	require.Equal(t, int64(1), result.Rows)
	require.Equal(t, int64(4), result.Bytes)
	require.Equal(t, []auth.QueryResult{{
		Command:  "SELECT",
		Columns:  []auth.QueryColumn{{Name: "one", Type: "int4"}, {Name: "two", Type: "text"}},
		Rows:     [][]*string{{ptr("1"), ptr("two")}},
		RowCount: 1,
	}}, result.Results)
}

func TestPostgresExecuteMultiStatementScript(t *testing.T) {
	schema := querySchema(t)
	result, err := execute(t, executeRequest(fmt.Sprintf(
		"create table %[1]s.notes (value text); insert into %[1]s.notes values ('a'), ('b'); "+
			"select value from %[1]s.notes order by value;", schema)))
	require.NoError(t, err)
	require.Equal(t, int64(3), result.Statements)
	// The results arrive in the order the statements were written.
	require.Equal(t, []string{"CREATE", "INSERT", "SELECT"}, commands(result))
	require.Equal(t, int64(2), result.Results[1].RowCount)
	require.Equal(t, [][]string{{"a"}, {"b"}}, text(result.Results[2].Rows))
	// A statement without rows carries empty lists rather than nil, so the
	// response renders them as [] and a caller never branches on the shape.
	require.NotNil(t, result.Results[0].Columns)
	require.NotNil(t, result.Results[0].Rows)
	require.Empty(t, result.Results[0].Columns)
}

func TestPostgresExecuteImplicitTransactionRollsBack(t *testing.T) {
	dsn := testDSN(t)
	schema := querySchema(t)
	adminExec(t, dsn, "create table "+schema+".notes (value text)")
	_, err := execute(t, executeRequest(fmt.Sprintf(
		"insert into %[1]s.notes values ('kept'); select nosuchcolumn from %[1]s.notes;", schema)))
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "42703", rejected.Failure.SQLState)
	require.NotEmpty(t, rejected.Failure.Message)
	require.NotZero(t, rejected.Failure.Position)
	require.Equal(t, auth.StatementIndex(1), rejected.Failure.Statement, "one statement completed before the failing one")
	// The failing statement took the implicit transaction down with it, so the
	// insert that had already run is gone.
	require.Equal(t, int64(0), adminValue[int64](t, dsn, "select count(*) from "+schema+".notes"))
}

func TestPostgresExecuteSyntaxErrorLocatesItself(t *testing.T) {
	_, err := execute(t, executeRequest("select 1; slect 2;"))
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "42601", rejected.Failure.SQLState)
	// PostgreSQL parses the whole string before it runs any of it, so a syntax
	// error means no statement completed whichever one carries it; the
	// position locates it in the string the caller submitted.
	require.Equal(t, auth.StatementIndex(0), rejected.Failure.Statement)
	require.Greater(t, rejected.Failure.Position, len("select 1; "))
}

func TestPostgresExecuteTypedValuesStayExact(t *testing.T) {
	result, err := execute(t, executeRequest(
		"set time zone 'UTC'; select 1.50::numeric as exact, 9007199254740993::int8 as big, "+
			"'2026-01-02 03:04:05+00'::timestamptz as moment, null::text as absent, ''::text as blank"))
	require.NoError(t, err)
	require.Equal(t, int64(2), result.Statements)
	rows := result.Results[1]
	require.Equal(t, []auth.QueryColumn{
		{Name: "exact", Type: "numeric"}, {Name: "big", Type: "int8"}, {Name: "moment", Type: "timestamptz"},
		{Name: "absent", Type: "text"}, {Name: "blank", Type: "text"},
	}, rows.Columns)
	// Every value is the text the source rendered: the exact numeric keeps its
	// trailing zero and the integer beyond 2^53 keeps every digit.
	require.Equal(t, [][]string{{"1.50", "9007199254740993", "2026-01-02 03:04:05+00", "<null>", ""}}, text(rows.Rows))
	require.Nil(t, rows.Rows[0][3], "NULL is a missing value")
	require.NotNil(t, rows.Rows[0][4], "an empty string is not NULL")
}

func TestPostgresExecuteDuplicateColumnNames(t *testing.T) {
	result, err := execute(t, executeRequest("select 1 as n, 2 as n"))
	require.NoError(t, err)
	require.Equal(t, []auth.QueryColumn{{Name: "n", Type: "int4"}, {Name: "n", Type: "int4"}}, result.Results[0].Columns)
	require.Equal(t, [][]string{{"1", "2"}}, text(result.Results[0].Rows))
}

func TestPostgresExecuteStatementWithoutRows(t *testing.T) {
	dsn := testDSN(t)
	schema := querySchema(t)
	adminExec(t, dsn, "create table "+schema+".counts (value int)")
	adminExec(t, dsn, "insert into "+schema+".counts values (1), (2), (3)")
	result, err := execute(t, executeRequest("update "+schema+".counts set value = value + 1"))
	require.NoError(t, err)
	require.Equal(t, "UPDATE", result.Results[0].Command)
	// A statement without rows reports what it affected, not what it returned.
	require.Equal(t, int64(3), result.Results[0].RowCount)
	require.Equal(t, int64(0), result.Rows)
	require.NotNil(t, result.Results[0].Columns)
	require.NotNil(t, result.Results[0].Rows)
	require.Empty(t, result.Results[0].Columns)
	require.Empty(t, result.Results[0].Rows)
}

func TestPostgresExecuteRowCapDrainsAndLaterWritesCommit(t *testing.T) {
	dsn := testDSN(t)
	schema := querySchema(t)
	adminExec(t, dsn, "create table "+schema+".after (value int)")
	request := executeRequest(fmt.Sprintf(
		"select generate_series(1, 2000) as n; insert into %s.after values (1);", schema))
	request.MaxRows = 1000
	result, err := execute(t, request)
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.Len(t, result.Results[0].Rows, 1000)
	require.True(t, result.Results[0].Truncated)
	require.Equal(t, int64(1000), result.Results[0].RowCount)
	require.Equal(t, [][]string{{"1"}}, text(result.Results[0].Rows[:1]))
	require.Equal(t, [][]string{{"1000"}}, text(result.Results[0].Rows[999:]))
	require.Equal(t, int64(1000), result.Rows)
	require.Equal(t, "INSERT", result.Results[1].Command)
	require.False(t, result.Results[1].Truncated)
	require.Equal(t, int64(1), result.Results[1].RowCount)
	// The rows past the cap were read and dropped, never cancelled, so the
	// statement after them ran and its work is committed.
	require.Equal(t, int64(1), adminValue[int64](t, dsn, "select count(*) from "+schema+".after"))
}

func TestPostgresExecuteByteCapKeepsTheCrossingRow(t *testing.T) {
	request := executeRequest("select repeat('x', 8) as wide from generate_series(1, 10)")
	request.MaxBytes = 10
	result, err := execute(t, request)
	require.NoError(t, err)
	// Rows are kept until the kept bytes pass the cap, so the row that crosses
	// it is the last one kept and every row after it is dropped.
	require.Len(t, result.Results[0].Rows, 2)
	require.Equal(t, int64(16), result.Bytes)
	require.True(t, result.Truncated)
	require.True(t, result.Results[0].Truncated)
}

func TestPostgresExecuteKeepsTheFirstRowWhateverTheByteCap(t *testing.T) {
	request := executeRequest("select repeat('x', 4096) as wide from generate_series(1, 3)")
	request.MaxBytes = auth.MinMaxBytes
	result, err := execute(t, request)
	require.NoError(t, err)
	require.Len(t, result.Results[0].Rows, 1)
	require.Equal(t, int64(4096), result.Bytes)
	require.True(t, result.Truncated)
}

func TestPostgresExecuteMaxRowsLowersTheCap(t *testing.T) {
	request := executeRequest("select generate_series(1, 50) as n")
	request.MaxRows = 5
	result, err := execute(t, request)
	require.NoError(t, err)
	require.Len(t, result.Results[0].Rows, 5)
	require.Equal(t, int64(5), result.Rows)
	require.True(t, result.Truncated)
}

func TestPostgresExecuteSessionSettings(t *testing.T) {
	request := executeRequest("select current_setting('application_name') as app, " +
		"current_setting('statement_timeout') as bound, current_setting('client_encoding') as encoding")
	request.Timeout = 2500 * time.Millisecond
	result, err := execute(t, request)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"clavis:payments-prod-reporting:alice", "2500ms", "UTF8"}}, text(result.Results[0].Rows))
}

func TestPostgresExecuteStatementTimeout(t *testing.T) {
	request := executeRequest("select pg_sleep(5)")
	request.Timeout = 250 * time.Millisecond
	started := time.Now()
	_, err := execute(t, request)
	require.ErrorIs(t, err, ErrTimeout)
	// The source aborted the statement itself: we never cancelled it, and we
	// did not wait for it to finish either.
	require.Less(t, time.Since(started), 4*time.Second)
	requireNoSentinel(t, err.Error())
}

func TestPostgresExecuteContextDeadlineIsTheBackstop(t *testing.T) {
	target, secret := postgresTarget(t)
	request := executeRequest("select pg_sleep(10)")
	request.Timeout = 60 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := postgreSQL{}.Execute(ctx, target, secret, request)
	require.ErrorIs(t, err, ErrTimeout)
	require.Less(t, time.Since(started), 5*time.Second)
}

func TestPostgresExecuteWrongPassword(t *testing.T) {
	target, _ := postgresTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := postgreSQL{}.Execute(ctx, target, auth.Secret(sentinel+"-wrong-password"), executeRequest("select "+sentinel))
	require.ErrorIs(t, err, ErrAuthRejected)
	requireNoSentinel(t, err.Error())
}

func TestPostgresExecuteUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := postgreSQL{}.Execute(ctx, closedTarget(t), auth.Secret(sentinel), executeRequest("select "+sentinel))
	require.ErrorIs(t, err, ErrUnreachable)
	requireNoSentinel(t, err.Error())
}

func TestPostgresExecuteErrorsCarryNeitherSecretNorStatement(t *testing.T) {
	target, secret := postgresTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := postgreSQL{}.Execute(ctx, target, secret, executeRequest("select "+sentinel+"_column"))
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	// The source's own message is the caller's answer and travels in the
	// failure block; the error's text is fixed and carries neither the
	// statement nor anything about the credentials that ran it.
	requireNoSentinel(t, err.Error())
	require.NotContains(t, fmt.Sprint(err), string(secret))
	require.NotContains(t, fmt.Sprintf("%v %+v", rejected.Failure, rejected.Failure), string(secret))
}

func TestPostgresExecuteUnknownTypeRendersItsOID(t *testing.T) {
	dsn := testDSN(t)
	schema := querySchema(t)
	adminExec(t, dsn, "create type "+schema+".mood as enum ('ok')")
	oid := adminValue[int64](t, dsn,
		"select oid::int8 from pg_type where typname = 'mood' and typnamespace = '"+schema+"'::regnamespace")
	result, err := execute(t, executeRequest("select 'ok'::"+schema+".mood as feeling"))
	require.NoError(t, err)
	// A type the driver has no name for is reported as its OID, which is
	// stable and looked up in pg_type; the value itself is unaffected.
	require.Equal(t, strconv.FormatInt(oid, 10), result.Results[0].Columns[0].Type)
	require.Equal(t, [][]string{{"ok"}}, text(result.Results[0].Rows))
}

func TestPostgresExecuteCounters(t *testing.T) {
	result, err := execute(t, executeRequest("select 'ab'::text as a; select 'cde'::text as b"))
	require.NoError(t, err)
	require.Equal(t, int64(2), result.Statements)
	require.Equal(t, int64(2), result.Rows)
	require.Equal(t, int64(5), result.Bytes)
	require.False(t, result.Truncated)
}

// fakeRows is a result reader over fixed rows. It hands out one reused buffer,
// exactly as the driver does, so a value the keeper failed to copy would be
// overwritten by the row after it.
type fakeRows struct {
	rows   [][][]byte
	index  int
	read   int
	buffer [][]byte
}

func (f *fakeRows) NextRow() bool {
	if f.index >= len(f.rows) {
		return false
	}
	row := f.rows[f.index]
	f.index++
	f.read++
	for len(f.buffer) < len(row) {
		f.buffer = append(f.buffer, nil)
	}
	f.buffer = f.buffer[:len(row)]
	for index, value := range row {
		if value == nil {
			f.buffer[index] = nil
			continue
		}
		// The driver hands out an empty but non-nil slice for an empty value;
		// only NULL arrives as nil.
		buffered := append(f.buffer[index][:0], value...)
		if buffered == nil {
			buffered = []byte{}
		}
		f.buffer[index] = buffered
	}
	return true
}

func (f *fakeRows) Values() [][]byte { return f.buffer }

func fakeRowsOf(values ...string) *fakeRows {
	rows := make([][][]byte, 0, len(values))
	for _, value := range values {
		rows = append(rows, [][]byte{[]byte(value)})
	}
	return &fakeRows{rows: rows}
}

func TestRowKeeperDrainsWhatItDoesNotKeep(t *testing.T) {
	rows := fakeRowsOf("a", "b", "c", "d", "e")
	keeper := &rowKeeper{maxRows: 2, maxBytes: 1024}
	kept, truncated := keeper.collect(rows)
	require.Len(t, kept, 2)
	require.True(t, truncated)
	require.True(t, keeper.dropped)
	require.Equal(t, 5, rows.read, "every row is read even when it is not kept")
	require.Equal(t, int64(2), keeper.rows)
	require.Equal(t, int64(2), keeper.bytes)
}

func TestRowKeeperByteCapKeepsTheCrossingRow(t *testing.T) {
	rows := fakeRowsOf("ab", "cd", "ef", "gh")
	keeper := &rowKeeper{maxRows: 100, maxBytes: 3}
	kept, truncated := keeper.collect(rows)
	require.Len(t, kept, 2)
	require.Equal(t, int64(4), keeper.bytes)
	require.True(t, truncated)
	require.Equal(t, 4, rows.read)
}

func TestRowKeeperAlwaysKeepsTheFirstRow(t *testing.T) {
	rows := fakeRowsOf("a very wide row", "second")
	keeper := &rowKeeper{maxRows: 1000, maxBytes: 0}
	kept, truncated := keeper.collect(rows)
	require.Len(t, kept, 1)
	require.True(t, truncated)
	require.Equal(t, int64(15), keeper.bytes)
}

func TestRowKeeperSpansResults(t *testing.T) {
	keeper := &rowKeeper{maxRows: 3, maxBytes: 1024}
	first, truncated := keeper.collect(fakeRowsOf("a", "b"))
	require.Len(t, first, 2)
	require.False(t, truncated)
	// The caps bound the whole response, so the next result continues where
	// the previous one left off.
	second := fakeRowsOf("c", "d", "e")
	kept, truncated := keeper.collect(second)
	require.Len(t, kept, 1)
	require.True(t, truncated)
	require.Equal(t, 3, second.read)
	require.Equal(t, int64(3), keeper.rows)
}

func TestRowKeeperCopiesValuesAndKeepsNullApart(t *testing.T) {
	rows := &fakeRows{rows: [][][]byte{
		{[]byte("first"), nil, {}},
		{[]byte("secnd"), []byte("x"), []byte("y")},
	}}
	keeper := &rowKeeper{maxRows: 10, maxBytes: 1024}
	kept, truncated := keeper.collect(rows)
	require.False(t, truncated)
	require.Len(t, kept, 2)
	require.Nil(t, kept[0][1], "a missing value is NULL")
	require.NotNil(t, kept[0][2])
	require.Equal(t, "", *kept[0][2], "an empty value is an empty string")
	// The reader overwrites its row buffer, so an uncopied value would read as
	// the next row's by now.
	require.Equal(t, "first", *kept[0][0])
	require.Equal(t, int64(12), keeper.bytes)
}

func TestCommandWord(t *testing.T) {
	require.Equal(t, "SELECT", commandWord("SELECT 2000"))
	require.Equal(t, "INSERT", commandWord("INSERT 0 1"))
	require.Equal(t, "CREATE", commandWord("CREATE TABLE"))
	require.Empty(t, commandWord(""))
}

func TestStatementTimeoutMS(t *testing.T) {
	require.Equal(t, int64(2500), statementTimeoutMS(2500*time.Millisecond))
	// A caller that passes no bound gets the documented default: PostgreSQL
	// reads 0 as "no timeout", which would leave a statement nothing stops.
	require.Equal(t, auth.DefaultStatementTimeout.Milliseconds(), statementTimeoutMS(0))
	require.Equal(t, auth.DefaultStatementTimeout.Milliseconds(), statementTimeoutMS(-time.Second))
	require.Equal(t, "clavis", applicationName(""))
	require.Equal(t, "clavis:payments:alice", applicationName("clavis:payments:alice"))
	defaulted := boundedRequest(ExecuteRequest{})
	require.Equal(t, auth.DefaultMaxRows, defaulted.MaxRows)
	require.Equal(t, auth.DefaultMaxBytes, defaulted.MaxBytes)
	explicit := boundedRequest(ExecuteRequest{MaxRows: 5, MaxBytes: 2048})
	require.Equal(t, 5, explicit.MaxRows)
	require.Equal(t, 2048, explicit.MaxBytes)
}

// A statement the role lacks the privilege for is refused by the source with
// its own SQLSTATE; the platform neither pre-empts nor softens it.
func TestPostgresExecutePrivilegeErrorIsTheSourcesOwn(t *testing.T) {
	dsn := testDSN(t)
	if !adminValue[bool](t, dsn, "select rolsuper or rolcreaterole from pg_roles where rolname = current_user") {
		t.Skip("the test role cannot create roles")
	}
	schema := querySchema(t)
	role := schema + "_reader"
	password := "reader-password-" + schema
	adminExec(t, dsn, fmt.Sprintf("create role %s login password '%s'", role, password))
	t.Cleanup(func() {
		adminExec(t, dsn, "drop owned by "+role)
		adminExec(t, dsn, "drop role if exists "+role)
	})
	adminExec(t, dsn, "create table "+schema+".ledger (value text)")
	adminExec(t, dsn, "grant usage on schema "+schema+" to "+role)
	target, _ := postgresTarget(t)
	target[keyRole] = role
	_, err := postgreSQL{}.Execute(t.Context(), target, auth.Secret(password), executeRequest("select value from "+schema+".ledger"))
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "42501", rejected.Failure.SQLState)
	require.Contains(t, rejected.Failure.Message, "permission denied")
	require.Equal(t, auth.StatementIndex(0), rejected.Failure.Statement)
}

// A metrics input on a SQL connection is refused before anything is dialled.
// The service refuses the mismatch first, with a hint naming the input this
// provider takes; this proves the provider's own backstop.
func TestPostgresExecuteRefusesUnsupportedInput(t *testing.T) {
	postgres, ok := Lookup(auth.ProviderPostgreSQL)
	require.True(t, ok)
	executor, ok := postgres.(Executor)
	require.True(t, ok)
	// A target that could never answer: reaching the source at all would be
	// the failure this test is looking for.
	target := map[string]string{
		keyHost: "127.0.0.1", keyPort: "1", keyDatabase: "none", keyRole: "none", keySSLMode: "disable",
	}
	for name, request := range map[string]ExecuteRequest{
		"an expression":       {PromQL: "up"},
		"labels":              {Labels: true},
		"label values":        {LabelValues: "job"},
		"series":              {Series: "up"},
		"a match":             {SQL: "select 1", Match: `{job="api"}`},
		"a time beside sql":   {SQL: "select 1", Start: "-1h"},
		"a step beside sql":   {SQL: "select 1", Step: "1m"},
		"no input at all":     {},
		"an empty sql string": {SQL: ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := executor.Execute(t.Context(), target, auth.Secret(sentinel), request)
			require.ErrorIs(t, err, ErrUnsupportedInput)
			requireNoSentinel(t, err.Error())
		})
	}
}
