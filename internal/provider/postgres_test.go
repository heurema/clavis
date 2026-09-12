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

// postgresTarget builds a canonical target from the supplied test database.
func postgresTarget(t *testing.T) (map[string]string, auth.Secret) {
	t.Helper()
	dsn := os.Getenv("CLAVIS_BACKEND_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set CLAVIS_BACKEND_TEST_DATABASE_URL to isolated PostgreSQL")
	}
	config, err := pgx.ParseConfig(dsn)
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
