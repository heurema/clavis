package database

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Integration tests use an explicitly supplied, isolated PostgreSQL instance.
// Every test owns a random schema and removes only that schema.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CLAVIS_BACKEND_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set CLAVIS_BACKEND_TEST_DATABASE_URL to isolated PostgreSQL")
	}
	pool, err := pgxpool.New(t.Context(), url)
	require.NoError(t, err)
	schema := "backend_" + strings.ReplaceAll(randomTestID(t), "-", "")
	_, err = pool.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	config := pool.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = schema
	isolated, err := pgxpool.NewWithConfig(t.Context(), config)
	require.NoError(t, err)
	t.Cleanup(func() {
		isolated.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		require.NoError(t, err)
		pool.Close()
	})
	return isolated
}

func randomTestID(t *testing.T) string {
	t.Helper()
	id, err := bootstrapID()
	require.NoError(t, err)
	return id
}

func testSecret(t *testing.T) (string, auth.Secret) {
	t.Helper()
	var data [32]byte
	_, err := rand.Read(data[:])
	require.NoError(t, err)
	password := auth.Secret(base64.RawURLEncoding.EncodeToString(data[:]))
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(password), 0600))
	return path, password
}

func execSQL(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	_, err := pool.Exec(t.Context(), sql, args...)
	require.NoError(t, err)
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var count int
	require.NoError(t, pool.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&count))
	return count
}

func TestBootstrapFileBoundaries(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, value string
		mode        os.FileMode
		valid       bool
	}{
		{"plain", "  a valid password  ", 0600, true},
		{"lf", "a valid password\n", 0400, true},
		{"crlf", "a valid password\r\n", 0600, true},
		{"max", strings.Repeat("x", 1024) + "\r\n", 0600, true},
		{"too-large", strings.Repeat("x", 1027), 0600, false},
		{"world", "a valid password", 0644, false},
		{"group", "a valid password", 0640, false},
		{"double-newline", "a valid password\n\n", 0600, false},
		{"invalid-utf8", "a valid password\xff", 0600, false},
		{"nul", "a valid password\x00", 0600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			require.NoError(t, os.WriteFile(path, []byte(tc.value), tc.mode))
			value, err := ReadBootstrapPassword(path)
			if tc.valid {
				require.NoError(t, err)
				require.True(t, auth.ValidPassword(value))
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), path)
			}
		})
	}
	link := filepath.Join(dir, "projected")
	require.NoError(t, os.Symlink(filepath.Join(dir, "plain"), link))
	_, err := ReadBootstrapPassword(link)
	require.NoError(t, err)
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	for _, path := range []string{fifo, dir, "relative", filepath.Join(dir, "absent")} {
		start := time.Now()
		_, err := ReadBootstrapPassword(path)
		require.Error(t, err)
		require.Less(t, time.Since(start), time.Second)
		require.NotContains(t, err.Error(), path)
	}
}

func TestMigrationProcessHelper(t *testing.T) {
	if os.Getenv("CLAVIS_BACKEND_HELPER") != "1" {
		return
	}
	pool, err := pgxpool.New(t.Context(), os.Getenv("CLAVIS_BACKEND_HELPER_URL"))
	require.NoError(t, err)
	defer pool.Close()
	i := NewInitializer(pool, os.Getenv("CLAVIS_BACKEND_HELPER_USERNAME"), os.Getenv("CLAVIS_BACKEND_HELPER_FILE"))
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
}

func TestConcurrentProcessesInitializeExactlyOnce(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	other, _ := testSecret(t)
	config := pool.Config().ConnConfig.Copy()
	// ConnString preserves the startup search_path query from this explicit DSN.
	url := config.ConnString()
	if strings.Contains(url, "?") {
		url += "&"
	} else {
		url += "?"
	}
	url += "search_path=" + config.RuntimeParams["search_path"]
	commands := make([]*exec.Cmd, 2)
	for index, file := range []string{path, other} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMigrationProcessHelper$")
		cmd.Env = append(os.Environ(), "CLAVIS_BACKEND_HELPER=1", "CLAVIS_BACKEND_HELPER_URL="+url,
			fmt.Sprintf("CLAVIS_BACKEND_HELPER_USERNAME=admin%d", index), "CLAVIS_BACKEND_HELPER_FILE="+file)
		commands[index] = cmd
		require.NoError(t, cmd.Start())
	}
	for _, cmd := range commands {
		require.NoError(t, cmd.Wait())
	}
	require.Equal(t, 2, countRows(t, pool, "goose_db_version"))
	for _, table := range []string{"users", "auth_events", "installation"} {
		require.Equal(t, 1, countRows(t, pool, table))
	}
	// Obsolete values include a special file: an initialized restart must not
	// validate the username or try to open it, even with no usable admin.
	execSQL(t, pool, `UPDATE users SET disabled=true,role='member'`)
	i := NewInitializer(pool, "INVALID USERNAME", "/not/a/usable/secret")
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	execSQL(t, pool, `DELETE FROM users`)
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	require.Zero(t, countRows(t, pool, "users"))
}

func TestMigrationFailureAndFreshReadiness(t *testing.T) {
	pool := testPool(t)
	bad := fstest.MapFS{"001_bad.sql": {Data: []byte("-- +goose Up\nCREATE TABLE should_rollback(id int);\nSELECT deliberate_missing_function();")}}
	require.Error(t, migrateFS(t.Context(), pool, bad))
	var exists bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('should_rollback') IS NOT NULL`).Scan(&exists))
	require.False(t, exists)
	require.NoError(t, Migrate(t.Context(), pool))
	i := NewInitializer(pool, "", "")
	require.Equal(t, platform.SetupRequired, i.Attempt(t.Context()).State)
	require.Equal(t, platform.SetupRequired, i.Check(t.Context()).State)
	execSQL(t, pool, `UPDATE goose_db_version SET checksum='mismatch' WHERE version_id=1`)
	require.Equal(t, platform.SchemaError, i.Check(t.Context()).State)
	require.Error(t, Migrate(t.Context(), pool))
	execSQL(t, pool, `UPDATE goose_db_version SET checksum=$1 WHERE version_id=1`, embeddedMigrations()[0].sum)
	execSQL(t, pool, `INSERT INTO goose_db_version(version_id,is_applied,checksum) VALUES (99,true,'future')`)
	require.Equal(t, platform.SchemaError, i.Check(t.Context()).State)
	require.Error(t, Migrate(t.Context(), pool))
	execSQL(t, pool, `DELETE FROM goose_db_version WHERE version_id=99`)
	execSQL(t, pool, `DROP TABLE sessions`)
	require.Equal(t, platform.SchemaError, i.Check(t.Context()).State)
}

func TestBootstrapRepairAtomicAuditAndInterruption(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	require.NoError(t, os.Chmod(path, 0644))
	i := NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.BootstrapFailed, i.Attempt(t.Context()).State)
	require.Zero(t, countRows(t, pool, "users"))
	require.NoError(t, os.Chmod(path, 0600))
	execSQL(t, pool, `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private failure'; END $$;
		CREATE TRIGGER reject_event BEFORE INSERT ON auth_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)
	require.Equal(t, platform.DependencyUnavailable, i.Attempt(t.Context()).State)
	for _, table := range []string{"users", "auth_events", "installation"} {
		require.Zero(t, countRows(t, pool, table))
	}
	execSQL(t, pool, `DROP TRIGGER reject_event ON auth_events`)
	lock, err := pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = lock.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, MigrationLock)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	start := time.Now()
	require.Equal(t, platform.DependencyUnavailable, i.Attempt(ctx).State)
	cancel()
	require.Less(t, time.Since(start), time.Second)
	require.NoError(t, lock.Rollback(t.Context()))
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	require.Equal(t, platform.Ready, i.Check(t.Context()).State)
	// Cached worker success must not override fresh connectivity or schema.
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	require.Equal(t, platform.DependencyUnavailable, i.Check(ctx).State)
	execSQL(t, pool, `UPDATE goose_db_version SET checksum='changed' WHERE version_id=1`)
	require.Equal(t, platform.SchemaError, i.Check(t.Context()).State)
}

func TestUnexpectedUserDoesNotBecomeAdministrator(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	path, _ := testSecret(t)
	execSQL(t, pool, `INSERT INTO users(id,username,password_hash,role) VALUES ($1,'member','not-a-hash','member')`, randomTestID(t))
	i := NewInitializer(pool, "admin", path)
	require.Equal(t, platform.BootstrapFailed, i.Attempt(t.Context()).State)
	require.Zero(t, countRows(t, pool, "installation"))
	require.Equal(t, 1, countRows(t, pool, "users"))
}

func TestWorkerNoticesRepairedSecretWithoutRestart(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	require.NoError(t, os.Chmod(path, 0644))
	i := NewInitializer(pool, "personal-admin", path)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); i.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool { return i.Check(t.Context()).State == platform.BootstrapFailed }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, os.Chmod(path, 0600))
	start := time.Now()
	require.Eventually(t, func() bool { return i.Check(t.Context()).Ready() }, 35*time.Second, 100*time.Millisecond)
	require.GreaterOrEqual(t, time.Since(start), 29*time.Second)
	require.Equal(t, 1, countRows(t, pool, "users"))
}

func TestWorkerCancellationWhileInitializationLockIsHeld(t *testing.T) {
	pool := testPool(t)
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, MigrationLock)
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	i := NewInitializer(pool, "", "")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); i.Run(ctx) }()
	require.Eventually(t, func() bool {
		var waiting bool
		err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event='advisory')`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting)
		return err == nil && waiting
	}, time.Second, time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not cancel")
	}
	require.Less(t, time.Since(start), time.Second)
}

func TestInterruptedBootstrapConnectionRollsBackAndRetries(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	require.NoError(t, Migrate(t.Context(), pool))
	execSQL(t, pool, `CREATE FUNCTION delay_bootstrap_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(10); RETURN NEW; END $$;
		CREATE TRIGGER delay_bootstrap_event BEFORE INSERT ON auth_events FOR EACH ROW EXECUTE FUNCTION delay_bootstrap_event()`)
	i := NewInitializer(pool, "personal-admin", path)
	done := make(chan platform.Readiness, 1)
	go func() { done <- i.Attempt(t.Context()) }()
	var pid int
	require.Eventually(t, func() bool {
		// Only this test's random application_name may be interrupted.
		err := pool.QueryRow(t.Context(), `SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event='PgSleep'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&pid)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	var stopped bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&stopped))
	require.True(t, stopped)
	select {
	case result := <-done:
		require.Equal(t, platform.DependencyUnavailable, result.State)
	case <-time.After(time.Second):
		t.Fatal("interrupted transaction did not return")
	}
	for _, table := range []string{"users", "auth_events", "installation"} {
		require.Zero(t, countRows(t, pool, table))
	}
	execSQL(t, pool, `DROP TRIGGER delay_bootstrap_event ON auth_events`)
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	for _, table := range []string{"users", "auth_events", "installation"} {
		require.Equal(t, 1, countRows(t, pool, table))
	}
}

func TestInitializationWorkerRecoversFromDatabaseOutage(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	cfg := pool.Config()
	upstream := net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port)))
	gate, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var available atomic.Bool
	var workers sync.WaitGroup
	var mu sync.Mutex
	var connections []net.Conn
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			client, err := gate.Accept()
			if err != nil {
				return
			}
			if !available.Load() {
				_ = client.Close()
				continue
			}
			server, err := net.DialTimeout("tcp", upstream, time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			mu.Lock()
			connections = append(connections, client, server)
			mu.Unlock()
			workers.Add(2)
			go func() { defer workers.Done(); _, _ = io.Copy(server, client); _ = server.Close() }()
			go func() { defer workers.Done(); _, _ = io.Copy(client, server); _ = client.Close() }()
		}
	}()
	t.Cleanup(func() {
		_ = gate.Close()
		<-accepted
		mu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	address := gate.Addr().(*net.TCPAddr)
	cfg.ConnConfig.Host = "127.0.0.1"
	cfg.ConnConfig.Port = uint16(address.Port)
	proxyPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(proxyPool.Close)
	i := NewInitializer(proxyPool, "personal-admin", path)
	require.Equal(t, platform.DependencyUnavailable, i.Check(t.Context()).State)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); i.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool { return i.state.Load() == platform.DependencyUnavailable }, 2*time.Second, 10*time.Millisecond)
	available.Store(true)
	require.Eventually(t, func() bool { return i.Check(t.Context()).Ready() }, 6*time.Second, 20*time.Millisecond)
	require.Equal(t, 1, countRows(t, pool, "users"))
}
