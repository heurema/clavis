package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// pgx tracing injects faults at the actual production query boundary without
// adding a production hook or substituting a fake transaction for PostgreSQL.
type bootstrapQueryTrace struct {
	start func(context.Context, *pgx.Conn, string) context.Context
	end   func(*pgx.Conn, string, error)
}

type bootstrapTraceSQLKey struct{}

func (tr *bootstrapQueryTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if tr.start != nil {
		ctx = tr.start(ctx, conn, data.SQL)
	}
	return context.WithValue(ctx, bootstrapTraceSQLKey{}, data.SQL)
}

func (tr *bootstrapQueryTrace) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if tr.end != nil {
		tr.end(conn, ctx.Value(bootstrapTraceSQLKey{}).(string), data.Err)
	}
}

func bootstrapTracedPool(t *testing.T, pool *pgxpool.Pool, tracer *bootstrapQueryTrace) *pgxpool.Pool {
	t.Helper()
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = tracer
	traced, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(traced.Close)
	return traced
}

func TestBootstrapLedgerReadFailureRecoversInRunningWorker(t *testing.T) {
	for _, fault := range []string{"connection-terminated", "canceled", "deadline"} {
		t.Run(fault, func(t *testing.T) {
			pool := testPool(t)
			require.NoError(t, Migrate(t.Context(), pool))
			path, _ := testSecret(t)
			var lockedPID atomic.Uint32
			var injected atomic.Bool
			injectionResult := make(chan error, 1)
			queryResult := make(chan error, 1)
			tracer := &bootstrapQueryTrace{
				end: func(conn *pgx.Conn, sql string, err error) {
					if strings.HasPrefix(sql, "-- name: LockTransaction ") && err == nil {
						lockedPID.Store(conn.PgConn().PID())
					}
					if sql == migrationRowsSQL && injected.Load() {
						select {
						case queryResult <- err:
						default:
						}
					}
				},
				start: func(ctx context.Context, conn *pgx.Conn, sql string) context.Context {
					// Goose must have finished and bootstrap must have successfully
					// acquired its transaction lock. Interrupt the ledger SELECT,
					// before BootstrapState or any credential or account operation.
					if sql != migrationRowsSQL || lockedPID.Load() != conn.PgConn().PID() || !injected.CompareAndSwap(false, true) {
						return ctx
					}
					switch fault {
					case "connection-terminated":
						var stopped bool
						err := pool.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, conn.PgConn().PID()).Scan(&stopped)
						if err == nil && !stopped {
							err = errors.New("owned bootstrap backend was not terminated")
						}
						injectionResult <- err
					case "canceled":
						canceled, cancel := context.WithCancel(ctx)
						cancel()
						injectionResult <- nil
						return canceled
					case "deadline":
						expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
						cancel()
						injectionResult <- nil
						return expired
					}
					return ctx
				},
			}
			i := NewInitializer(bootstrapTracedPool(t, pool, tracer), "personal-admin", path)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan struct{})
			go func() { defer close(done); i.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done })
			select {
			case err := <-injectionResult:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("bootstrap ledger fault window was not reached")
			}
			select {
			case err := <-queryResult:
				require.Error(t, err, "the actual ledger read must fail")
				require.False(t, schemaFailure(err))
			case <-ctx.Done():
				t.Fatal("ledger read did not finish")
			}
			require.Eventually(t, func() bool { return i.state.Load() == platform.DependencyUnavailable }, time.Second, time.Millisecond)
			for _, table := range []string{"users", "installation"} {
				require.Zero(t, countRows(t, pool, table))
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("same initialization worker did not recover")
			}
			require.Equal(t, platform.Ready, i.state.Load())
			require.Equal(t, platform.Ready, i.Check(t.Context()).State)
			for _, table := range []string{"users", "installation"} {
				require.Equal(t, 1, countRows(t, pool, table))
			}
		})
	}
}

func TestBootstrapLedgerSchemaFaultRemainsTerminal(t *testing.T) {
	for _, fault := range []string{
		`UPDATE goose_db_version SET checksum='incompatible' WHERE version_id=1`,
		`ALTER TABLE goose_db_version DROP COLUMN checksum`,
		`DELETE FROM goose_db_version WHERE version_id=1`,
	} {
		t.Run(fault, func(t *testing.T) {
			pool := testPool(t)
			require.NoError(t, Migrate(t.Context(), pool))
			path, _ := testSecret(t)
			var injected atomic.Bool
			result := make(chan error, 1)
			tracer := &bootstrapQueryTrace{end: func(_ *pgx.Conn, sql string, err error) {
				if strings.HasPrefix(sql, "-- name: LockTransaction ") && err == nil && injected.CompareAndSwap(false, true) {
					_, err := pool.Exec(t.Context(), fault)
					result <- err
				}
			}}
			i := NewInitializer(bootstrapTracedPool(t, pool, tracer), "personal-admin", path)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			i.Run(ctx)
			require.NoError(t, ctx.Err(), "schema failures must stop, not retry until cancellation")
			require.True(t, injected.Load())
			require.NoError(t, <-result)
			require.Equal(t, platform.SchemaError, i.state.Load())
			for _, table := range []string{"users", "installation"} {
				require.Zero(t, countRows(t, pool, table))
			}
		})
	}
}

func TestBootstrapValidationFailsSafelyOnEachAttempt(t *testing.T) {
	for _, failure := range []string{"bad-filename", "relative-path", "permissions", "username", "unsafe-password", "directory", "fifo", "unexpected-user"} {
		t.Run(failure, func(t *testing.T) {
			pool := testPool(t)
			path, password := testSecret(t)
			username := "private-bootstrap-user"
			input := path
			existingUsers := 0
			require.NoError(t, Migrate(t.Context(), pool))
			switch failure {
			case "bad-filename":
				require.NoError(t, os.Remove(path))
			case "relative-path":
				input = "private-relative-secret"
			case "permissions":
				require.NoError(t, os.Chmod(path, 0644))
			case "username":
				username = "PRIVATE INVALID USERNAME"
			case "unsafe-password":
				require.NoError(t, os.WriteFile(path, []byte(string(password)+"\x00"), 0600))
			case "directory":
				input = t.TempDir()
			case "fifo":
				input = filepath.Join(t.TempDir(), "private-fifo")
				require.NoError(t, unix.Mkfifo(input, 0600))
			case "unexpected-user":
				execSQL(t, pool, `INSERT INTO users(id,username,password_hash,role) VALUES ($1,'existing-member','private-existing-hash','member')`, randomTestID(t))
				existingUsers = 1
			}
			i := NewInitializer(pool, username, input)
			digest := sha256.Sum256([]byte(password))
			for attempt := 1; attempt <= 2; attempt++ {
				require.Equal(t, platform.BootstrapFailed, i.Attempt(t.Context()).State)
				require.Equal(t, existingUsers, countRows(t, pool, "users"))
				require.Zero(t, countRows(t, pool, "installation"))
				for range 3 {
					require.Equal(t, platform.BootstrapFailed, i.Check(t.Context()).State)
				}
				// The reported state never carries a supplied identity, path,
				// secret or stored hash, on this or any earlier attempt.
				safe, err := json.Marshal(i.Check(t.Context()))
				require.NoError(t, err)
				for _, value := range []string{username, input, string(password),
					hex.EncodeToString(digest[:]), "private-existing-hash"} {
					require.NotContains(t, string(safe), value, attempt)
				}
			}
			if existingUsers != 0 {
				var role, hash string
				require.NoError(t, pool.QueryRow(t.Context(), `SELECT role, password_hash FROM users`).Scan(&role, &hash))
				require.Equal(t, "member", role)
				require.Equal(t, "private-existing-hash", hash)
				return
			}
			// Repair only deployment input, then retry in this same initializer.
			require.NoError(t, os.WriteFile(path, []byte(password), 0600))
			require.NoError(t, os.Chmod(path, 0600))
			i.username, i.passwordFile = "personal-admin", path
			require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
			require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
			require.Equal(t, 1, countRows(t, pool, "users"))
			require.Equal(t, 1, countRows(t, pool, "installation"))
			var role string
			require.NoError(t, pool.QueryRow(t.Context(), `SELECT role FROM users`).Scan(&role))
			require.Equal(t, "admin", role)
		})
	}
}

func TestBootstrapMissingSetupAndReadOnlyChecksWriteNothing(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	for _, input := range [][2]string{{"", ""}, {"", "/private/absent-secret"}, {"INVALID USERNAME", ""}} {
		i := NewInitializer(pool, input[0], input[1])
		require.Equal(t, platform.Initializing, i.Check(t.Context()).State)
		for range 2 {
			require.Equal(t, platform.SetupRequired, i.Attempt(t.Context()).State)
			require.Equal(t, platform.SetupRequired, i.Check(t.Context()).State)
		}
	}
	i := NewInitializer(pool, "INVALID USERNAME", "/private/absent-secret")
	for range 3 {
		require.Equal(t, platform.Initializing, i.Check(t.Context()).State)
	}
	for _, table := range []string{"users", "installation"} {
		require.Zero(t, countRows(t, pool, table))
	}
}

func TestInitializedBootstrapDoesNotReadInputs(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	require.Equal(t, platform.Ready, NewInitializer(pool, "personal-admin", path).Attempt(t.Context()).State)
	// A queued FIFO payload is observable if consumed. Keeping an O_RDWR handle
	// open avoids blocking the test, and the nonblocking read verifies the bytes
	// remain untouched after both initialized Attempt and read-only Check.
	fifo := filepath.Join(t.TempDir(), "obsolete-secret")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, unix.Close(fd)) }()
	payload := []byte("private-obsolete-bootstrap-input")
	n, err := unix.Write(fd, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	for _, input := range [][2]string{{"INVALID USERNAME", "/private/absent"}, {"changed-admin", fifo}, {"", ""}} {
		i := NewInitializer(pool, input[0], input[1])
		require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
		require.Equal(t, platform.Ready, i.Check(t.Context()).State)
	}
	buffer := make([]byte, len(payload))
	n, err = unix.Read(fd, buffer)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, buffer)
	require.Equal(t, 1, countRows(t, pool, "users"))
	require.Equal(t, 1, countRows(t, pool, "installation"))
}
