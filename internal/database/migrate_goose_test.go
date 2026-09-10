package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"testing"
	"testing/fstest"
	"time"

	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	goosedb "github.com/pressly/goose/v3/database"
	"github.com/stretchr/testify/require"
)

// Arbitrary filesystem migrations are a test seam, not a production entrypoint.
func migrateFS(ctx context.Context, pool *pgxpool.Pool, root fs.FS) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	migrations, err := migrationManifest(root)
	if err != nil {
		return err
	}
	return migrateValidated(ctx, pool, root, migrations)
}

func TestGooseOwnsVersioningAndSQLParsing(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	root, err := fs.Sub(migrationFiles, "migrations")
	require.NoError(t, err)
	db := stdlib.OpenDBFromPool(pool)
	defer func() { require.NoError(t, db.Close()) }()
	// An unmodified Goose PostgreSQL provider recognizes the real Goose ledger.
	provider, err := goose.NewProvider(goose.DialectPostgres, db, root, goose.WithDisableGlobalRegistry(true))
	require.NoError(t, err)
	version, err := provider.GetDBVersion(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, version)
	pending, err := provider.HasPending(t.Context())
	require.NoError(t, err)
	require.False(t, pending)
	var legacy bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&legacy))
	require.False(t, legacy)

	initial, err := fs.ReadFile(root, "001_initial.sql")
	require.NoError(t, err)
	changed := fstest.MapFS{"001_initial.sql": {Data: append(append([]byte{}, initial...), []byte("\n-- changed after application\n")...)}}
	require.ErrorIs(t, migrateFS(t.Context(), pool, changed), errSchema)
	require.Equal(t, 2, countRows(t, pool, "goose_db_version"))
	migrations := fstest.MapFS{
		"001_initial.sql": {Data: initial},
		"002_parser.sql": {Data: []byte(`-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION goose_parser_probe() RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
    RETURN 42;
END;
$$;
-- +goose StatementEnd
-- +goose Down
SELECT deliberate_down_must_not_run();
`)},
	}
	require.NoError(t, migrateFS(t.Context(), pool, migrations))
	require.NoError(t, migrateFS(t.Context(), pool, migrations))
	var value int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT goose_parser_probe()`).Scan(&value))
	require.Equal(t, 42, value)
	require.Equal(t, 3, countRows(t, pool, "goose_db_version"))
	// The old binary must not accept the newer ledger.
	require.ErrorIs(t, Migrate(t.Context(), pool), errSchema)
}

func TestGooseManifestRejectsNontransactionalAndMutableInputs(t *testing.T) {
	for _, directive := range []string{
		"-- +goose NO TRANSACTION",
		"-- +goose no transaction",
		"-- +goose NO TRANSACTION --",
		"-- +goose ENVSUB ON",
		"-- +goose envsub on",
	} {
		t.Run(directive, func(t *testing.T) {
			files := fstest.MapFS{
				"001_bad.sql": {Data: []byte(directive + "\n-- +goose Up\nSELECT 1;")},
			}
			_, err := migrationManifest(files)
			require.ErrorIs(t, err, errSchema)
			// Rejection must precede even opening the database adapter.
			require.ErrorIs(t, migrateFS(t.Context(), nil, files), errSchema)
		})
	}
	for _, files := range []fstest.MapFS{
		{},
		{"invalid.sql": {Data: []byte("-- +goose Up\nSELECT 1;")}},
		{"001_a.sql": {}, "1_b.sql": {}},
	} {
		_, err := migrationManifest(files)
		require.ErrorIs(t, err, errSchema)
		require.ErrorIs(t, migrateFS(t.Context(), nil, files), errSchema)
	}
}

func TestGooseChecksumFailureRollsBackDDLAndVersion(t *testing.T) {
	pool := testPool(t)
	bad := fstest.MapFS{"001_bad.sql": {Data: []byte("-- +goose Up\nSELECT deliberate_missing_function();")}}
	require.Error(t, migrateFS(t.Context(), pool, bad))
	// Goose's zero version is allowed to survive a failed first migration, but
	// no successful application version may survive either SQL or checksum failure.
	require.Equal(t, 1, countRows(t, pool, "goose_db_version"))
	execSQL(t, pool, `CREATE FUNCTION reject_checksum() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'reject checksum'; END $$;
		CREATE TRIGGER reject_checksum BEFORE UPDATE ON goose_db_version
		FOR EACH ROW EXECUTE FUNCTION reject_checksum()`)
	require.Error(t, Migrate(t.Context(), pool))
	require.Equal(t, 1, countRows(t, pool, "goose_db_version"))
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('users') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	execSQL(t, pool, `DROP TRIGGER reject_checksum ON goose_db_version`)
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, 2, countRows(t, pool, "goose_db_version"))
}

func TestGooseRejectsExperimentalAndCorruptedLedgers(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		pool := testPool(t)
		execSQL(t, pool, `CREATE TABLE schema_migrations(version integer, checksum text)`)
		require.ErrorIs(t, Migrate(t.Context(), pool), errSchema)
		require.Equal(t, platform.SchemaError, NewInitializer(pool, "", "").Check(t.Context()).State)
		var present bool
		require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&present))
		require.False(t, present)
	})
	for name, corruption := range map[string]string{
		"empty ledger":            `DELETE FROM goose_db_version`,
		"missing checksum column": `ALTER TABLE goose_db_version DROP COLUMN checksum`,
		"missing checksum":        `UPDATE goose_db_version SET checksum=NULL WHERE version_id=1`,
		"missing zero":            `DELETE FROM goose_db_version WHERE version_id=0`,
		"modified zero":           `UPDATE goose_db_version SET checksum='modified' WHERE version_id=0`,
		"missing zero checksum":   `UPDATE goose_db_version SET checksum=NULL WHERE version_id=0`,
		"unapplied zero":          `UPDATE goose_db_version SET is_applied=false WHERE version_id=0`,
		"reordered zero":          `UPDATE goose_db_version SET id=100 WHERE version_id=0`,
		"down record":             `UPDATE goose_db_version SET is_applied=false WHERE version_id=1`,
		"duplicate":               `INSERT INTO goose_db_version(version_id,is_applied,checksum) SELECT version_id,is_applied,checksum FROM goose_db_version WHERE version_id=1`,
		"unknown version":         `UPDATE goose_db_version SET version_id=99 WHERE version_id=1`,
		"negative version":        `UPDATE goose_db_version SET version_id=-1 WHERE version_id=1`,
	} {
		t.Run(name, func(t *testing.T) {
			pool := testPool(t)
			require.NoError(t, Migrate(t.Context(), pool))
			execSQL(t, pool, corruption)
			db := migrationDB(pool)
			defer func() { require.NoError(t, db.Close()) }()
			base, err := goosedb.NewStore(goosedb.DialectPostgres, goose.DefaultTablename)
			require.NoError(t, err)
			store := &checksumStore{Store: base, migrations: embeddedMigrations()}
			counted := &countingMigrationDB{DBTxConn: db}
			got, err := store.ListMigrations(t.Context(), counted)
			require.Error(t, err)
			require.Nil(t, got)
			require.Equal(t, []string{migrationRowsSQL}, counted.queries)
			err = Migrate(t.Context(), pool)
			require.Error(t, err)
			require.True(t, schemaFailure(err))
			require.Equal(t, platform.SchemaError, NewInitializer(pool, "", "").Check(t.Context()).State)
		})
	}
}

func TestGooseReadinessIsReadOnlyBeforeAndAfterMigration(t *testing.T) {
	pool := testPool(t)
	i := NewInitializer(pool, "", "")
	require.Equal(t, platform.Initializing, i.Check(t.Context()).State)
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	require.Equal(t, platform.SetupRequired, i.Attempt(t.Context()).State)
	config := pool.Config()
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readOnly, err := pgxpool.NewWithConfig(t.Context(), config)
	require.NoError(t, err)
	defer readOnly.Close()
	checker := NewInitializer(readOnly, "", "")
	checker.state.Store(platform.SetupRequired)
	require.Equal(t, platform.SetupRequired, checker.Check(t.Context()).State)
	require.Equal(t, 2, countRows(t, pool, "goose_db_version"))
	require.Zero(t, countRows(t, pool, "users"))
}

func TestGooseCancellationRollsBackAndUnblocksBootstrap(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	initial, err := migrationFiles.ReadFile("migrations/001_initial.sql")
	require.NoError(t, err)
	migrations := fstest.MapFS{
		"001_initial.sql": {Data: initial},
		"002_slow.sql": {Data: []byte(`-- +goose Up
CREATE TABLE interrupted_migration(id integer);
SELECT pg_sleep(10);
`)},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	migrated := make(chan error, 1)
	go func() { migrated <- migrateFS(ctx, pool, migrations) }()
	require.Eventually(t, func() bool {
		var sleeping bool
		err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event='PgSleep')`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&sleeping)
		return err == nil && sleeping
	}, 3*time.Second, 10*time.Millisecond)

	path, _ := testSecret(t)
	i := NewInitializer(pool, "admin", path)
	bootstrapped := make(chan platform.State, 1)
	go func() { bootstrapped <- i.bootstrap(t.Context()) }()
	require.Eventually(t, func() bool {
		var waiting bool
		err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event='advisory')`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	require.Zero(t, countRows(t, pool, "users"))
	cancel()
	select {
	case err := <-migrated:
		require.Error(t, err)
		require.False(t, schemaFailure(err))
	case <-time.After(3 * time.Second):
		t.Fatal("Goose did not stop after cancellation")
	}
	select {
	case state := <-bootstrapped:
		require.Equal(t, platform.Ready, state)
	case <-time.After(3 * time.Second):
		t.Fatal("Goose leaked its session lock")
	}
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('interrupted_migration') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	require.Equal(t, 2, countRows(t, pool, "goose_db_version"))
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, platform.Ready, i.Check(t.Context()).State)
}

func TestGoosePreparationFailuresAreSchemaErrorsWithoutPartialDDL(t *testing.T) {
	for name, body := range map[string]string{
		"missing Up":         "CREATE TABLE malformed_probe(id integer);",
		"unterminated block": "-- +goose Up\n-- +goose StatementBegin\nCREATE TABLE malformed_probe(id integer);",
	} {
		t.Run(name, func(t *testing.T) {
			pool := testPool(t)
			files := fstest.MapFS{
				"001_valid.sql": {Data: []byte("-- +goose Up\nCREATE TABLE earlier_probe(id integer);")},
				"002_bad.sql":   {Data: []byte(body)},
			}
			err := migrateFS(t.Context(), pool, files)
			require.ErrorIs(t, err, errSchema)
			require.True(t, schemaFailure(err))
			// Goose prepares all pending SQL before executing even the valid
			// earlier migration. Only its initial zero ledger row can survive.
			require.Equal(t, 1, countRows(t, pool, "goose_db_version"))
			for _, table := range []string{"earlier_probe", "malformed_probe"} {
				var present bool
				require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present))
				require.False(t, present)
			}
		})
	}
}

func TestGoosePreparationClassificationBoundary(t *testing.T) {
	config, err := pgconn.ParseConfig("host=localhost sslmode=disable")
	require.NoError(t, err)
	config.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection unavailable")
	}
	_, connectErr := pgconn.ConnectConfig(t.Context(), config)
	require.Error(t, connectErr)
	sources := []*goose.Source{{Type: goose.TypeSQL, Version: 2, Path: "002_bad.sql"}}
	wrap := func(version int, path string, cause error) error {
		return fmt.Errorf("failed to prepare migration (type:sql,version:%d): %w", version,
			fmt.Errorf("failed to parse %s: %w", path, cause))
	}
	bad := wrap(2, "002_bad.sql", errors.New("arbitrary parser detail"))
	require.True(t, goosePreparationFailure(bad, sources))
	require.True(t, goosePreparationFailure(errors.Join(bad, errors.New("cleanup")), sources))
	for _, err := range []error{
		nil, errors.New("unrelated"), errors.New(bad.Error()),
		wrap(3, "002_bad.sql", errors.New("wrong version")),
		wrap(2, "003_bad.sql", errors.New("wrong filename")),
		fmt.Errorf("lookalike: %w", bad),
		fmt.Errorf("failed to prepare migration (type:sql,version:2): %w", errors.New("no parse wrapper")),
	} {
		require.False(t, goosePreparationFailure(err, sources), "%v", err)
		require.False(t, schemaFailure(err), "%v", err)
	}
	transient := []error{
		context.Canceled, context.DeadlineExceeded, driver.ErrBadConn, sql.ErrConnDone,
		io.EOF, io.ErrUnexpectedEOF,
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
		connectErr,
	}
	for _, code := range []string{"08006", "40001", "53300", "55P03", "57014", "58030"} {
		transient = append(transient, &pgconn.PgError{Code: code})
	}
	for _, cause := range transient {
		for _, err := range []error{cause, wrap(2, "002_bad.sql", cause), errors.Join(bad, cause)} {
			require.False(t, goosePreparationFailure(err, sources))
			require.False(t, schemaFailure(err))
		}
	}
	require.True(t, schemaFailure(&pgconn.PgError{Code: "42601"}))
}

func TestGooseTransientInterruptionsRollback(t *testing.T) {
	for _, mode := range []string{"deadline", "connection lost"} {
		t.Run(mode, func(t *testing.T) {
			pool := testPool(t)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- migrateFS(ctx, pool, fstest.MapFS{
					"001_slow.sql": {Data: []byte("-- +goose Up\nCREATE TABLE transient_probe(id integer);\nSELECT pg_sleep(10);")},
				})
			}()
			var pid int
			require.Eventually(t, func() bool {
				err := pool.QueryRow(t.Context(), `SELECT pid FROM pg_stat_activity
					WHERE application_name=$1 AND wait_event='PgSleep'`,
					pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&pid)
				return err == nil
			}, time.Second, 10*time.Millisecond)
			if mode == "connection lost" {
				execSQL(t, pool, `SELECT pg_terminate_backend($1)`, pid)
			}
			select {
			case err := <-done:
				require.Error(t, err)
				require.False(t, schemaFailure(err))
			case <-time.After(3 * time.Second):
				t.Fatal("interrupted migration did not finish")
			}
			require.Equal(t, 1, countRows(t, pool, "goose_db_version"))
			var present bool
			require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('transient_probe') IS NOT NULL`).Scan(&present))
			require.False(t, present)
			require.NoError(t, Migrate(t.Context(), pool))
		})
	}
}

func TestGooseFailedUnlockDiscardsNativeConnection(t *testing.T) {
	pool := testPool(t)
	db := migrationDB(pool)
	defer func() { require.NoError(t, db.Close()) }()
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	var pid int
	require.NoError(t, conn.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid))
	locker := migrationLocker{}
	require.NoError(t, locker.SessionLock(t.Context(), conn))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.Error(t, locker.SessionUnlock(ctx, conn))
	err = conn.Close()
	require.True(t, err == nil || errors.Is(err, sql.ErrConnDone))
	// A separate native pool must be able to acquire the same key. This fails
	// with OpenDBFromPool: automatic driver discard can return a locked session
	// to that pool before the locker can close it.
	check, cancelCheck := context.WithTimeout(t.Context(), time.Second)
	defer cancelCheck()
	tx, err := pool.Begin(check)
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	_, err = tx.Exec(check, `SELECT pg_advisory_xact_lock($1)`, MigrationLock)
	require.NoError(t, err)
	var oldSession bool
	require.NoError(t, tx.QueryRow(check, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)`, pid).Scan(&oldSession))
	require.False(t, oldSession)
}
