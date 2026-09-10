package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	goosedb "github.com/pressly/goose/v3/database"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// MigrationLock serializes Goose's session and native bootstrap transactions.
const MigrationLock int64 = 0x434c415649530001

var errSchema = errors.New("platform schema unavailable or incompatible")

type migration struct {
	version int
	sum     string
}

func embeddedMigrations() []migration {
	root, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		panic(err)
	}
	migrations, err := migrationManifest(root)
	if err != nil {
		panic(err)
	}
	return migrations
}

// The manifest is an integrity policy, not a migration planner. Goose discovers,
// parses, orders and executes these same files and owns the sole version ledger.
func migrationManifest(root fs.FS) ([]migration, error) {
	names, err := fs.Glob(root, "*.sql")
	if err != nil {
		return nil, err
	}
	var migrations []migration
	for _, name := range names {
		version, err := goose.NumericComponent(name)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid migration name", errSchema)
		}
		data, err := fs.ReadFile(root, name)
		if err != nil {
			return nil, err
		}
		// A nontransactional migration could execute DDL before Store.Insert can
		// reject it. Refuse the directive before giving any SQL to Goose.
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "+goose") {
				continue
			}
			// Match Goose's case-insensitive annotation normalization. Also
			// prohibit environment substitution: a checksum must identify the
			// SQL being executed, not a template with process-specific values.
			annotation := strings.TrimSpace(strings.Replace(
				strings.ReplaceAll(line, "--", ""), "+goose", "", 1))
			if strings.EqualFold(annotation, "NO TRANSACTION") || strings.EqualFold(annotation, "ENVSUB ON") {
				return nil, fmt.Errorf("%w: nontransactional or environment-dependent migration", errSchema)
			}
		}
		migrations = append(migrations, migration{int(version), fmt.Sprintf("%x", sha256.Sum256(data))})
	}
	slices.SortFunc(migrations, func(a, b migration) int { return a.version - b.version })
	for n, m := range migrations {
		if m.version <= 0 || (n > 0 && migrations[n-1].version == m.version) {
			return nil, errSchema
		}
	}
	if len(migrations) == 0 {
		return nil, errSchema
	}
	return migrations, nil
}

// rollback uses the operation context. pgx closes the connection if rollback
// cannot complete, rather than returning an open transaction to the pool.
func rollback(ctx context.Context, tx pgx.Tx) { _ = tx.Rollback(ctx) }

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	root, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	return migrateFS(ctx, pool, root)
}

func migrateFS(ctx context.Context, pool *pgxpool.Pool, root fs.FS) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	migrations, err := migrationManifest(root)
	if err != nil {
		return err
	}
	store, err := goosedb.NewStore(goosedb.DialectPostgres, goose.DefaultTablename)
	if err != nil {
		return err
	}
	db := migrationDB(pool)
	defer func() { _ = db.Close() }()
	provider, err := goose.NewProvider(goose.DialectCustom, db, root,
		goose.WithStore(&checksumStore{Store: store, migrations: migrations}),
		goose.WithSessionLocker(migrationLocker{}),
		goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return fmt.Errorf("%w: %w", errSchema, err)
	}
	_, err = provider.Up(ctx)
	if goosePreparationFailure(err, provider.ListSources()) {
		return fmt.Errorf("%w: %w", errSchema, err)
	}
	return err
}

// Goose 3.28 exposes neither a public SQL validation API nor typed preparation
// errors. Recognize only its two exact wrapping layers for a discovered SQL
// source, never parser-detail text. Real-provider tests pin this compatibility
// boundary; revisit it when upgrading Goose. Cleanup can join another error.
func goosePreparationFailure(err error, sources []*goose.Source) bool {
	if err == nil || retryableMigrationError(err) {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if goosePreparationFailure(child, sources) {
				return true
			}
		}
		return false
	}
	parsed := errors.Unwrap(err)
	if parsed == nil {
		return false
	}
	cause := errors.Unwrap(parsed)
	if cause == nil {
		return false
	}
	for _, source := range sources {
		if source.Type == goose.TypeSQL &&
			err.Error() == fmt.Sprintf("failed to prepare migration (type:sql,version:%d): %s", source.Version, parsed.Error()) &&
			parsed.Error() == fmt.Sprintf("failed to parse %s: %s", source.Path, cause.Error()) {
			return true
		}
	}
	return false
}

func retryableMigrationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || pgconn.SafeToRetry(err) {
		return true
	}
	switch e := err.(type) {
	case net.Error:
		return true
	case *pgconn.ConnectError:
		return true
	case *pgconn.PgError:
		for _, class := range []string{"08", "40", "53", "55", "57", "58"} {
			if strings.HasPrefix(e.Code, class) {
				return true
			}
		}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if retryableMigrationError(child) {
				return true
			}
		}
		return false
	}
	if child := errors.Unwrap(err); child != nil {
		return retryableMigrationError(child)
	}
	return false
}

func migrationDB(pool *pgxpool.Pool) *sql.DB {
	// Do not use OpenDBFromPool here: database/sql can automatically discard a
	// canceled driver connection before the locker gets a chance to unlock it.
	// That adapter releases to pgxpool rather than closing the native session.
	// A dedicated adapter guarantees discard closes the session and its locks.
	db := stdlib.OpenDB(*pool.Config().ConnConfig.Copy())
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	return db
}

func schemaFailure(err error) bool {
	if retryableMigrationError(err) {
		return false
	}
	if errors.Is(err, errSchema) {
		return true
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return false
	}
	// Other SQL failures are a schema failure, not a database outage.
	return true
}
