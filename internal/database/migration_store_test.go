package database

import (
	"context"
	"database/sql"
	"testing"
	"testing/fstest"

	"github.com/pressly/goose/v3"
	goosedb "github.com/pressly/goose/v3/database"
	"github.com/stretchr/testify/require"
)

// Count every query, not just migrationRowsSQL: delegating to Goose's default
// ListMigrations must not accidentally introduce a second ledger read.
type countingMigrationDB struct {
	goosedb.DBTxConn
	queries []string
}

func (db *countingMigrationDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	db.queries = append(db.queries, query)
	return db.DBTxConn.QueryContext(ctx, query, args...)
}

func TestChecksumStoreSingleReadMatchesGoose(t *testing.T) {
	pool := testPool(t)
	db := migrationDB(pool)
	defer func() { require.NoError(t, db.Close()) }()
	// Sparse versions ensure results are actual versions, not prefix indexes.
	files := fstest.MapFS{
		"1_first.sql":  {Data: []byte("-- +goose Up\nSELECT 1;\n")},
		"2_second.sql": {Data: []byte("-- +goose Up\nSELECT 2;\n")},
		"10_tenth.sql": {Data: []byte("-- +goose Up\nSELECT 10;\n")},
	}
	manifest, err := migrationManifest(files)
	require.NoError(t, err)
	base, err := goosedb.NewStore(goosedb.DialectPostgres, goose.DefaultTablename)
	require.NoError(t, err)
	store := &checksumStore{Store: base, migrations: manifest}
	provider, err := goose.NewProvider(goose.DialectCustom, db, files,
		goose.WithStore(store), goose.WithSessionLocker(migrationLocker{}),
		goose.WithDisableGlobalRegistry(true))
	require.NoError(t, err)
	standard, err := goose.NewProvider(goose.DialectPostgres, db, files,
		goose.WithDisableGlobalRegistry(true))
	require.NoError(t, err)
	// Genuine provider initialization creates and stamps the zero row.
	version, err := provider.GetDBVersion(t.Context())
	require.NoError(t, err)
	require.Zero(t, version)

	for n, versions := range [][]int64{{0}, {1, 0}, {2, 1, 0}, {10, 2, 1, 0}} {
		counted := &countingMigrationDB{DBTxConn: db}
		got, err := store.ListMigrations(t.Context(), counted)
		require.NoError(t, err)
		require.Equal(t, []string{migrationRowsSQL}, counted.queries)
		want, err := base.ListMigrations(t.Context(), db)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Len(t, got, len(versions))
		for i, version := range versions {
			require.Equal(t, &goosedb.ListMigrationsResult{Version: version, IsApplied: true}, got[i])
		}

		// The same prefix count serves native read-only readiness without DTOs.
		tx, err := pool.Begin(t.Context())
		require.NoError(t, err)
		count, err := schemaVersions(t.Context(), tx, manifest)
		require.NoError(t, err)
		require.Equal(t, n, count)
		require.NoError(t, tx.Rollback(t.Context()))
		for _, p := range []*goose.Provider{provider, standard} {
			version, err := p.GetDBVersion(t.Context())
			require.NoError(t, err)
			require.Equal(t, versions[0], version)
			pending, err := p.HasPending(t.Context())
			require.NoError(t, err)
			require.Equal(t, n < len(manifest), pending)
		}
		// DTO ownership is private to each call, just like Goose's store.
		got[0].Version = -1
		got[0].IsApplied = false
		counted.queries = nil
		again, err := store.ListMigrations(t.Context(), counted)
		require.NoError(t, err)
		require.Equal(t, want, again)
		require.Equal(t, []string{migrationRowsSQL}, counted.queries)
		if n < len(manifest) {
			applied, err := provider.UpByOne(t.Context())
			require.NoError(t, err)
			require.EqualValues(t, manifest[n].version, applied.Source.Version)
		}
	}
	applied, err := provider.Up(t.Context())
	require.NoError(t, err)
	require.Empty(t, applied)

	// A canceled read returns no DTOs and cannot fall back to another query.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	counted := &countingMigrationDB{DBTxConn: db}
	got, err := store.ListMigrations(ctx, counted)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, got)
	require.Equal(t, []string{migrationRowsSQL}, counted.queries)

	// The checksum policy intentionally rejects an empty ledger even though
	// the default store returns an empty list. Never synthesize a missing zero.
	execSQL(t, pool, `DELETE FROM goose_db_version`)
	want, err := base.ListMigrations(t.Context(), db)
	require.NoError(t, err)
	require.Empty(t, want)
	counted.queries = nil
	got, err = store.ListMigrations(t.Context(), counted)
	require.ErrorIs(t, err, errSchema)
	require.Nil(t, got)
	require.Equal(t, []string{migrationRowsSQL}, counted.queries)
}

func TestMigrateUsesPrivateEmbeddedManifestAndFreshInjectedFiles(t *testing.T) {
	pool := testPool(t)
	copy := embeddedMigrations()
	copy[0] = migration{version: -1, sum: "caller mutation"}
	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, Migrate(t.Context(), pool))

	initial, err := migrationFiles.ReadFile("migrations/001_initial.sql")
	require.NoError(t, err)
	files := fstest.MapFS{"001_initial.sql": {Data: initial}}
	require.NoError(t, migrateFS(t.Context(), pool, files))
	files["001_initial.sql"].Data = append(initial, []byte("\n-- changed\n")...)
	require.ErrorIs(t, migrateFS(t.Context(), pool, files), errSchema)
	// A changed injected filesystem must not poison production's cached data.
	require.NoError(t, Migrate(t.Context(), pool))
}
