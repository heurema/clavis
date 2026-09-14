package database

import (
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Migration 006 replaces the provider check on an installation that already
// stores connections: the existing rows survive the replacement, and only
// afterwards can the third provider be stored.
func TestVictoriaLogsProviderMigrationKeepsExistingConnections(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "006_victorialogs_provider.sql")
	// A later migration must not be applied ahead of the one under test: the
	// ledger would then be ahead of the manifest and fail closed.
	delete(previous, "007_groups.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	insert := `INSERT INTO connections (id, name, title, provider, target, secret_envelope)
		VALUES ($1::uuid, $2, $2, $3, '{"url":"http://source:9428","auth":"none"}'::jsonb, 'sealed')`
	execSQL(t, pool, insert, randomTestID(t), "metrics-before", auth.ProviderVictoriaMetrics)
	execSQL(t, pool, insert, randomTestID(t), "postgres-before", auth.ProviderPostgreSQL)
	// The previous release's check refuses the third provider.
	_, err := pool.Exec(t.Context(), insert, randomTestID(t), "logs-before", auth.ProviderVictoriaLogs)
	var refused *pgconn.PgError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "23514", refused.Code)

	require.NoError(t, migrateFS(t.Context(), pool, embeddedMapFS(t)))
	require.Equal(t, 2, countRows(t, pool, "connections"), "existing rows survive the replaced check")
	execSQL(t, pool, insert, randomTestID(t), "logs-after", auth.ProviderVictoriaLogs)
	require.Equal(t, 3, countRows(t, pool, "connections"))
	_, err = pool.Exec(t.Context(), insert, randomTestID(t), "unknown-after", "loki")
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "23514", refused.Code, "the check still closes the registry")
}
