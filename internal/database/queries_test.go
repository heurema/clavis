package database

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestGeneratedQueriesStayOnNativeTransaction(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	queries := sqlc.New(pool)
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	qtx := queries.WithTx(tx)
	id, sessionID := randomTestID(t), randomTestID(t)
	require.NoError(t, qtx.CreateInitialAdministrator(t.Context(), sqlc.CreateInitialAdministratorParams{
		ID: id, Username: "query-admin", PasswordHash: "fixture-only-not-a-password-hash",
	}))
	user, err := qtx.FindLoginUser(t.Context(), "query-admin")
	require.NoError(t, err)
	require.Equal(t, id, user.ID)
	require.Equal(t, "admin", user.Role)
	digest := sha256.Sum256([]byte("fixture-only-session"))
	expires, err := qtx.CreateSession(t.Context(), sqlc.CreateSessionParams{
		ID: sessionID, UserID: id, Kind: "cli", TokenDigest: digest[:], TtlSeconds: 3600,
	})
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(time.Hour), expires, 2*time.Second)
	require.NoError(t, qtx.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{
		ID: randomTestID(t), Action: "login", Outcome: "invalid_credentials",
	}))
	require.NoError(t, qtx.MarkInstallationInitialized(t.Context()))
	require.NoError(t, qtx.LockMutationUsers(t.Context(), sqlc.LockMutationUsersParams{ActorID: id}))
	current, err := qtx.RecheckSession(t.Context(), sqlc.RecheckSessionParams{
		SessionID: sessionID, UserID: id, Kind: "cli",
	})
	require.NoError(t, err)
	require.Equal(t, expires, current.ExpiresAt)
	// Independent fixture assertions prove writes cannot escape WithTx into pool.
	for _, table := range []string{"users", "sessions", "auth_events", "installation"} {
		require.Zero(t, countRows(t, pool, table))
	}
	require.NoError(t, tx.Rollback(t.Context()))
	_, err = queries.FindLoginUser(t.Context(), "query-admin")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	state, err := queries.BootstrapState(t.Context())
	require.NoError(t, err)
	require.False(t, state.Initialized)
	require.False(t, state.HasUsers)
	for _, table := range []string{"sessions", "auth_events", "installation"} {
		require.Zero(t, countRows(t, pool, table))
	}
}

func TestGeneratedAdvisoryLockRespectsTransactionAndContext(t *testing.T) {
	pool := testPool(t)
	first, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), first)
	require.NoError(t, sqlc.New(first).LockTransaction(t.Context(), limitLock))
	second, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), second)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	require.Error(t, sqlc.New(second).LockTransaction(ctx, limitLock))
	require.Less(t, time.Since(start), time.Second)
	rollback(t.Context(), second)
	require.NoError(t, first.Rollback(t.Context()))
	third, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), third)
	require.NoError(t, sqlc.New(third).LockTransaction(t.Context(), limitLock))
}

func TestGeneratedReadinessChecksEveryApplicationColumn(t *testing.T) {
	for table, columns := range map[string][]string{
		"users":        {"id", "username", "password_hash", "role", "disabled", "created_at", "updated_at"},
		"sessions":     {"id", "token_digest", "user_id", "kind", "created_at", "expires_at", "revoked_at"},
		"auth_events":  {"id", "actor_id", "target_id", "session_id", "action", "outcome", "created_at"},
		"login_limits": {"key", "failures", "expires_at"},
		"installation": {"singleton", "initialized_at"},
	} {
		for _, column := range columns {
			t.Run(table+"/"+column, func(t *testing.T) {
				pool := testPool(t)
				require.NoError(t, Migrate(t.Context(), pool))
				i := NewInitializer(pool, "", "")
				require.Equal(t, platform.Initializing, i.Check(t.Context()).State)
				// Fault injection only: production readiness must never repair columns.
				execSQL(t, pool, "ALTER TABLE "+pgx.Identifier{table}.Sanitize()+
					" DROP COLUMN "+pgx.Identifier{column}.Sanitize()+" CASCADE")
				require.Equal(t, platform.SchemaError, i.Check(t.Context()).State)
			})
		}
	}
}

func TestGeneratedLimitReleasePreservesNewWindow(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	queries := sqlc.New(pool)
	key := sha256.Sum256([]byte("fixture-only-window"))
	previous, err := queries.ReserveLoginLimit(t.Context(), key[:])
	require.NoError(t, err)
	// Fault injection advances the window without a five-minute sleep.
	execSQL(t, pool, `UPDATE login_limits SET expires_at=clock_timestamp()-interval '1 second' WHERE key=$1`, key[:])
	current, err := queries.ReserveLoginLimit(t.Context(), key[:])
	require.NoError(t, err)
	require.NotEqual(t, previous, current)
	require.NoError(t, queries.ReleaseLoginLimit(t.Context(), sqlc.ReleaseLoginLimitParams{Key: key[:], ExpiresAt: previous}))
	limit, err := queries.GetLoginLimit(t.Context(), key[:])
	require.NoError(t, err)
	require.EqualValues(t, 1, limit.Failures)
	require.True(t, limit.Active)
	for range 2 {
		require.NoError(t, queries.ReleaseLoginLimit(t.Context(), sqlc.ReleaseLoginLimitParams{Key: key[:], ExpiresAt: current}))
	}
	limit, err = queries.GetLoginLimit(t.Context(), key[:])
	require.NoError(t, err)
	require.Zero(t, limit.Failures)
}
