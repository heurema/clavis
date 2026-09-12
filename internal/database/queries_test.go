package database

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

func TestGeneratedUserAdministrationQueriesAndEventAllowlist(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	queries := sqlc.New(pool)
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	qtx := queries.WithTx(tx)
	adminID, memberID := randomTestID(t), randomTestID(t)
	require.NoError(t, qtx.CreateInitialAdministrator(t.Context(), sqlc.CreateInitialAdministratorParams{
		ID: adminID, Username: "query-admin", PasswordHash: "fixture-only-not-a-password-hash",
	}))
	created, err := qtx.InsertUser(t.Context(), sqlc.InsertUserParams{
		ID: memberID, Username: "alice", PasswordHash: "fixture-only-hash-one",
	})
	require.NoError(t, err)
	require.Equal(t, memberID, created.ID)
	require.Equal(t, "member", created.Role)
	require.False(t, created.Disabled)
	require.WithinDuration(t, time.Now(), created.CreatedAt, 2*time.Second)
	_, err = qtx.InsertUser(t.Context(), sqlc.InsertUserParams{ID: randomTestID(t), Username: "alice", PasswordHash: "x"})
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	// A failed statement aborts the transaction; the remaining checks use a fresh one.
	require.NoError(t, tx.Rollback(t.Context()))
	tx, err = pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	qtx = queries.WithTx(tx)
	require.NoError(t, qtx.CreateInitialAdministrator(t.Context(), sqlc.CreateInitialAdministratorParams{
		ID: adminID, Username: "query-admin", PasswordHash: "fixture-only-not-a-password-hash",
	}))
	_, err = qtx.InsertUser(t.Context(), sqlc.InsertUserParams{ID: memberID, Username: "alice", PasswordHash: "fixture-only-hash-one"})
	require.NoError(t, err)
	_, err = qtx.InsertUser(t.Context(), sqlc.InsertUserParams{ID: randomTestID(t), Username: "bob", PasswordHash: "fixture-only-hash-two"})
	require.NoError(t, err)

	exists, err := qtx.UsernameExists(t.Context(), "alice")
	require.NoError(t, err)
	require.True(t, exists)
	exists, err = qtx.UsernameExists(t.Context(), "Alice")
	require.NoError(t, err)
	require.False(t, exists)
	found, err := qtx.FindUser(t.Context(), memberID)
	require.NoError(t, err)
	require.Equal(t, "alice", found.Username)
	_, err = qtx.FindUser(t.Context(), randomTestID(t))
	require.ErrorIs(t, err, pgx.ErrNoRows)

	listed, err := qtx.ListUsers(t.Context(), 2)
	require.NoError(t, err)
	require.Len(t, listed, 2)
	require.Equal(t, "alice", listed[0].Username)
	require.Equal(t, "bob", listed[1].Username)
	listed, err = qtx.ListUsers(t.Context(), 10)
	require.NoError(t, err)
	require.Len(t, listed, 3)
	require.Equal(t, "query-admin", listed[2].Username)

	admins, err := qtx.CountEnabledAdministrators(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, admins)
	promoted, err := qtx.SetUserRole(t.Context(), sqlc.SetUserRoleParams{ID: memberID, Role: "admin"})
	require.NoError(t, err)
	require.Equal(t, "admin", promoted.Role)
	admins, err = qtx.CountEnabledAdministrators(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 2, admins)
	blocked, err := qtx.SetUserDisabled(t.Context(), sqlc.SetUserDisabledParams{ID: memberID, Disabled: true})
	require.NoError(t, err)
	require.True(t, blocked.Disabled)
	admins, err = qtx.CountEnabledAdministrators(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, admins)
	require.NoError(t, qtx.SetUserPasswordHash(t.Context(), sqlc.SetUserPasswordHashParams{ID: memberID, PasswordHash: "fixture-only-hash-three"}))
	login, err := qtx.FindLoginUser(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, "fixture-only-hash-three", login.PasswordHash)
	require.True(t, login.Disabled)
	var updated time.Time
	require.NoError(t, tx.QueryRow(t.Context(), `SELECT updated_at FROM users WHERE id=$1`, memberID).Scan(&updated))
	require.True(t, updated.After(created.CreatedAt))

	for _, action := range []string{
		"bootstrap", "login", "logout", "revoke", "user.create", "user.block", "user.unblock",
		"user.reset_password", "user.promote", "user.demote", "users.list",
	} {
		for _, outcome := range []string{"success", "forbidden", "username_taken", "last_administrator", "self_target", "user_not_found"} {
			require.NoError(t, qtx.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{
				ID: randomTestID(t), ActorID: adminID, TargetID: memberID, Action: action, Outcome: outcome,
			}), action+"/"+outcome)
		}
	}
	require.NoError(t, tx.Rollback(t.Context()))
	for _, event := range []sqlc.InsertAuthEventParams{
		{Action: "user.delete", Outcome: "success"},
		{Action: "user.create", Outcome: "duplicate"},
	} {
		err := queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: event.Action, Outcome: event.Outcome})
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code, event.Action+"/"+event.Outcome)
	}
	require.Zero(t, countRows(t, pool, "auth_events"))
}

func TestEventAllowlistMigrationAppliesToInitializedInstallation(t *testing.T) {
	pool := testPool(t)
	// A previous release migrated only 001 and recorded old-style events.
	previous := embeddedMapFS(t)
	delete(previous, "002_user_administration.sql")
	delete(previous, "003_connections.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	queries := sqlc.New(pool)
	require.NoError(t, queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "login", Outcome: "success"}))
	err := queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "user.create", Outcome: "success"})
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)

	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, 1, countRows(t, pool, "auth_events"))
	require.NoError(t, queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "user.create", Outcome: "username_taken"}))
	require.Equal(t, 2, countRows(t, pool, "auth_events"))
	var name string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT conname FROM pg_constraint WHERE conname='auth_events_action_check'`).Scan(&name))
	require.Equal(t, "auth_events_action_check", name)
}

func TestGeneratedConnectionQueriesAndEventAllowlist(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	queries := sqlc.New(pool)
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	qtx := queries.WithTx(tx)
	id := randomTestID(t)
	insert := func(name, labels string) sqlc.Connection {
		t.Helper()
		row, err := qtx.InsertConnection(t.Context(), sqlc.InsertConnectionParams{
			ID: randomTestID(t), Name: name, Title: "Title", Provider: "postgresql",
			Target: []byte(`{"host":"db"}`), Labels: []byte(labels), SecretEnvelope: "v1:fixture",
			StatementTimeoutMs: 30000, MaxRows: 1000, MaxBytes: 1048576,
		})
		require.NoError(t, err)
		return row
	}
	created, err := qtx.InsertConnection(t.Context(), sqlc.InsertConnectionParams{
		ID: id, Name: "payments-prod", Title: "Payments", Description: "d", Scope: "s", Provider: "postgresql",
		Target: []byte(`{"host":"db","port":"5432"}`), Labels: []byte(`{"env":"prod","service":"payments"}`),
		SecretEnvelope: "v1:fixture-envelope", StatementTimeoutMs: 30000, MaxRows: 1000, MaxBytes: 1048576,
	})
	require.NoError(t, err)
	require.Equal(t, id, created.ID)
	require.True(t, created.Enabled)
	require.Nil(t, created.LastCheckOutcome)
	require.Nil(t, created.LastCheckAt)
	require.JSONEq(t, `{"env":"prod","service":"payments"}`, string(created.Labels))
	insert("payments-stage", `{"env":"stage","service":"payments"}`)
	insert("metrics-prod", `{"env":"prod","team":"sre"}`)

	byName, err := qtx.FindConnectionByName(t.Context(), "payments-prod")
	require.NoError(t, err)
	require.Equal(t, created.ID, byName.ID)
	_, err = qtx.FindConnectionByID(t.Context(), randomTestID(t))
	require.ErrorIs(t, err, pgx.ErrNoRows)
	exists, err := qtx.ConnectionNameExists(t.Context(), "payments-prod")
	require.NoError(t, err)
	require.True(t, exists)

	names := func(rows []sqlc.Connection) []string {
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.Name)
		}
		return out
	}
	list := func(contains, excludes string, keys []string, limit int32) []string {
		t.Helper()
		rows, err := qtx.ListConnections(t.Context(), sqlc.ListConnectionsParams{
			Contains: []byte(contains), Excludes: []byte(excludes), Keys: keys, LimitRows: limit,
		})
		require.NoError(t, err)
		return names(rows)
	}
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-stage"}, list(`{}`, `[]`, []string{}, 10))
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, list(`{"env":"prod"}`, `[]`, []string{}, 10))
	require.Equal(t, []string{"payments-prod"}, list(`{"env":"prod"}`, `[{"team":"sre"}]`, []string{}, 10))
	require.Equal(t, []string{"metrics-prod"}, list(`{}`, `[]`, []string{"team"}, 10))
	require.Equal(t, []string{"payments-prod", "payments-stage"}, list(`{}`, `[]`, []string{"env", "service"}, 10))
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, list(`{}`, `[]`, []string{}, 2))
	// NULL inputs behave like empty ones rather than silently matching nothing.
	rows, err := qtx.ListConnections(t.Context(), sqlc.ListConnectionsParams{LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, rows, 3)

	name := "payments-prod-reporting"
	timeout := int32(60000)
	updated, err := qtx.UpdateConnection(t.Context(), sqlc.UpdateConnectionParams{
		ID: id, Name: &name, StatementTimeoutMs: &timeout, Labels: []byte(`{"env":"prod"}`),
	})
	require.NoError(t, err)
	require.Equal(t, "payments-prod-reporting", updated.Name)
	require.Equal(t, "Payments", updated.Title, "absent fields are untouched")
	require.EqualValues(t, 60000, updated.StatementTimeoutMs)
	require.JSONEq(t, `{"env":"prod"}`, string(updated.Labels))
	require.Equal(t, "v1:fixture-envelope", updated.SecretEnvelope)
	require.True(t, updated.UpdatedAt.After(created.UpdatedAt))

	checked, err := qtx.SetConnectionCheck(t.Context(), sqlc.SetConnectionCheckParams{ID: id, Outcome: "reachable"})
	require.NoError(t, err)
	require.NotNil(t, checked.LastCheckOutcome)
	require.Equal(t, "reachable", *checked.LastCheckOutcome)
	require.NotNil(t, checked.LastCheckAt)
	secret, err := qtx.SetConnectionSecret(t.Context(), sqlc.SetConnectionSecretParams{ID: id, SecretEnvelope: "v1:replaced"})
	require.NoError(t, err)
	require.Nil(t, secret.LastCheckOutcome, "replacing credentials clears the last check")
	require.Nil(t, secret.LastCheckAt)
	require.Equal(t, "v1:replaced", secret.SecretEnvelope)

	deleted, err := qtx.DeleteConnection(t.Context(), id)
	require.NoError(t, err)
	require.Zero(t, deleted, "an enabled connection is never deleted by the query")
	disabled, err := qtx.SetConnectionEnabled(t.Context(), sqlc.SetConnectionEnabledParams{ID: id, Enabled: false})
	require.NoError(t, err)
	require.False(t, disabled.Enabled)
	deleted, err = qtx.DeleteConnection(t.Context(), id)
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	_, err = qtx.FindConnectionByID(t.Context(), id)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	for _, action := range []string{
		"connection.create", "connection.update", "connection.set_credentials", "connection.enable",
		"connection.disable", "connection.delete", "connection.check", "connection.get", "connections.list",
	} {
		for _, outcome := range []string{"success", "forbidden", "connection_exists", "connection_not_found", "connection_in_use", "credentials_unavailable", "check_failed"} {
			require.NoError(t, qtx.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{
				ID: randomTestID(t), Action: action, Outcome: outcome,
			}), action+"/"+outcome)
		}
	}
	require.NoError(t, tx.Rollback(t.Context()))

	var pgErr *pgconn.PgError
	for name, params := range map[string]sqlc.InsertConnectionParams{
		"bad name":          {ID: randomTestID(t), Name: "Bad", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:x", StatementTimeoutMs: 30000, MaxRows: 1, MaxBytes: 1024},
		"uuid-shaped name":  {ID: randomTestID(t), Name: "abcdef12-3456-4890-abcd-ef1234567890", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:x", StatementTimeoutMs: 30000, MaxRows: 1, MaxBytes: 1024},
		"unknown provider":  {ID: randomTestID(t), Name: "ok-name", Title: "t", Provider: "mysql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:x", StatementTimeoutMs: 30000, MaxRows: 1, MaxBytes: 1024},
		"timeout ceiling":   {ID: randomTestID(t), Name: "ok-name", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:x", StatementTimeoutMs: 120001, MaxRows: 1, MaxBytes: 1024},
		"rows ceiling":      {ID: randomTestID(t), Name: "ok-name", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:x", StatementTimeoutMs: 30000, MaxRows: 100001, MaxBytes: 1024},
		"bytes floor":       {ID: randomTestID(t), Name: "ok-name", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:x", StatementTimeoutMs: 30000, MaxRows: 1, MaxBytes: 1023},
		"empty envelope":    {ID: randomTestID(t), Name: "ok-name", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "", StatementTimeoutMs: 30000, MaxRows: 1, MaxBytes: 1024},
		"labels not object": {ID: randomTestID(t), Name: "ok-name", Title: "t", Provider: "postgresql", Target: []byte(`{}`), Labels: []byte(`[]`), SecretEnvelope: "v1:x", StatementTimeoutMs: 30000, MaxRows: 1, MaxBytes: 1024},
	} {
		_, err := queries.InsertConnection(t.Context(), params)
		require.ErrorAs(t, err, &pgErr, name)
		require.Equal(t, "23514", pgErr.Code, name)
	}
	err = queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "connection.rotate", Outcome: "success"})
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)
	require.Zero(t, countRows(t, pool, "connections"))
	require.Zero(t, countRows(t, pool, "auth_events"))
}

func TestConnectionMigrationAppliesToInitializedInstallation(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "003_connections.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	queries := sqlc.New(pool)
	require.NoError(t, queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "user.create", Outcome: "success"}))
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('connections') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	// A ledger behind the embedded manifest is a pending migration, not an
	// incompatible schema; readiness stays closed until it is applied.
	require.Equal(t, platform.Initializing, NewInitializer(pool, "", "").Check(t.Context()).State)

	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, 1, countRows(t, pool, "auth_events"))
	require.NoError(t, queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "connection.check", Outcome: "check_failed"}))
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('connections') IS NOT NULL`).Scan(&present))
	require.True(t, present)
	// Attempt applies nothing further and observes the fresh, uninitialized schema.
	require.Equal(t, platform.SetupRequired, NewInitializer(pool, "", "").Attempt(t.Context()).State)
}
