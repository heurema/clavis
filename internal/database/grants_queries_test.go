package database

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
)

func TestGeneratedGrantQueriesAndConstraints(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	queries := sqlc.New(pool)
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), tx)
	qtx := queries.WithTx(tx)

	user := func(name string) string {
		t.Helper()
		row, err := qtx.InsertUser(t.Context(), sqlc.InsertUserParams{ID: randomTestID(t), Username: name, PasswordHash: "fixture"})
		require.NoError(t, err)
		return row.ID
	}
	connection := func(name, labels string) string {
		t.Helper()
		row, err := qtx.InsertConnection(t.Context(), sqlc.InsertConnectionParams{
			ID: randomTestID(t), Name: name, Title: "Title", Provider: "postgresql",
			Target: []byte(`{"host":"db"}`), Labels: []byte(labels), SecretEnvelope: "v1:fixture",
			StatementTimeoutMs: 30000, MaxRows: 1000, MaxBytes: 1048576,
		})
		require.NoError(t, err)
		return row.ID
	}
	admin, alice, bob := user("admin"), user("alice"), user("bob")
	payments := connection("payments-prod", `{"env":"prod","service":"payments"}`)
	metrics := connection("metrics-prod", `{"env":"prod","team":"sre"}`)
	stage := connection("payments-stage", `{"env":"stage","service":"payments"}`)

	// The users constraint refuses a UUID-shaped username at the storage layer.
	_, err = tx.Exec(t.Context(), "SAVEPOINT username")
	require.NoError(t, err)
	_, err = qtx.InsertUser(t.Context(), sqlc.InsertUserParams{ID: randomTestID(t), Username: "abcdef12-3456-4890-abcd-ef1234567890", PasswordHash: "fixture"})
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)
	require.Equal(t, "users_username_check", pgErr.ConstraintName)
	_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT username")
	require.NoError(t, err)

	byName, err := qtx.FindUserIDByUsername(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, alice, byName)
	_, err = qtx.FindUserIDByUsername(t.Context(), "carol")
	require.ErrorIs(t, err, pgx.ErrNoRows)

	inserted, err := qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: alice, ConnectionID: payments, CreatedBy: admin})
	require.NoError(t, err)
	require.Equal(t, alice, inserted.UserID)
	require.Equal(t, payments, inserted.ConnectionID)
	require.Equal(t, admin, inserted.CreatedBy)
	// A repeated grant is a no-op that returns no row rather than an error.
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: alice, ConnectionID: payments, CreatedBy: admin})
	require.ErrorIs(t, err, pgx.ErrNoRows)
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: alice, ConnectionID: metrics, CreatedBy: admin})
	require.NoError(t, err)
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: bob, ConnectionID: payments, CreatedBy: admin})
	require.NoError(t, err)
	// Foreign keys refuse unknown parties; a savepoint isolates the failures.
	for _, params := range []sqlc.InsertGrantParams{
		{UserID: randomTestID(t), ConnectionID: payments, CreatedBy: admin},
		{UserID: alice, ConnectionID: randomTestID(t), CreatedBy: admin},
		{UserID: alice, ConnectionID: stage, CreatedBy: randomTestID(t)},
	} {
		_, err := tx.Exec(t.Context(), "SAVEPOINT fk")
		require.NoError(t, err)
		_, err = qtx.InsertGrant(t.Context(), params)
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23503", pgErr.Code)
		_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT fk")
		require.NoError(t, err)
	}

	found, err := qtx.FindGrant(t.Context(), sqlc.FindGrantParams{UserID: alice, ConnectionID: payments})
	require.NoError(t, err)
	require.Equal(t, "alice", found.Username)
	require.Equal(t, "payments-prod", found.ConnectionName)
	require.Equal(t, "admin", found.CreatedByUsername)
	require.Equal(t, inserted.CreatedAt, found.CreatedAt)
	_, err = qtx.FindGrant(t.Context(), sqlc.FindGrantParams{UserID: bob, ConnectionID: metrics})
	require.ErrorIs(t, err, pgx.ErrNoRows)

	all, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, all, 3)
	require.Equal(t, []string{"alice", "alice", "bob"}, []string{all[0].Username, all[1].Username, all[2].Username})
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-prod"}, []string{all[0].ConnectionName, all[1].ConnectionName, all[2].ConnectionName})
	byUser, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{UserID: &alice, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, byUser, 2)
	byConnection, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{ConnectionID: &payments, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, byConnection, 2)
	both, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{UserID: &bob, ConnectionID: &payments, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, both, 1)
	limited, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{LimitRows: 2})
	require.NoError(t, err)
	require.Len(t, limited, 2)

	count, err := qtx.CountConnectionGrants(t.Context(), payments)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	count, err = qtx.CountConnectionGrants(t.Context(), stage)
	require.NoError(t, err)
	require.Zero(t, count)

	// Member views join through grants and honour the selector semantics.
	granted, err := qtx.ListGrantedConnections(t.Context(), sqlc.ListGrantedConnectionsParams{UserID: alice, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, granted, 2)
	require.Equal(t, "metrics-prod", granted[0].Name)
	require.Equal(t, "payments-prod", granted[1].Name)
	granted, err = qtx.ListGrantedConnections(t.Context(), sqlc.ListGrantedConnectionsParams{
		UserID: alice, Contains: []byte(`{"service":"payments"}`), LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, granted, 1)
	require.Equal(t, "payments-prod", granted[0].Name)
	granted, err = qtx.ListGrantedConnections(t.Context(), sqlc.ListGrantedConnectionsParams{
		UserID: alice, Excludes: []byte(`[{"service":"payments"}]`), Keys: []string{"team"}, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, granted, 1)
	require.Equal(t, "metrics-prod", granted[0].Name)
	granted, err = qtx.ListGrantedConnections(t.Context(), sqlc.ListGrantedConnectionsParams{UserID: bob, Keys: []string{"team"}, LimitRows: 10})
	require.NoError(t, err)
	require.Empty(t, granted)
	names, err := qtx.ListGrantedConnectionNames(t.Context(), sqlc.ListGrantedConnectionNamesParams{UserID: alice, LimitRows: 1})
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, names)
	byID, err := qtx.FindGrantedConnectionByID(t.Context(), sqlc.FindGrantedConnectionByIDParams{UserID: alice, ID: payments})
	require.NoError(t, err)
	require.Equal(t, "payments-prod", byID.Name)
	_, err = qtx.FindGrantedConnectionByID(t.Context(), sqlc.FindGrantedConnectionByIDParams{UserID: alice, ID: stage})
	require.ErrorIs(t, err, pgx.ErrNoRows)
	byGrantedName, err := qtx.FindGrantedConnectionByName(t.Context(), sqlc.FindGrantedConnectionByNameParams{UserID: bob, Name: "payments-prod"})
	require.NoError(t, err)
	require.Equal(t, payments, byGrantedName.ID)
	_, err = qtx.FindGrantedConnectionByName(t.Context(), sqlc.FindGrantedConnectionByNameParams{UserID: bob, Name: "metrics-prod"})
	require.ErrorIs(t, err, pgx.ErrNoRows)

	// A connection with grants cannot be deleted at the storage layer either.
	_, err = tx.Exec(t.Context(), "SAVEPOINT del")
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), "DELETE FROM connections WHERE id = $1::uuid", payments)
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23503", pgErr.Code)
	_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT del")
	require.NoError(t, err)

	deleted, err := qtx.DeleteGrant(t.Context(), sqlc.DeleteGrantParams{UserID: alice, ConnectionID: payments})
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	deleted, err = qtx.DeleteGrant(t.Context(), sqlc.DeleteGrantParams{UserID: alice, ConnectionID: payments})
	require.NoError(t, err)
	require.Zero(t, deleted)

	// Grant events carry the user target and the connection column; the
	// allowlists accept the new actions and outcome and refuse near misses.
	for _, event := range []struct{ action, outcome string }{
		{"grant.create", "success"}, {"grant.revoke", "success"}, {"grants.list", "forbidden"},
		{"connection.get", "connection_disabled"},
	} {
		require.NoError(t, qtx.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{
			ID: randomTestID(t), ActorID: admin, TargetID: alice, ConnectionID: payments, Action: event.action, Outcome: event.outcome,
		}), event.action+"/"+event.outcome)
	}
	var connectionID *string
	require.NoError(t, tx.QueryRow(t.Context(), `SELECT connection_id::text FROM auth_events WHERE action = 'grant.create'`).Scan(&connectionID))
	require.NotNil(t, connectionID)
	require.Equal(t, payments, *connectionID)
	require.NoError(t, qtx.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "login", Outcome: "success"}))
	require.NoError(t, tx.QueryRow(t.Context(), `SELECT connection_id::text FROM auth_events WHERE action = 'login'`).Scan(&connectionID))
	require.Nil(t, connectionID)
	for _, event := range []struct{ action, outcome string }{
		{"grant.delete", "success"}, {"grants.create", "success"}, {"grant.create", "grant_exists"},
	} {
		_, err := tx.Exec(t.Context(), "SAVEPOINT ev")
		require.NoError(t, err)
		err = qtx.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: event.action, Outcome: event.outcome})
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code, event.action+"/"+event.outcome)
		_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT ev")
		require.NoError(t, err)
	}
}

func TestGrantMigrationAppliesToInitializedInstallation(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "004_grants.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	queries := sqlc.New(pool)
	// The previous release stored events without the connection column.
	execSQL(t, pool, `INSERT INTO auth_events (id, action, outcome) VALUES ($1::uuid, 'connection.check', 'check_failed')`, randomTestID(t))
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	require.Equal(t, platform.Initializing, NewInitializer(pool, "", "").Check(t.Context()).State)

	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, 1, countRows(t, pool, "auth_events"))
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.True(t, present)
	var connectionID *string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT connection_id::text FROM auth_events`).Scan(&connectionID))
	require.Nil(t, connectionID, "existing rows keep a null connection")
	require.NoError(t, queries.InsertAuthEvent(t.Context(), sqlc.InsertAuthEventParams{ID: randomTestID(t), Action: "grant.create", Outcome: "success"}))
	_, err := queries.InsertUser(t.Context(), sqlc.InsertUserParams{ID: randomTestID(t), Username: "abcdef12-3456-4890-abcd-ef1234567890", PasswordHash: "fixture"})
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)
	require.Equal(t, platform.SetupRequired, NewInitializer(pool, "", "").Attempt(t.Context()).State)
}

func TestGrantMigrationFailsClosedOnUUIDShapedUsername(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "004_grants.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	// The previous release's pattern admitted a lowercase UUID as a username;
	// the constraint replacement must refuse to apply while one exists, and
	// the whole migration rolls back with it.
	execSQL(t, pool, `INSERT INTO users (id, username, password_hash, role) VALUES ($1::uuid, 'abcdef12-3456-4890-abcd-ef1234567890', 'fixture', 'member')`, randomTestID(t))
	execSQL(t, pool, `INSERT INTO auth_events (id, action, outcome) VALUES ($1::uuid, 'login', 'success')`, randomTestID(t))
	ledger := countRows(t, pool, "goose_db_version")
	require.Error(t, Migrate(t.Context(), pool))
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.False(t, present, "a failed 004 leaves no grants table")
	require.Equal(t, ledger, countRows(t, pool, "goose_db_version"))
	require.Equal(t, 1, countRows(t, pool, "auth_events"))
	var columns int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_name = 'auth_events' AND column_name = 'connection_id'`).Scan(&columns))
	require.Zero(t, columns)

	execSQL(t, pool, `UPDATE users SET username = 'renamed-operator'`)
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, ledger+1, countRows(t, pool, "goose_db_version"))
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.True(t, present)
}
