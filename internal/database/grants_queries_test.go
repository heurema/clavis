package database

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
)

// ref is the pointer form every nullable recipient parameter takes.
func ref(value string) *string { return &value }

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
	finance, err := qtx.InsertGroup(t.Context(), sqlc.InsertGroupParams{
		ID: randomTestID(t), Name: "finance-managers", Description: "Finance managers",
	})
	require.NoError(t, err)

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

	inserted, err := qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: &alice, ConnectionID: payments, CreatedBy: admin})
	require.NoError(t, err)
	require.Equal(t, alice, *inserted.UserID)
	require.Nil(t, inserted.GroupID, "a user grant names no group")
	require.Equal(t, payments, inserted.ConnectionID)
	require.Equal(t, admin, inserted.CreatedBy)
	// A repeated grant is a no-op that returns no row rather than an error;
	// the partial unique index is the arbiter for each recipient kind.
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: &alice, ConnectionID: payments, CreatedBy: admin})
	require.ErrorIs(t, err, pgx.ErrNoRows)
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: &alice, ConnectionID: metrics, CreatedBy: admin})
	require.NoError(t, err)
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{UserID: &bob, ConnectionID: payments, CreatedBy: admin})
	require.NoError(t, err)
	group, err := qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{GroupID: &finance.ID, ConnectionID: payments, CreatedBy: admin})
	require.NoError(t, err)
	require.Nil(t, group.UserID)
	require.Equal(t, finance.ID, *group.GroupID)
	// A group grant on a connection a member already holds directly is a
	// distinct row, not a conflict.
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{GroupID: &finance.ID, ConnectionID: payments, CreatedBy: admin})
	require.ErrorIs(t, err, pgx.ErrNoRows)

	// Foreign keys refuse unknown parties; a savepoint isolates the failures.
	for name, params := range map[string]sqlc.InsertGrantParams{
		"unknown user":       {UserID: ref(randomTestID(t)), ConnectionID: payments, CreatedBy: admin},
		"unknown connection": {UserID: &alice, ConnectionID: randomTestID(t), CreatedBy: admin},
		"unknown actor":      {UserID: &alice, ConnectionID: stage, CreatedBy: randomTestID(t)},
		"unknown group":      {GroupID: ref(randomTestID(t)), ConnectionID: stage, CreatedBy: admin},
	} {
		_, err := tx.Exec(t.Context(), "SAVEPOINT fk")
		require.NoError(t, err)
		_, err = qtx.InsertGrant(t.Context(), params)
		require.ErrorAs(t, err, &pgErr, name)
		require.Equal(t, "23503", pgErr.Code, name)
		_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT fk")
		require.NoError(t, err)
	}
	// Exactly one recipient: neither and both are refused by the check.
	for name, params := range map[string]sqlc.InsertGrantParams{
		"no recipient":   {ConnectionID: stage, CreatedBy: admin},
		"two recipients": {UserID: &alice, GroupID: &finance.ID, ConnectionID: stage, CreatedBy: admin},
	} {
		_, err := tx.Exec(t.Context(), "SAVEPOINT recipient")
		require.NoError(t, err)
		_, err = qtx.InsertGrant(t.Context(), params)
		require.ErrorAs(t, err, &pgErr, name)
		require.Equal(t, "23514", pgErr.Code, name)
		require.Equal(t, "grants_one_recipient", pgErr.ConstraintName, name)
		_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT recipient")
		require.NoError(t, err)
	}

	found, err := qtx.FindGrant(t.Context(), sqlc.FindGrantParams{UserID: &alice, ConnectionID: payments})
	require.NoError(t, err)
	require.Equal(t, "alice", *found.Username)
	require.Nil(t, found.GroupName)
	require.Equal(t, "payments-prod", found.ConnectionName)
	require.Equal(t, "admin", found.CreatedByUsername)
	require.Equal(t, inserted.CreatedAt, found.CreatedAt)
	// The recipient is part of the key: the group's grant on the same
	// connection is a different row, and a user reference never finds it.
	foundGroup, err := qtx.FindGrant(t.Context(), sqlc.FindGrantParams{GroupID: &finance.ID, ConnectionID: payments})
	require.NoError(t, err)
	require.Nil(t, foundGroup.Username)
	require.Equal(t, "finance-managers", *foundGroup.GroupName)
	_, err = qtx.FindGrant(t.Context(), sqlc.FindGrantParams{UserID: &bob, ConnectionID: metrics})
	require.ErrorIs(t, err, pgx.ErrNoRows)

	all, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, all, 4)
	// User grants order before group grants, then by recipient and connection.
	require.Equal(t, []string{"alice", "alice", "bob"},
		[]string{*all[0].Username, *all[1].Username, *all[2].Username})
	require.Nil(t, all[3].Username)
	require.Equal(t, "finance-managers", *all[3].GroupName)
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-prod", "payments-prod"},
		[]string{all[0].ConnectionName, all[1].ConnectionName, all[2].ConnectionName, all[3].ConnectionName})
	byUser, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{UserID: &alice, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, byUser, 2)
	byGroup, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{GroupID: &finance.ID, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, byGroup, 1)
	byConnection, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{ConnectionID: &payments, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, byConnection, 3)
	both, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{UserID: &bob, ConnectionID: &payments, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, both, 1)
	limited, err := qtx.ListGrants(t.Context(), sqlc.ListGrantsParams{LimitRows: 2})
	require.NoError(t, err)
	require.Len(t, limited, 2)

	// The connection delete guard counts both recipient kinds together.
	count, err := qtx.CountConnectionGrants(t.Context(), payments)
	require.NoError(t, err)
	require.EqualValues(t, 3, count)
	count, err = qtx.CountConnectionGrants(t.Context(), stage)
	require.NoError(t, err)
	require.Zero(t, count)

	// Member views resolve effective access and honour the selector semantics.
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

	// Membership makes the group's grants effective without storing anything
	// derived: alice reaches payments-prod through two paths and bob, whose
	// only path is the group, reaches stage once the group is granted it.
	_, err = qtx.InsertGroupMember(t.Context(), sqlc.InsertGroupMemberParams{
		GroupID: finance.ID, UserID: alice, CreatedBy: admin})
	require.NoError(t, err)
	_, err = qtx.InsertGroupMember(t.Context(), sqlc.InsertGroupMemberParams{
		GroupID: finance.ID, UserID: bob, CreatedBy: admin})
	require.NoError(t, err)
	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{GroupID: &finance.ID, ConnectionID: stage, CreatedBy: admin})
	require.NoError(t, err)
	granted, err = qtx.ListGrantedConnections(t.Context(), sqlc.ListGrantedConnectionsParams{UserID: alice, LimitRows: 10})
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-stage"},
		[]string{granted[0].Name, granted[1].Name, granted[2].Name},
		"two paths to payments-prod still list it once")
	names, err = qtx.ListGrantedConnectionNames(t.Context(), sqlc.ListGrantedConnectionNamesParams{UserID: alice, LimitRows: 10})
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-stage"}, names)
	inherited, err := qtx.FindGrantedConnectionByName(t.Context(), sqlc.FindGrantedConnectionByNameParams{UserID: bob, Name: "payments-stage"})
	require.NoError(t, err)
	require.Equal(t, stage, inherited.ID)
	inheritedByID, err := qtx.FindGrantedConnectionByID(t.Context(), sqlc.FindGrantedConnectionByIDParams{UserID: bob, ID: stage})
	require.NoError(t, err)
	require.Equal(t, stage, inheritedByID.ID)

	// The effective listing keeps one row per path, direct before group.
	paths, err := qtx.ListEffectiveAccess(t.Context(), sqlc.ListEffectiveAccessParams{UserID: alice, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, paths, 4)
	require.Equal(t, "metrics-prod", paths[0].ConnectionName)
	require.Nil(t, paths[0].GroupID)
	require.Equal(t, "payments-prod", paths[1].ConnectionName)
	require.Nil(t, paths[1].GroupName)
	require.Equal(t, "payments-prod", paths[2].ConnectionName)
	require.Equal(t, "finance-managers", *paths[2].GroupName)
	require.Equal(t, finance.ID, *paths[2].GroupID)
	require.Equal(t, "payments-stage", paths[3].ConnectionName)
	filteredPaths, err := qtx.ListEffectiveAccess(t.Context(), sqlc.ListEffectiveAccessParams{
		UserID: alice, ConnectionID: &payments, LimitRows: 10})
	require.NoError(t, err)
	require.Len(t, filteredPaths, 2)

	// A connection with grants cannot be deleted at the storage layer either.
	_, err = tx.Exec(t.Context(), "SAVEPOINT del")
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), "DELETE FROM connections WHERE id = $1::uuid", payments)
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23503", pgErr.Code)
	_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT del")
	require.NoError(t, err)
	// So does a group that still holds one.
	_, err = tx.Exec(t.Context(), "SAVEPOINT group_del")
	require.NoError(t, err)
	_, err = qtx.DeleteGroup(t.Context(), finance.ID)
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23503", pgErr.Code)
	_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT group_del")
	require.NoError(t, err)

	deleted, err := qtx.DeleteGrant(t.Context(), sqlc.DeleteGrantParams{UserID: &alice, ConnectionID: payments})
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	deleted, err = qtx.DeleteGrant(t.Context(), sqlc.DeleteGrantParams{UserID: &alice, ConnectionID: payments})
	require.NoError(t, err)
	require.Zero(t, deleted)
	// The group's grant on the same connection survived the user's revocation,
	// so alice still reaches it through the group.
	after, err := qtx.FindGrantedConnectionByID(t.Context(), sqlc.FindGrantedConnectionByIDParams{UserID: alice, ID: payments})
	require.NoError(t, err)
	require.Equal(t, payments, after.ID)
	deleted, err = qtx.DeleteGrant(t.Context(), sqlc.DeleteGrantParams{GroupID: &finance.ID, ConnectionID: payments})
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	_, err = qtx.FindGrantedConnectionByID(t.Context(), sqlc.FindGrantedConnectionByIDParams{UserID: alice, ID: payments})
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestGrantMigrationAppliesToInitializedInstallation(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "004_grants.sql")
	// A later migration must not be applied ahead of the one under test: the
	// ledger would then be ahead of the manifest and fail closed.
	delete(previous, "005_drop_audit_events.sql")
	delete(previous, "006_victorialogs_provider.sql")
	delete(previous, "007_groups.sql")
	delete(previous, "008_session_renewal_and_cli_authorization.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	queries := sqlc.New(pool)
	// The previous release still had the journal and stored rows in it.
	execSQL(t, pool, `INSERT INTO auth_events (id, action, outcome) VALUES ($1::uuid, 'connection.check', 'check_failed')`, randomTestID(t))
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	require.Equal(t, platform.Initializing, NewInitializer(pool, "", "").Check(t.Context()).State)

	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.True(t, present)
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('auth_events') IS NOT NULL`).Scan(&present))
	require.False(t, present, "the populated journal is dropped with its rows")
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
	// A later migration must not be applied ahead of the one under test: the
	// ledger would then be ahead of the manifest and fail closed.
	delete(previous, "005_drop_audit_events.sql")
	delete(previous, "006_victorialogs_provider.sql")
	delete(previous, "007_groups.sql")
	delete(previous, "008_session_renewal_and_cli_authorization.sql")
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
	require.Equal(t, ledger+5, countRows(t, pool, "goose_db_version"))
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('grants') IS NOT NULL`).Scan(&present))
	require.True(t, present)
}
