package database

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
)

func TestGeneratedGroupQueriesAndConstraints(t *testing.T) {
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
	admin, alice, bob := user("admin"), user("alice"), user("bob")
	payments, err := qtx.InsertConnection(t.Context(), sqlc.InsertConnectionParams{
		ID: randomTestID(t), Name: "payments-prod", Title: "Title", Provider: "postgresql",
		Target: []byte(`{"host":"db"}`), Labels: []byte(`{}`), SecretEnvelope: "v1:fixture",
		StatementTimeoutMs: 30000, MaxRows: 1000, MaxBytes: 1048576,
	})
	require.NoError(t, err)

	finance, err := qtx.InsertGroup(t.Context(), sqlc.InsertGroupParams{
		ID: randomTestID(t), Name: "finance-managers", Description: "Finance managers",
	})
	require.NoError(t, err)
	require.Equal(t, "finance-managers", finance.Name)
	require.Equal(t, finance.CreatedAt, finance.UpdatedAt)
	platformGroup, err := qtx.InsertGroup(t.Context(), sqlc.InsertGroupParams{ID: randomTestID(t), Name: "platform"})
	require.NoError(t, err)
	require.Empty(t, platformGroup.Description, "the description is optional and defaults to empty")

	byID, err := qtx.FindGroupByID(t.Context(), finance.ID)
	require.NoError(t, err)
	require.Equal(t, finance, byID)
	byName, err := qtx.FindGroupByName(t.Context(), "finance-managers")
	require.NoError(t, err)
	require.Equal(t, finance.ID, byName.ID)
	_, err = qtx.FindGroupByName(t.Context(), "missing-group")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	locked, err := qtx.LockGroup(t.Context(), finance.ID)
	require.NoError(t, err)
	require.Equal(t, finance.ID, locked.ID)
	exists, err := qtx.GroupNameExists(t.Context(), "finance-managers")
	require.NoError(t, err)
	require.True(t, exists)
	exists, err = qtx.GroupNameExists(t.Context(), "Finance-Managers")
	require.NoError(t, err)
	require.False(t, exists)

	// The name and description constraints are the storage half of the
	// validators: the grammar, the UUID exclusion and the character bound.
	var pgErr *pgconn.PgError
	for name, params := range map[string]sqlc.InsertGroupParams{
		"uppercase":   {ID: randomTestID(t), Name: "Finance"},
		"too short":   {ID: randomTestID(t), Name: "ab"},
		"leading dot": {ID: randomTestID(t), Name: ".finance"},
		"uuid shaped": {ID: randomTestID(t), Name: "abcdef12-3456-4890-abcd-ef1234567890"},
		// The bound counts characters, not bytes: 2,001 multibyte characters
		// are refused where 2,000 are stored.
		"description": {ID: randomTestID(t), Name: "over-long", Description: strings.Repeat("é", 2001)},
	} {
		_, err := tx.Exec(t.Context(), "SAVEPOINT bad_group")
		require.NoError(t, err)
		_, err = qtx.InsertGroup(t.Context(), params)
		require.ErrorAs(t, err, &pgErr, name)
		require.Equal(t, "23514", pgErr.Code, name)
		_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT bad_group")
		require.NoError(t, err)
	}
	wide, err := qtx.InsertGroup(t.Context(), sqlc.InsertGroupParams{
		ID: randomTestID(t), Name: "wide-description", Description: strings.Repeat("é", 2000),
	})
	require.NoError(t, err)
	require.Len(t, []rune(wide.Description), 2000)
	_, err = tx.Exec(t.Context(), "SAVEPOINT duplicate_group")
	require.NoError(t, err)
	_, err = qtx.InsertGroup(t.Context(), sqlc.InsertGroupParams{ID: randomTestID(t), Name: "finance-managers"})
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	_, err = tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT duplicate_group")
	require.NoError(t, err)

	// Membership records the adding administrator and is idempotent.
	membership, err := qtx.InsertGroupMember(t.Context(), sqlc.InsertGroupMemberParams{
		GroupID: finance.ID, UserID: alice, CreatedBy: admin})
	require.NoError(t, err)
	require.Equal(t, admin, membership.CreatedBy)
	_, err = qtx.InsertGroupMember(t.Context(), sqlc.InsertGroupMemberParams{
		GroupID: finance.ID, UserID: alice, CreatedBy: admin})
	require.ErrorIs(t, err, pgx.ErrNoRows)
	_, err = qtx.InsertGroupMember(t.Context(), sqlc.InsertGroupMemberParams{
		GroupID: finance.ID, UserID: bob, CreatedBy: admin})
	require.NoError(t, err)
	member, err := qtx.FindGroupMember(t.Context(), sqlc.FindGroupMemberParams{GroupID: finance.ID, UserID: alice})
	require.NoError(t, err)
	require.Equal(t, "alice", member.Username)
	require.Equal(t, "finance-managers", member.GroupName)
	require.Equal(t, "admin", member.CreatedByUsername)
	_, err = qtx.FindGroupMember(t.Context(), sqlc.FindGroupMemberParams{GroupID: platformGroup.ID, UserID: alice})
	require.ErrorIs(t, err, pgx.ErrNoRows)
	members, err := qtx.ListGroupMembers(t.Context(), sqlc.ListGroupMembersParams{GroupID: finance.ID, LimitRows: 10})
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "bob"}, []string{members[0].Username, members[1].Username})
	require.Equal(t, "admin", members[0].AddedByUsername)
	require.Equal(t, "member", members[0].Role)
	members, err = qtx.ListGroupMembers(t.Context(), sqlc.ListGroupMembersParams{GroupID: finance.ID, LimitRows: 1})
	require.NoError(t, err)
	require.Len(t, members, 1)
	groupNames, err := qtx.ListGroupNames(t.Context(), sqlc.ListGroupNamesParams{UserID: alice, LimitRows: 10})
	require.NoError(t, err)
	require.Equal(t, []string{"finance-managers"}, groupNames)
	groupNames, err = qtx.ListGroupNames(t.Context(), sqlc.ListGroupNamesParams{UserID: randomTestID(t), LimitRows: 10})
	require.NoError(t, err)
	require.Empty(t, groupNames)

	_, err = qtx.InsertGrant(t.Context(), sqlc.InsertGrantParams{
		GroupID: &finance.ID, ConnectionID: payments.ID, CreatedBy: admin})
	require.NoError(t, err)
	memberCount, err := qtx.CountGroupMembers(t.Context(), finance.ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, memberCount)
	grantCount, err := qtx.CountGroupGrants(t.Context(), finance.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, grantCount)
	grantCount, err = qtx.CountGroupGrants(t.Context(), platformGroup.ID)
	require.NoError(t, err)
	require.Zero(t, grantCount)

	listed, err := qtx.ListGroups(t.Context(), 10)
	require.NoError(t, err)
	require.Equal(t, []string{"finance-managers", "platform", "wide-description"},
		[]string{listed[0].Name, listed[1].Name, listed[2].Name})
	require.EqualValues(t, 2, listed[0].Members)
	require.EqualValues(t, 1, listed[0].Grants)
	require.EqualValues(t, 0, listed[1].Members)
	listed, err = qtx.ListGroups(t.Context(), 2)
	require.NoError(t, err)
	require.Len(t, listed, 2)

	// A rename keeps the UUID, so memberships and grants follow it; an absent
	// field is untouched and a no-op update leaves updated_at alone.
	renamed, err := qtx.UpdateGroup(t.Context(), sqlc.UpdateGroupParams{ID: finance.ID, Name: ref("finance-leads")})
	require.NoError(t, err)
	require.Equal(t, "finance-leads", renamed.Name)
	require.Equal(t, "Finance managers", renamed.Description)
	require.True(t, renamed.UpdatedAt.After(finance.UpdatedAt))
	unchanged, err := qtx.UpdateGroup(t.Context(), sqlc.UpdateGroupParams{ID: finance.ID, Name: ref("finance-leads")})
	require.NoError(t, err)
	require.Equal(t, renamed.UpdatedAt, unchanged.UpdatedAt)
	cleared, err := qtx.UpdateGroup(t.Context(), sqlc.UpdateGroupParams{ID: finance.ID, Description: ref("")})
	require.NoError(t, err)
	require.Empty(t, cleared.Description)
	grantCount, err = qtx.CountGroupGrants(t.Context(), finance.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, grantCount, "a rename never moves access")

	// Deleting a group takes its memberships with it and nothing else; the
	// grant has to go first because grants.group_id has no cascade.
	deleted, err := qtx.DeleteGrant(t.Context(), sqlc.DeleteGrantParams{GroupID: &finance.ID, ConnectionID: payments.ID})
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	rows, err := qtx.DeleteGroup(t.Context(), finance.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	memberCount, err = qtx.CountGroupMembers(t.Context(), finance.ID)
	require.NoError(t, err)
	require.Zero(t, memberCount, "memberships follow the group")
	var users int
	require.NoError(t, tx.QueryRow(t.Context(), `SELECT count(*) FROM users`).Scan(&users))
	require.Equal(t, 3, users, "members outlive the group")
	rows, err = qtx.DeleteGroup(t.Context(), finance.ID)
	require.NoError(t, err)
	require.Zero(t, rows)
	// A group recreated with the same name inherits nothing.
	recreated, err := qtx.InsertGroup(t.Context(), sqlc.InsertGroupParams{ID: randomTestID(t), Name: "finance-leads"})
	require.NoError(t, err)
	memberCount, err = qtx.CountGroupMembers(t.Context(), recreated.ID)
	require.NoError(t, err)
	require.Zero(t, memberCount)
	grantCount, err = qtx.CountGroupGrants(t.Context(), recreated.ID)
	require.NoError(t, err)
	require.Zero(t, grantCount)
}

// The two partial unique indexes are the table's real key now that the primary
// key is gone: one grant per user and connection, one per group and connection,
// and the two never collide.
func TestGroupMigrationKeepsOneGrantPerRecipientAndConnection(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, Migrate(t.Context(), pool))
	queries := sqlc.New(pool)
	admin, err := queries.InsertUser(t.Context(), sqlc.InsertUserParams{
		ID: randomTestID(t), Username: "index-admin", PasswordHash: "fixture"})
	require.NoError(t, err)
	connection, err := queries.InsertConnection(t.Context(), sqlc.InsertConnectionParams{
		ID: randomTestID(t), Name: "index-connection", Title: "Title", Provider: "postgresql",
		Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:fixture",
		StatementTimeoutMs: 30000, MaxRows: 1000, MaxBytes: 1048576,
	})
	require.NoError(t, err)
	group, err := queries.InsertGroup(t.Context(), sqlc.InsertGroupParams{ID: randomTestID(t), Name: "index-group"})
	require.NoError(t, err)

	insert := func(userID, groupID *string) error {
		_, err := pool.Exec(t.Context(),
			`INSERT INTO grants (user_id, group_id, connection_id, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)`,
			userID, groupID, connection.ID, admin.ID)
		return err
	}
	require.NoError(t, insert(&admin.ID, nil))
	var pgErr *pgconn.PgError
	require.ErrorAs(t, insert(&admin.ID, nil), &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	require.Equal(t, "grants_user_connection", pgErr.ConstraintName)
	require.NoError(t, insert(nil, &group.ID), "a group grant on the same connection is a distinct row")
	require.ErrorAs(t, insert(nil, &group.ID), &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	require.Equal(t, "grants_group_connection", pgErr.ConstraintName)
	require.Equal(t, 2, countRows(t, pool, "grants"))
}

func TestGroupMigrationAppliesToInitializedInstallation(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "007_groups.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	queries := sqlc.New(pool)
	var present bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('groups') IS NOT NULL`).Scan(&present))
	require.False(t, present)
	// A ledger behind the embedded manifest is a pending migration, not an
	// incompatible schema; readiness stays closed until it is applied.
	require.Equal(t, platform.Initializing, NewInitializer(pool, "", "").Check(t.Context()).State)

	// The previous release stored grants under the old primary key; they must
	// survive the rewrite unchanged.
	admin, err := queries.InsertUser(t.Context(), sqlc.InsertUserParams{
		ID: randomTestID(t), Username: "carried-admin", PasswordHash: "fixture"})
	require.NoError(t, err)
	require.NoError(t, queries.MarkInstallationInitialized(t.Context()))
	connection, err := queries.InsertConnection(t.Context(), sqlc.InsertConnectionParams{
		ID: randomTestID(t), Name: "carried-connection", Title: "Title", Provider: "postgresql",
		Target: []byte(`{}`), Labels: []byte(`{}`), SecretEnvelope: "v1:fixture",
		StatementTimeoutMs: 30000, MaxRows: 1000, MaxBytes: 1048576,
	})
	require.NoError(t, err)
	execSQL(t, pool, `INSERT INTO grants (user_id, connection_id, created_by) VALUES ($1::uuid, $2::uuid, $1::uuid)`,
		admin.ID, connection.ID)

	require.NoError(t, Migrate(t.Context(), pool))
	require.NoError(t, Migrate(t.Context(), pool))
	require.Equal(t, appliedLedgerRows(), countRows(t, pool, "goose_db_version"), "007 applies once")
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('groups') IS NOT NULL`).Scan(&present))
	require.True(t, present)
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('group_members') IS NOT NULL`).Scan(&present))
	require.True(t, present)
	require.Equal(t, 1, countRows(t, pool, "grants"))
	carried, err := queries.FindGrant(t.Context(), sqlc.FindGrantParams{UserID: &admin.ID, ConnectionID: connection.ID})
	require.NoError(t, err)
	require.Equal(t, "carried-admin", *carried.Username)
	require.Nil(t, carried.GroupID, "an existing grant keeps its user recipient")
	// Readiness opens again only because the new tables answer their column
	// checks; Attempt applies nothing further on an initialized installation.
	require.Equal(t, platform.Ready, NewInitializer(pool, "", "").Attempt(t.Context()).State)
}
