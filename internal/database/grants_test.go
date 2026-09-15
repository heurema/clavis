package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file is fixture setup, fault injection, or an independent
// assertion against persisted state. Application operations use LocalAuth.

func signedInMember(t *testing.T, s *LocalAuth, admin auth.Session, username string) (auth.UserRecord, auth.Session) {
	t.Helper()
	record, input := createMember(t, s, admin, username)
	return record, session(t, s, login(t, s, input), auth.CLI)
}

// everyGrantRow flattens every stored grant so a test can assert that a name,
// a host or a secret never entered the table; grants reference UUIDs only.
func everyGrantRow(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var rows string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(
		coalesce(user_id::text, group_id::text)||' '||connection_id::text||' '||created_by::text, ' '), '') FROM grants`).Scan(&rows))
	return rows
}

func grantUsernames(list auth.GrantList) []string {
	names := make([]string, 0, len(list.Grants))
	for _, grant := range list.Grants {
		names = append(names, grant.Recipient.Name)
	}
	return names
}

func grantConnections(list auth.GrantList) []string {
	names := make([]string, 0, len(list.Grants))
	for _, grant := range list.Grants {
		names = append(names, grant.Connection.Name)
	}
	return names
}

func summaryNames(list auth.ConnectionSummaryList) []string {
	names := make([]string, 0, len(list.Connections))
	for _, record := range list.Connections {
		names = append(names, record.Name)
	}
	return names
}

// The recipient is what a grant is keyed on, so the resolver owns it: a user
// or a group, addressed by UUID or name, and nothing else. Group management
// itself is not implemented yet, so the group row is seeded directly.
func TestGrantRecipientResolvesUsersAndGroups(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	metrics := createConnection(t, s, admin, connectionRequest("metrics-prod"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	finance, err := sqlc.New(pool).InsertGroup(t.Context(), sqlc.InsertGroupParams{
		ID: randomTestID(t), Name: "finance-managers", Description: "Finance managers",
	})
	require.NoError(t, err)

	granted, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.True(t, granted.Created)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientGroup, ID: finance.ID, Name: "finance-managers"}, granted.Grant.Recipient)
	require.Equal(t, auth.GrantParty{ID: payments.ID, Name: "payments-prod"}, granted.Grant.Connection)
	byID, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: finance.ID, Connection: metrics.ID}, false)
	require.NoError(t, err)
	require.Equal(t, granted.Grant.Recipient, byID.Grant.Recipient)
	require.Equal(t, 2, countRows(t, pool, "grants"))
	// A direct grant on the same connection is a distinct row, not a conflict.
	direct, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.True(t, direct.Created)
	require.Equal(t, 3, countRows(t, pool, "grants"))

	// The recipient rule and unknown references are refused before any write.
	rows := countRows(t, pool, "grants")
	for name, request := range map[string]auth.GrantRequest{
		"no recipient":  {Connection: "payments-prod"},
		"two":           {User: "alice", Group: "finance-managers", Connection: "payments-prod"},
		"empty strings": {User: "", Group: "", Connection: "payments-prod"},
	} {
		_, err := s.CreateGrant(t.Context(), admin, request, false)
		code(t, err, auth.InvalidArgument, name)
		require.Equal(t, auth.RecipientHint, hintOf(t, err), name)
		_, err = s.RevokeGrant(t.Context(), admin, request, false)
		code(t, err, auth.InvalidArgument, name)
	}
	for _, ref := range []string{"missing-group", randomTestID(t), "NOT A NAME"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: ref, Connection: "payments-prod"}, false)
		code(t, err, auth.GroupNotFound, ref)
		require.Equal(t, hintGroupNotFound, hintOf(t, err))
	}
	require.Equal(t, rows, countRows(t, pool, "grants"))

	// Membership makes the group's grants effective on the next request, with
	// no derived row: the member reaches metrics-prod only through the group.
	before, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"payments-prod"}, summaryNames(before))
	execSQL(t, pool, `INSERT INTO group_members (group_id, user_id, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		finance.ID, alice.ID, admin.User.ID)
	after, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, summaryNames(after),
		"two paths to payments-prod still list it once")
	record, err := s.AuthorizeConnection(t.Context(), aliceSession, "metrics-prod")
	require.NoError(t, err)
	require.Equal(t, metrics.ID, record.ID)
	names, truncated, err := s.ListGrantedConnectionNames(t.Context(), aliceSession, 0)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, names)

	// Revoking the group's grant ends the inherited path and leaves the direct
	// one; the listing still names the group recipient it removed.
	revoked, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: metrics.ID}, false)
	require.NoError(t, err)
	require.True(t, revoked.Revoked)
	require.Equal(t, granted.Grant.Recipient, revoked.Recipient)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "metrics-prod")
	code(t, err, auth.ConnectionNotFound)
	still, err := s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err)
	require.Equal(t, payments.ID, still.ID)
	listed, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "finance-managers"}, grantUsernames(listed))
	require.Equal(t, []auth.RecipientKind{auth.RecipientUser, auth.RecipientGroup},
		[]auth.RecipientKind{listed.Grants[0].Recipient.Kind, listed.Grants[1].Recipient.Kind})
}

func TestCreateAndRevokeGrantAreIdempotent(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	metrics := createConnection(t, s, admin, connectionRequest("metrics-prod"))
	alice, _ := createMember(t, s, admin, "alice")

	created, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.True(t, created.Created)
	require.False(t, created.DryRun)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientUser, ID: alice.ID, Name: "alice"}, created.Grant.Recipient)
	require.Equal(t, auth.GrantParty{ID: payments.ID, Name: "payments-prod"}, created.Grant.Connection)
	require.Equal(t, auth.GrantParty{ID: admin.User.ID, Name: admin.User.Username}, created.Grant.CreatedBy)
	require.Equal(t, time.UTC, created.Grant.CreatedAt.Location())
	require.WithinDuration(t, time.Now(), created.Grant.CreatedAt, 5*time.Second)
	require.Equal(t, 1, countRows(t, pool, "grants"))

	// The same operation addressed by UUID on both sides.
	byID, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: metrics.ID}, false)
	require.NoError(t, err)
	require.True(t, byID.Created)
	require.Equal(t, auth.GrantParty{ID: metrics.ID, Name: "metrics-prod"}, byID.Grant.Connection)
	require.Equal(t, 2, countRows(t, pool, "grants"))

	// A repeated grant returns the one that exists and leaves its row alone:
	// the creation time and the granting administrator never move.
	repeat, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.False(t, repeat.Created)
	require.Equal(t, created.Grant, repeat.Grant)
	require.Equal(t, 2, countRows(t, pool, "grants"))

	revoked, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: payments.ID}, false)
	require.NoError(t, err)
	require.True(t, revoked.Revoked)
	require.False(t, revoked.DryRun)
	require.Equal(t, created.Grant.Recipient, revoked.Recipient)
	require.Equal(t, created.Grant.Connection, revoked.Connection)
	require.Equal(t, 1, countRows(t, pool, "grants"))

	// Revoking what is not there succeeds and removes nothing further.
	again, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.False(t, again.Revoked)
	require.Equal(t, revoked.Recipient, again.Recipient)
	require.Equal(t, revoked.Connection, again.Connection)
	require.Equal(t, 1, countRows(t, pool, "grants"))
	remaining, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, grantConnections(remaining))
	require.Equal(t, byID.Grant, remaining.Grants[0], "the surviving grant is untouched")

	// Only UUIDs are stored; no username, connection name, host or secret.
	rows := everyGrantRow(t, pool)
	for _, value := range []string{"alice", "payments-prod", "metrics-prod", sentinelHost, sentinelSecret} {
		require.NotContains(t, rows, value)
	}
}

func TestGrantMutationsDenyUnknownPartiesMembersAndRevokedSessions(t *testing.T) {
	pool, s, admin, input := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))

	users := 0
	for _, ref := range []string{"nobody-here", randomTestID(t), "Not A Ref"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: ref, Connection: "payments-prod"}, false)
		code(t, err, auth.UserNotFound)
		require.Equal(t, hintUserNotFound, hintOf(t, err), ref)
		_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: ref, Connection: "payments-prod"}, false)
		code(t, err, auth.UserNotFound)
		users += 2
	}
	require.Equal(t, 6, users)
	require.Zero(t, countRows(t, pool, "grants"))

	for _, ref := range []string{"missing-connection", randomTestID(t), "Not A Ref"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: ref}, false)
		code(t, err, auth.ConnectionNotFound)
		require.Equal(t, hintConnectionNotFound, hintOf(t, err), ref)
		_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: ref}, false)
		code(t, err, auth.ConnectionNotFound)
	}
	require.Zero(t, countRows(t, pool, "grants"))

	operations := map[string]func(auth.Session) error{
		"grant.create": func(actor auth.Session) error {
			_, err := s.CreateGrant(t.Context(), actor, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
			return err
		},
		"grant.revoke": func(actor auth.Session) error {
			_, err := s.RevokeGrant(t.Context(), actor, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
			return err
		},
		"grants.list": func(actor auth.Session) error {
			_, err := s.ListGrants(t.Context(), actor, auth.GrantFilter{User: "personal-admin"})
			return err
		},
	}
	// The other user's reference denies a member in either spelling.
	_, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{User: admin.User.ID})
	code(t, err, auth.Forbidden)
	for action, operation := range operations {
		code(t, operation(aliceSession), auth.Forbidden, action)
	}
	for action, operation := range operations {
		code(t, operation(revoked), auth.Unauthenticated, action)
	}
	for _, operation := range operations {
		code(t, operation(auth.Session{}), auth.Unauthenticated)
	}

	// A member's own listing is allowed, by either form of their reference.
	for _, ref := range []string{"", "alice", alice.ID} {
		list, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{User: ref})
		require.NoError(t, err, ref)
		require.Empty(t, list.Grants)
		require.False(t, list.Truncated)
	}
	require.Zero(t, countRows(t, pool, "grants"), "no denial granted anything")
}

func TestMemberReadsOnlyGrantedConnections(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	created := map[string]auth.Connection{}
	for name, labels := range map[string]map[string]string{
		"payments-prod":  {"env": "prod", "service": "payments"},
		"metrics-prod":   {"env": "prod", "team": "sre"},
		"payments-stage": {"env": "stage", "service": "payments"},
	} {
		request := connectionRequest(name)
		request.Labels = labels
		created[name] = createConnection(t, s, admin, request)
	}
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	for _, name := range []string{"payments-prod", "metrics-prod"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: name}, false)
		require.NoError(t, err)
	}
	// A disabled connection stays visible, marked disabled.
	_, err := s.SetConnectionEnabled(t.Context(), admin, "metrics-prod", false, false)
	require.NoError(t, err)
	execSQL(t, pool, `UPDATE connections SET last_check_outcome='reachable', last_check_at=clock_timestamp() WHERE id=$1`,
		created["payments-prod"].ID)
	grants := countRows(t, pool, "grants")

	list, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, summaryNames(list))
	require.False(t, list.Truncated)
	require.False(t, list.Connections[0].Enabled)
	require.True(t, list.Connections[1].Enabled)
	require.NotNil(t, list.Connections[1].LastCheck)
	require.Equal(t, auth.CheckReachable, list.Connections[1].LastCheck.Outcome)
	encoded, err := json.Marshal(list)
	require.NoError(t, err)
	for _, absent := range []string{sentinelHost, sentinelSecret, "target", "maxRows", "maxBytes", "statementTimeoutMs"} {
		require.NotContains(t, string(encoded), absent)
	}

	// Selectors, ordering and bounds behave as they do for administrators.
	for value, want := range map[string][]string{
		"":                 {"metrics-prod", "payments-prod"},
		"env=prod":         {"metrics-prod", "payments-prod"},
		"service=payments": {"payments-prod"},
		"team":             {"metrics-prod"},
		"env=stage":        {},
		"env=prod,env=dev": {},
	} {
		filtered, err := s.ListGrantedConnections(t.Context(), aliceSession, selector(t, value), 0)
		require.NoError(t, err, value)
		require.Equal(t, want, summaryNames(filtered), value)
	}
	small, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 1)
	require.NoError(t, err)
	require.True(t, small.Truncated)
	require.Len(t, small.Connections, 1)

	byName, err := s.GetGrantedConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err)
	byID, err := s.GetGrantedConnection(t.Context(), aliceSession, created["payments-prod"].ID)
	require.NoError(t, err)
	require.Equal(t, byName, byID)
	require.Equal(t, list.Connections[1], byName)
	full := created["payments-prod"]
	full.LastCheck = byName.LastCheck
	require.Equal(t, full.Summary(), byName)

	// An ungranted connection answers exactly like one that does not exist.
	for _, ref := range []string{"payments-stage", created["payments-stage"].ID, "missing-connection", randomTestID(t), "Not A Ref"} {
		_, err := s.GetGrantedConnection(t.Context(), aliceSession, ref)
		code(t, err, auth.ConnectionNotFound)
		require.Equal(t, hintConnectionNotFound, hintOf(t, err), ref)
	}
	require.Equal(t, grants, countRows(t, pool, "grants"), "member reads change nothing")

	names, truncated, err := s.ListGrantedConnectionNames(t.Context(), aliceSession, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, names)
	require.False(t, truncated)
	names, truncated, err = s.ListGrantedConnectionNames(t.Context(), aliceSession, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, names)
	require.True(t, truncated)
	// An administrator uses anything without a grant, so the list is empty.
	names, truncated, err = s.ListGrantedConnectionNames(t.Context(), admin, 0)
	require.NoError(t, err)
	require.Empty(t, names)
	require.False(t, truncated)

	// The administrator listing and get stay administrator-only.
	_, err = s.ListConnections(t.Context(), aliceSession, nil, 0)
	code(t, err, auth.Forbidden)
	_, err = s.GetConnection(t.Context(), aliceSession, "payments-prod")
	code(t, err, auth.Forbidden)
	require.Equal(t, grants, countRows(t, pool, "grants"), "a refused read changes nothing")

	// A grant revoked mid-session takes effect on the next read.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	after, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, summaryNames(after))
	_, err = s.GetGrantedConnection(t.Context(), aliceSession, "payments-prod")
	code(t, err, auth.ConnectionNotFound)
	require.Equal(t, grants-1, countRows(t, pool, "grants"))
	require.Equal(t, 3, countRows(t, pool, "connections"))
}

func TestAuthorizeConnectionRequiresAGrantAndAnEnabledConnection(t *testing.T) {
	pool, s, admin, input := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	spare := createConnection(t, s, admin, connectionRequest("spare-connection"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	_, bobSession := signedInMember(t, s, admin, "bob")
	_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	grants := countRows(t, pool, "grants")

	record, err := s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err)
	require.Equal(t, payments, record)
	byID, err := s.AuthorizeConnection(t.Context(), aliceSession, payments.ID)
	require.NoError(t, err)
	require.Equal(t, payments, byID)
	// An administrator needs no grant.
	free, err := s.AuthorizeConnection(t.Context(), admin, spare.Name)
	require.NoError(t, err)
	require.Equal(t, spare, free)

	for name, call := range map[string]func() error{
		"ungranted member": func() error { _, err := s.AuthorizeConnection(t.Context(), bobSession, "payments-prod"); return err },
		"other connection": func() error { _, err := s.AuthorizeConnection(t.Context(), aliceSession, spare.Name); return err },
		"unknown reference": func() error {
			_, err := s.AuthorizeConnection(t.Context(), aliceSession, "missing-connection")
			return err
		},
		"malformed":        func() error { _, err := s.AuthorizeConnection(t.Context(), aliceSession, "Not A Ref"); return err },
		"unknown to admin": func() error { _, err := s.AuthorizeConnection(t.Context(), admin, randomTestID(t)); return err },
	} {
		err := call()
		code(t, err, auth.ConnectionNotFound)
		require.Equal(t, hintConnectionNotFound, hintOf(t, err), name)
	}
	require.Equal(t, grants, countRows(t, pool, "grants"), "authorization changes nothing of its own")

	_, err = s.SetConnectionEnabled(t.Context(), admin, "payments-prod", false, false)
	require.NoError(t, err)
	for _, actor := range []auth.Session{aliceSession, admin} {
		_, err := s.AuthorizeConnection(t.Context(), actor, "payments-prod")
		code(t, err, auth.ConnectionDisabled)
		require.Equal(t, hintConnectionDisabled, hintOf(t, err))
	}
	_, err = s.SetConnectionEnabled(t.Context(), admin, "payments-prod", true, false)
	require.NoError(t, err)

	// A revoked grant takes effect on the next call despite a valid session.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: payments.ID}, false)
	require.NoError(t, err)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	code(t, err, auth.ConnectionNotFound)
	require.Equal(t, grants-1, countRows(t, pool, "grants"))

	// A revoked session and no session at all are both refused and change
	// nothing.
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	_, err = s.AuthorizeConnection(t.Context(), revoked, "payments-prod")
	code(t, err, auth.Unauthenticated)
	_, err = s.AuthorizeConnection(t.Context(), auth.Session{}, "payments-prod")
	code(t, err, auth.Unauthenticated)
	require.Equal(t, grants-1, countRows(t, pool, "grants"))
	require.Equal(t, 2, countRows(t, pool, "connections"))
}

func TestGrantsSurviveBlockingAndRenamingAndGuardDelete(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	alice, aliceInput := createMember(t, s, admin, "alice")
	for _, username := range []string{"bob", "carol"} {
		createMember(t, s, admin, username)
	}
	for _, user := range []string{"alice", "bob", "carol"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: user, Connection: "payments-prod"}, false)
		require.NoError(t, err)
	}
	require.Equal(t, 3, countRows(t, pool, "grants"))

	// Blocking and unblocking leave the grant alone; access resumes without
	// re-granting. The target is addressed by username here.
	blocked, err := s.SetUserDisabled(t.Context(), admin, "alice", true)
	require.NoError(t, err)
	require.Equal(t, alice.ID, blocked.User.ID)
	require.True(t, blocked.SessionsRevoked)
	require.Equal(t, 3, countRows(t, pool, "grants"))
	_, err = s.SetUserDisabled(t.Context(), admin, "alice", false)
	require.NoError(t, err)
	aliceSession := session(t, s, login(t, s, aliceInput), auth.CLI)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err)

	// A rename moves the name, never the access: grants reference UUIDs.
	renamed := "payments-prod-reporting"
	_, err = s.UpdateConnection(t.Context(), admin, payments.ID, auth.UpdateConnectionRequest{Name: &renamed}, false)
	require.NoError(t, err)
	list, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{renamed, renamed, renamed}, grantConnections(list))
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, renamed)
	require.NoError(t, err)
	granted, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{renamed}, summaryNames(granted))

	// Delete needs a disabled connection and zero grants; the hint names both
	// conditions while the connection is enabled and counts what is left.
	_, err = s.DeleteConnection(t.Context(), admin, renamed, false)
	code(t, err, auth.ConnectionInUse)
	require.Equal(t, hintConnectionGuard(true, 3), hintOf(t, err))
	require.Contains(t, hintOf(t, err), "3 grants")
	_, err = s.SetConnectionEnabled(t.Context(), admin, renamed, false, false)
	require.NoError(t, err)
	for _, remaining := range []int64{3, 2, 1} {
		for _, dryRun := range []bool{true, false} {
			_, err := s.DeleteConnection(t.Context(), admin, renamed, dryRun)
			code(t, err, auth.ConnectionInUse)
			require.Equal(t, hintRemainingGrants(remaining), hintOf(t, err))
		}
		revoked, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{
			User: []string{"alice", "bob", "carol"}[3-remaining], Connection: renamed,
		}, false)
		require.NoError(t, err)
		require.True(t, revoked.Revoked)
	}
	deletion, err := s.DeleteConnection(t.Context(), admin, renamed, false)
	require.NoError(t, err)
	require.True(t, deletion.Deleted)
	require.Equal(t, renamed, deletion.Name)
	require.Zero(t, countRows(t, pool, "grants"))
	require.Zero(t, countRows(t, pool, "connections"))
}

func TestGrantDryRunLeavesNoTrace(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	metrics := createConnection(t, s, admin, connectionRequest("metrics-prod"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "metrics-prod"}, false)
	require.NoError(t, err)
	_, err = s.SetConnectionEnabled(t.Context(), admin, metrics.ID, false, false)
	require.NoError(t, err)
	grants := countRows(t, pool, "grants")
	connections := countRows(t, pool, "connections")

	created, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, true)
	require.NoError(t, err)
	require.True(t, created.Created)
	require.True(t, created.DryRun)
	require.Equal(t, alice.ID, created.Grant.Recipient.ID)
	repeat, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "metrics-prod"}, true)
	require.NoError(t, err)
	require.False(t, repeat.Created)
	require.True(t, repeat.DryRun)

	revocation, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "metrics-prod"}, true)
	require.NoError(t, err)
	require.True(t, revocation.Revoked)
	require.True(t, revocation.DryRun)
	missing, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, true)
	require.NoError(t, err)
	require.False(t, missing.Revoked)

	// Every denial answers the same way and still leaves nothing behind.
	_, err = s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "nobody-here", Connection: "payments-prod"}, true)
	code(t, err, auth.UserNotFound)
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "missing-connection"}, true)
	code(t, err, auth.ConnectionNotFound)
	_, err = s.CreateGrant(t.Context(), aliceSession, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, true)
	code(t, err, auth.Forbidden)
	_, err = s.DeleteConnection(t.Context(), admin, "metrics-prod", true)
	code(t, err, auth.ConnectionInUse)
	require.Equal(t, hintRemainingGrants(1), hintOf(t, err))

	require.Equal(t, grants, countRows(t, pool, "grants"))
	require.Equal(t, connections, countRows(t, pool, "connections"))
}

func TestListGrantsOrdersFiltersAndBounds(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	metrics := createConnection(t, s, admin, connectionRequest("metrics-prod"))
	createConnection(t, s, admin, connectionRequest("spare-connection"))
	alice, _ := createMember(t, s, admin, "alice")
	bob, _ := createMember(t, s, admin, "bob")
	for _, request := range []auth.GrantRequest{
		{User: "bob", Connection: "payments-prod"},
		{User: "alice", Connection: "payments-prod"},
		{User: "alice", Connection: "metrics-prod"},
	} {
		_, err := s.CreateGrant(t.Context(), admin, request, false)
		require.NoError(t, err)
	}

	all, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "alice", "bob"}, grantUsernames(all))
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-prod"}, grantConnections(all))
	require.False(t, all.Truncated)
	require.Equal(t, admin.User.Username, all.Grants[0].CreatedBy.Name)
	require.Equal(t, admin.User.ID, all.Grants[0].CreatedBy.ID)

	for name, filter := range map[string]auth.GrantFilter{
		"user by name":    {User: "alice"},
		"user by id":      {User: alice.ID},
		"connection name": {Connection: "payments-prod"},
		"connection id":   {Connection: payments.ID},
	} {
		list, err := s.ListGrants(t.Context(), admin, filter)
		require.NoError(t, err, name)
		require.Len(t, list.Grants, 2, name)
	}
	both, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{User: bob.ID, Connection: "payments-prod"})
	require.NoError(t, err)
	require.Len(t, both.Grants, 1)

	// A reference that names nothing narrows the listing to nothing.
	for name, filter := range map[string]auth.GrantFilter{
		"unknown username":   {User: "nobody-here"},
		"unknown user id":    {User: randomTestID(t)},
		"malformed user":     {User: "Not A Ref"},
		"unknown connection": {Connection: "missing-connection"},
		"ungranted":          {Connection: "spare-connection"},
		"malformed target":   {Connection: "Not A Ref"},
		"unmatched pair":     {User: "bob", Connection: metrics.ID},
	} {
		list, err := s.ListGrants(t.Context(), admin, filter)
		require.NoError(t, err, name)
		require.Empty(t, list.Grants, name)
		require.False(t, list.Truncated, name)
	}

	bounded, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, bounded.Grants, 2)
	require.True(t, bounded.Truncated)
	over, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{Limit: auth.MaxGrantListing * 10})
	require.NoError(t, err)
	require.Len(t, over.Grants, 3)
	require.False(t, over.Truncated)
	require.Equal(t, 3, countRows(t, pool, "grants"), "listing changes nothing")
}

func TestGrantMutationsSerializeOnTheirOwnKeyAndOnTheConnectionRow(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")

	blocker, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback(context.Background()) }()
	_, err = blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, grantMutationLock)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	start := time.Now()
	_, err = s.CreateGrant(bounded, admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	cancel()
	code(t, err, auth.ServiceUnavailable)
	require.Less(t, time.Since(start), 5*time.Second)
	// Reads and the other mutation families never take the grant key.
	list, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Empty(t, list.Grants)
	_, err = s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.NoError(t, blocker.Rollback(t.Context()))
	require.Zero(t, countRows(t, pool, "grants"), "a timed-out mutation granted nothing")

	// A connection mutation in flight holds the row, so the grant waits for it
	// rather than referencing a connection that is being removed.
	holder, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(context.Background()) }()
	_, err = holder.Exec(t.Context(), `SELECT id FROM connections WHERE id=$1 FOR UPDATE`, payments.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: payments.ID}, false)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '-- name: LockConnection :one%'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting)
		return err == nil && waiting > 0
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, holder.Rollback(t.Context()))
	require.NoError(t, <-done)
	require.Equal(t, 1, countRows(t, pool, "grants"))

	// Run for real against a delete: whichever wins, a grant never survives
	// its connection.
	_, err = s.SetConnectionEnabled(t.Context(), admin, payments.ID, false, false)
	require.NoError(t, err)
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: payments.ID}, false)
	require.NoError(t, err)
	granting, deleting := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: payments.ID}, false)
		granting <- err
	}()
	go func() {
		_, err := s.DeleteConnection(t.Context(), admin, payments.ID, false)
		deleting <- err
	}()
	grantErr, deleteErr := <-granting, <-deleting
	if deleteErr == nil {
		code(t, grantErr, auth.ConnectionNotFound)
		require.Zero(t, countRows(t, pool, "connections"))
	} else {
		require.NoError(t, grantErr)
		code(t, deleteErr, auth.ConnectionInUse)
		require.Equal(t, hintRemainingGrants(1), hintOf(t, deleteErr))
	}
	require.Equal(t, countRows(t, pool, "connections"), countRows(t, pool, "grants"))
}

// accessPaths renders one entry per line as the provenance an administrator
// reads: the connection, then the path that supplies it.
func accessPaths(list auth.AccessList) []string {
	paths := make([]string, 0, len(list.Entries))
	for _, entry := range list.Entries {
		if entry.Source == auth.AccessGroup {
			paths = append(paths, entry.Connection.Name+" via "+entry.Group.Name)
			continue
		}
		paths = append(paths, entry.Connection.Name+" direct")
	}
	return paths
}

// inheritedFixture is the shape every effective-access scenario needs: alice
// reaches payments-prod both directly and through finance-managers, and
// metrics-prod only through platform-team.
func inheritedFixture(t *testing.T) (*pgxpool.Pool, *LocalAuth, auth.Session, auth.UserRecord, auth.Session) {
	t.Helper()
	pool, s, admin, _ := connectionFixture(t)
	for _, name := range []string{"payments-prod", "metrics-prod"} {
		createConnection(t, s, admin, connectionRequest(name))
	}
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	for group, connection := range map[string]string{
		"finance-managers": "payments-prod",
		"platform-team":    "metrics-prod",
	} {
		createGroup(t, s, admin, group, "")
		_, err := s.AddMember(t.Context(), admin, group, "alice", false)
		require.NoError(t, err)
		_, err = s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: group, Connection: connection}, false)
		require.NoError(t, err)
	}
	_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	return pool, s, admin, alice, aliceSession
}

func TestMemberReadsConnectionsThroughEveryPath(t *testing.T) {
	pool, s, admin, alice, aliceSession := inheritedFixture(t)

	// A connection reached twice is listed once, and one reached only through
	// a group is listed at all.
	list, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, summaryNames(list))
	filtered, err := s.ListGrantedConnections(t.Context(), aliceSession, selector(t, "env=prod"), 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, summaryNames(filtered))
	inherited, err := s.GetGrantedConnection(t.Context(), aliceSession, "metrics-prod")
	require.NoError(t, err)
	require.Equal(t, "metrics-prod", inherited.Name)
	byID, err := s.GetGrantedConnection(t.Context(), aliceSession, inherited.ID)
	require.NoError(t, err)
	require.Equal(t, inherited, byID)
	encoded, err := json.Marshal(list)
	require.NoError(t, err)
	for _, absent := range []string{sentinelHost, sentinelSecret, "target", "maxRows"} {
		require.NotContains(t, string(encoded), absent)
	}

	// Revoking the direct grant leaves the connection listed through the
	// group, and revoking the group's grant is what finally removes it.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	still, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, summaryNames(still))
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	after, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, summaryNames(after))
	_, err = s.GetGrantedConnection(t.Context(), aliceSession, "payments-prod")
	code(t, err, auth.ConnectionNotFound)
	require.Equal(t, hintConnectionNotFound, hintOf(t, err))

	// Leaving the group ends the inherited path on the next request, with the
	// session still valid and the grant still in place.
	removed, err := s.RemoveMember(t.Context(), admin, "platform-team", "alice", false)
	require.NoError(t, err)
	require.True(t, removed.Removed)
	empty, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Empty(t, empty.Connections)
	_, err = s.GetGrantedConnection(t.Context(), aliceSession, "metrics-prod")
	code(t, err, auth.ConnectionNotFound)
	require.Equal(t, 1, countRows(t, pool, "grants"), "the group's grant is untouched")
	require.Equal(t, 2, countRows(t, pool, "connections"))
}

func TestAuthorizeConnectionAcceptsEveryPathAndOnlyTheLastRemovalDenies(t *testing.T) {
	pool, s, admin, alice, aliceSession := inheritedFixture(t)
	metrics, err := s.GetConnection(t.Context(), admin, "metrics-prod")
	require.NoError(t, err)

	// A group grant alone authorizes, exactly as a direct grant does.
	record, err := s.AuthorizeConnection(t.Context(), aliceSession, "metrics-prod")
	require.NoError(t, err)
	require.Equal(t, metrics, record)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err)

	// One of two paths removed still authorizes; only the last removal denies.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err, "the group still supplies it")

	// Two groups reaching one connection behave the same way.
	_, err = s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: "platform-team", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	require.NoError(t, err)
	_, err = s.RemoveMember(t.Context(), admin, "platform-team", "alice", false)
	require.NoError(t, err)
	for _, ref := range []string{"payments-prod", "metrics-prod"} {
		_, err := s.AuthorizeConnection(t.Context(), aliceSession, ref)
		code(t, err, auth.ConnectionNotFound, ref)
		require.Equal(t, hintConnectionNotFound, hintOf(t, err), ref)
	}

	// A disabled connection inside effective access is refused with its own
	// code, so the caller learns to ask for it to be enabled.
	_, err = s.AddMember(t.Context(), admin, "platform-team", "alice", false)
	require.NoError(t, err)
	_, err = s.SetConnectionEnabled(t.Context(), admin, "metrics-prod", false, false)
	require.NoError(t, err)
	for _, actor := range []auth.Session{aliceSession, admin} {
		_, err := s.AuthorizeConnection(t.Context(), actor, "metrics-prod")
		code(t, err, auth.ConnectionDisabled)
		require.Equal(t, hintConnectionDisabled, hintOf(t, err))
	}
	require.Equal(t, 2, countRows(t, pool, "grants"), "authorization changes nothing of its own")
}

func TestListEffectiveAccessReportsEveryPathAndResolvesTheSubjectServerSide(t *testing.T) {
	pool, s, admin, alice, aliceSession := inheritedFixture(t)
	bob, bobSession := signedInMember(t, s, admin, "bob")

	// Three configured paths, ordered by connection, direct before group.
	list, err := s.ListEffectiveAccess(t.Context(), admin, "alice", "", 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod via platform-team", "payments-prod direct",
		"payments-prod via finance-managers"}, accessPaths(list))
	require.False(t, list.Truncated)
	require.Equal(t, auth.UserRecord{
		ID: alice.ID, Username: "alice", Role: auth.Member, Disabled: false, CreatedAt: alice.CreatedAt,
	}, list.User)
	require.Equal(t, time.UTC, list.Entries[0].CreatedAt.Location())
	require.WithinDuration(t, time.Now(), list.Entries[0].CreatedAt, 5*time.Second)
	require.Nil(t, list.Entries[1].Group, "a direct path names no group")
	require.NotNil(t, list.Entries[2].Group)
	require.True(t, auth.ValidUserID(list.Entries[2].Group.ID))

	// Revoking one path leaves the other two, which is the whole point of
	// reading paths rather than a usability verdict.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	fewer, err := s.ListEffectiveAccess(t.Context(), admin, alice.ID, "", 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod via platform-team", "payments-prod via finance-managers"}, accessPaths(fewer))

	// The connection filter narrows to one connection; a reference that names
	// nothing narrows to nothing, as every listing filter does.
	narrowed, err := s.ListEffectiveAccess(t.Context(), admin, "alice", "payments-prod", 0)
	require.NoError(t, err)
	require.Equal(t, []string{"payments-prod via finance-managers"}, accessPaths(narrowed))
	for _, ref := range []string{"missing-connection", randomTestID(t), "Not A Ref"} {
		unknown, err := s.ListEffectiveAccess(t.Context(), admin, "alice", ref, 0)
		require.NoError(t, err, ref)
		require.Empty(t, unknown.Entries, ref)
		require.Equal(t, alice.ID, unknown.User.ID, "the subject is still reported")
	}
	bounded, err := s.ListEffectiveAccess(t.Context(), admin, "alice", "", 1)
	require.NoError(t, err)
	require.Len(t, bounded.Entries, 1)
	require.True(t, bounded.Truncated)

	// A member asks about themselves by no reference or by either spelling,
	// and anybody else is refused.
	for _, ref := range []string{"", "alice", alice.ID} {
		own, err := s.ListEffectiveAccess(t.Context(), aliceSession, ref, "", 0)
		require.NoError(t, err, ref)
		require.Equal(t, fewer.Entries, own.Entries, ref)
		require.Equal(t, alice.ID, own.User.ID, ref)
	}
	for _, ref := range []string{"bob", bob.ID, "personal-admin", admin.User.ID, "nobody-here"} {
		_, err := s.ListEffectiveAccess(t.Context(), aliceSession, ref, "", 0)
		code(t, err, auth.Forbidden, ref)
	}
	none, err := s.ListEffectiveAccess(t.Context(), bobSession, "", "", 0)
	require.NoError(t, err)
	require.Empty(t, none.Entries)
	require.Equal(t, bob.ID, none.User.ID)

	// An administrator has no default subject: their own access comes from
	// their role, so the omission is an argument failure with the flag named.
	_, err = s.ListEffectiveAccess(t.Context(), admin, "", "", 0)
	code(t, err, auth.InvalidArgument)
	require.Equal(t, hintAccessSubject, hintOf(t, err))
	require.Contains(t, hintAccessSubject, "--user")
	for _, ref := range []string{"nobody-here", randomTestID(t), "Not A Ref"} {
		_, err := s.ListEffectiveAccess(t.Context(), admin, ref, "", 0)
		code(t, err, auth.UserNotFound, ref)
		require.Equal(t, hintUserNotFound, hintOf(t, err), ref)
	}

	// A revoked session is refused before any subject is resolved.
	require.NoError(t, s.Logout(t.Context(), bobSession))
	_, err = s.ListEffectiveAccess(t.Context(), bobSession, "", "", 0)
	code(t, err, auth.Unauthenticated)
	_, err = s.ListEffectiveAccess(t.Context(), auth.Session{}, "alice", "", 0)
	code(t, err, auth.Unauthenticated)
	require.Equal(t, 2, countRows(t, pool, "grants"), "the listing changes nothing")
}

// An administrator subject lists the paths configured for them even though
// their access does not depend on them, and role: admin on the record is what
// explains that. Demotion changes the record, never the entries.
func TestListEffectiveAccessDescribesAnAdministratorSubjectAcrossDemotion(t *testing.T) {
	_, s, admin, _, _ := inheritedFixture(t)
	carol := signedInAdministrator(t, s, admin, "carol")
	_, err := s.AddMember(t.Context(), admin, "finance-managers", "carol", false)
	require.NoError(t, err)

	before, err := s.ListEffectiveAccess(t.Context(), admin, "carol", "", 0)
	require.NoError(t, err)
	require.Equal(t, auth.Admin, before.User.Role)
	require.Equal(t, []string{"payments-prod via finance-managers"}, accessPaths(before))
	// An administrator needs no grant, so the paths say nothing about what
	// they may use: authorization answers that, and it lets them through.
	_, err = s.AuthorizeConnection(t.Context(), carol, "metrics-prod")
	require.NoError(t, err)

	_, err = s.SetRole(t.Context(), admin, "carol", auth.Member)
	require.NoError(t, err)
	after, err := s.ListEffectiveAccess(t.Context(), admin, "carol", "", 0)
	require.NoError(t, err)
	require.Equal(t, auth.Member, after.User.Role)
	require.Equal(t, before.Entries, after.Entries, "the same entries now describe the access they inherit")
	_, err = s.AuthorizeConnection(t.Context(), carol, "payments-prod")
	require.NoError(t, err)
	_, err = s.AuthorizeConnection(t.Context(), carol, "metrics-prod")
	code(t, err, auth.ConnectionNotFound, "no path reaches it once the role is gone")

	// A blocked subject is visible on the record rather than on the entries.
	_, err = s.SetUserDisabled(t.Context(), admin, "carol", true)
	require.NoError(t, err)
	blocked, err := s.ListEffectiveAccess(t.Context(), admin, "carol", "", 0)
	require.NoError(t, err)
	require.True(t, blocked.User.Disabled)
	require.Equal(t, before.Entries, blocked.Entries)
}

func TestIdentityNamesEffectiveConnectionsAndGroups(t *testing.T) {
	_, s, admin, _, aliceSession := inheritedFixture(t)

	names, truncated, err := s.ListGrantedConnectionNames(t.Context(), aliceSession, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod"}, names, "each connection once, whatever the path")
	require.False(t, truncated)
	groups, groupsTruncated, err := s.ListGroupNames(t.Context(), aliceSession, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"finance-managers", "platform-team"}, groups)
	require.False(t, groupsTruncated)

	// The two listings are bounded independently.
	groups, groupsTruncated, err = s.ListGroupNames(t.Context(), aliceSession, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"finance-managers"}, groups)
	require.True(t, groupsTruncated)
	over, _, err := s.ListGroupNames(t.Context(), aliceSession, auth.MaxGroupListing*10)
	require.NoError(t, err)
	require.Len(t, over, 2)

	// An administrator needs no grant, so their connection list stays empty,
	// while their groups are still reported: membership is a fact about them.
	_, err = s.AddMember(t.Context(), admin, "platform-team", admin.User.ID, false)
	require.NoError(t, err)
	names, truncated, err = s.ListGrantedConnectionNames(t.Context(), admin, 0)
	require.NoError(t, err)
	require.Empty(t, names)
	require.False(t, truncated)
	adminGroups, _, err := s.ListGroupNames(t.Context(), admin, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"platform-team"}, adminGroups)

	// Leaving every group empties the list without emptying the grants.
	for _, group := range []string{"finance-managers", "platform-team"} {
		_, err := s.RemoveMember(t.Context(), admin, group, "alice", false)
		require.NoError(t, err)
	}
	groups, groupsTruncated, err = s.ListGroupNames(t.Context(), aliceSession, 0)
	require.NoError(t, err)
	require.Empty(t, groups)
	require.False(t, groupsTruncated)
	names, _, err = s.ListGrantedConnectionNames(t.Context(), aliceSession, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"payments-prod"}, names, "the direct grant is what is left")

	require.NoError(t, s.Logout(t.Context(), aliceSession))
	_, _, err = s.ListGroupNames(t.Context(), aliceSession, 0)
	code(t, err, auth.Unauthenticated)
	_, _, err = s.ListGroupNames(t.Context(), auth.Session{}, 0)
	code(t, err, auth.Unauthenticated)
}

func TestListGrantsFiltersByGroupAndRefusesAMemberBeforeAnyLookup(t *testing.T) {
	pool, s, admin, alice, aliceSession := inheritedFixture(t)
	finance, err := s.GetGroup(t.Context(), admin, "finance-managers")
	require.NoError(t, err)

	all, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "finance-managers", "platform-team"}, grantUsernames(all))
	require.Equal(t, []auth.RecipientKind{auth.RecipientUser, auth.RecipientGroup, auth.RecipientGroup},
		[]auth.RecipientKind{all.Grants[0].Recipient.Kind, all.Grants[1].Recipient.Kind, all.Grants[2].Recipient.Kind})

	for name, filter := range map[string]auth.GrantFilter{
		"group by name": {Group: "finance-managers"},
		"group by id":   {Group: finance.ID},
	} {
		list, err := s.ListGrants(t.Context(), admin, filter)
		require.NoError(t, err, name)
		require.Equal(t, []string{"finance-managers"}, grantUsernames(list), name)
		require.Equal(t, []string{"payments-prod"}, grantConnections(list), name)
	}
	pair, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{Group: "finance-managers", Connection: "payments-prod"})
	require.NoError(t, err)
	require.Len(t, pair.Grants, 1)

	// A reference that names nothing narrows the listing to nothing, and the
	// two recipient filters together narrow to no row at all.
	for name, filter := range map[string]auth.GrantFilter{
		"unknown group name": {Group: "missing-group"},
		"unknown group id":   {Group: randomTestID(t)},
		"malformed group":    {Group: "Not A Ref"},
		"unmatched pair":     {Group: "finance-managers", Connection: "metrics-prod"},
		"both recipients":    {User: "alice", Group: "finance-managers"},
	} {
		list, err := s.ListGrants(t.Context(), admin, filter)
		require.NoError(t, err, name)
		require.Empty(t, list.Grants, name)
		require.False(t, list.Truncated, name)
	}

	// A member's own listing is their direct grants only: the group grants
	// they inherit are records about the group, not about them.
	own, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, grantUsernames(own))
	require.Equal(t, []string{"payments-prod"}, grantConnections(own))
	require.Equal(t, auth.RecipientUser, own.Grants[0].Recipient.Kind)
	byOwnID, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{User: alice.ID})
	require.NoError(t, err)
	require.Equal(t, own.Grants, byOwnID.Grants)

	// A group filter is refused before any group is looked up, so an existing
	// group and a missing one are indistinguishable to a member.
	for _, ref := range []string{"finance-managers", finance.ID, "missing-group", randomTestID(t), "Not A Ref"} {
		_, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{Group: ref})
		code(t, err, auth.Forbidden, ref)
		_, err = s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{User: "alice", Group: ref})
		code(t, err, auth.Forbidden, ref)
	}
	require.Equal(t, 3, countRows(t, pool, "grants"), "listing changes nothing")
}

// Group names live in their own namespace, so a user and a group may share a
// name; --user and --group keep every reference unambiguous.
func TestAUserAndAGroupWithTheSameNameHoldDistinctGrants(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	shared := "finance-managers"
	person, personSession := signedInMember(t, s, admin, shared)
	group := createGroup(t, s, admin, shared, "")
	require.NotEqual(t, person.ID, group.ID)

	direct, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: shared, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientUser, ID: person.ID, Name: shared}, direct.Grant.Recipient)
	inherited, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: shared, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.True(t, inherited.Created)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientGroup, ID: group.ID, Name: shared}, inherited.Grant.Recipient)
	require.Equal(t, 2, countRows(t, pool, "grants"))

	byUser, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{User: shared})
	require.NoError(t, err)
	require.Len(t, byUser.Grants, 1)
	require.Equal(t, auth.RecipientUser, byUser.Grants[0].Recipient.Kind)
	byGroup, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{Group: shared})
	require.NoError(t, err)
	require.Len(t, byGroup.Grants, 1)
	require.Equal(t, auth.RecipientGroup, byGroup.Grants[0].Recipient.Kind)

	// Revoking one leaves the other, and the member keeps the access the
	// surviving path supplies.
	revoked, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: shared, Connection: payments.ID}, false)
	require.NoError(t, err)
	require.True(t, revoked.Revoked)
	require.Equal(t, auth.RecipientUser, revoked.Recipient.Kind)
	_, err = s.AuthorizeConnection(t.Context(), personSession, "payments-prod")
	code(t, err, auth.ConnectionNotFound, "the group grant is not membership")
	_, err = s.AddMember(t.Context(), admin, shared, shared, false)
	require.NoError(t, err)
	_, err = s.AuthorizeConnection(t.Context(), personSession, "payments-prod")
	require.NoError(t, err)
	paths, err := s.ListEffectiveAccess(t.Context(), admin, shared, "", 0)
	require.NoError(t, err)
	require.Equal(t, []string{"payments-prod via " + shared}, accessPaths(paths))
	require.Equal(t, person.ID, paths.User.ID)
	require.Equal(t, 1, countRows(t, pool, "grants"))
}
