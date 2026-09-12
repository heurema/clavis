package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
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

// lastGrantEvent adds the connection column to lastEvent, because a grant event
// names a user as its target and a connection beside it.
func lastGrantEvent(t *testing.T, pool *pgxpool.Pool, action, outcome string) (actor, target, sessionID, connection string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT coalesce(actor_id::text,''), coalesce(target_id::text,''),
			coalesce(session_id::text,''), coalesce(connection_id::text,'')
		FROM auth_events WHERE action=$1 AND outcome=$2 ORDER BY created_at DESC LIMIT 1`, action, outcome).
		Scan(&actor, &target, &sessionID, &connection))
	return actor, target, sessionID, connection
}

// everyEvent flattens every recorded event, identifiers included, so a test can
// assert that a name or a secret never entered the audit trail.
func everyEvent(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var events string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(
		coalesce(actor_id::text,'')||' '||coalesce(target_id::text,'')||' '||
		coalesce(session_id::text,'')||' '||coalesce(connection_id::text,'')||' '||action||' '||outcome, ' '), '')
		FROM auth_events`).Scan(&events))
	return events
}

func grantUsernames(list auth.GrantList) []string {
	names := make([]string, 0, len(list.Grants))
	for _, grant := range list.Grants {
		names = append(names, grant.User.Name)
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

func TestCreateAndRevokeGrantAreIdempotentAndAudited(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	metrics := createConnection(t, s, admin, connectionRequest("metrics-prod"))
	alice, _ := createMember(t, s, admin, "alice")

	created, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.True(t, created.Created)
	require.False(t, created.DryRun)
	require.Equal(t, auth.GrantParty{ID: alice.ID, Name: "alice"}, created.Grant.User)
	require.Equal(t, auth.GrantParty{ID: payments.ID, Name: "payments-prod"}, created.Grant.Connection)
	require.Equal(t, auth.GrantParty{ID: admin.User.ID, Name: admin.User.Username}, created.Grant.CreatedBy)
	require.Equal(t, time.UTC, created.Grant.CreatedAt.Location())
	require.WithinDuration(t, time.Now(), created.Grant.CreatedAt, 5*time.Second)
	require.Equal(t, 1, eventCount(t, pool, "grant.create", "success"))
	actor, target, sessionID, connection := lastGrantEvent(t, pool, "grant.create", "success")
	require.Equal(t, []string{admin.User.ID, alice.ID, admin.ID, payments.ID},
		[]string{actor, target, sessionID, connection})

	// The same operation addressed by UUID on both sides.
	byID, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: metrics.ID}, false)
	require.NoError(t, err)
	require.True(t, byID.Created)
	require.Equal(t, auth.GrantParty{ID: metrics.ID, Name: "metrics-prod"}, byID.Grant.Connection)
	require.Equal(t, 2, eventCount(t, pool, "grant.create", "success"))

	// A repeated grant returns the one that exists and records nothing.
	repeat, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.False(t, repeat.Created)
	require.Equal(t, created.Grant, repeat.Grant)
	require.Equal(t, 2, eventCount(t, pool, "grant.create", "success"))
	require.Equal(t, 2, countRows(t, pool, "grants"))

	revoked, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: payments.ID}, false)
	require.NoError(t, err)
	require.True(t, revoked.Revoked)
	require.False(t, revoked.DryRun)
	require.Equal(t, created.Grant.User, revoked.User)
	require.Equal(t, created.Grant.Connection, revoked.Connection)
	require.Equal(t, 1, eventCount(t, pool, "grant.revoke", "success"))
	actor, target, sessionID, connection = lastGrantEvent(t, pool, "grant.revoke", "success")
	require.Equal(t, []string{admin.User.ID, alice.ID, admin.ID, payments.ID},
		[]string{actor, target, sessionID, connection})

	// Revoking what is not there succeeds and records nothing.
	again, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.False(t, again.Revoked)
	require.Equal(t, revoked.User, again.User)
	require.Equal(t, revoked.Connection, again.Connection)
	require.Equal(t, 1, eventCount(t, pool, "grant.revoke", "success"))
	require.Equal(t, 1, countRows(t, pool, "grants"))

	// Only UUIDs reach an event; no username, connection name, host or secret.
	events := everyEvent(t, pool)
	for _, value := range []string{"alice", "payments-prod", "metrics-prod", sentinelHost, sentinelSecret} {
		require.NotContains(t, events, value)
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
	require.Equal(t, users/2, eventCount(t, pool, "grant.create", "user_not_found"))
	require.Equal(t, users/2, eventCount(t, pool, "grant.revoke", "user_not_found"))
	_, target, _, connection := lastGrantEvent(t, pool, "grant.create", "user_not_found")
	require.Empty(t, target, "an unresolved user has no verified identifier")
	require.Empty(t, connection)

	for _, ref := range []string{"missing-connection", randomTestID(t), "Not A Ref"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: ref}, false)
		code(t, err, auth.ConnectionNotFound)
		require.Equal(t, hintConnectionNotFound, hintOf(t, err), ref)
		_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: ref}, false)
		code(t, err, auth.ConnectionNotFound)
	}
	require.Equal(t, 3, eventCount(t, pool, "grant.create", "connection_not_found"))
	_, target, _, connection = lastGrantEvent(t, pool, "grant.create", "connection_not_found")
	require.Equal(t, alice.ID, target, "the verified user names the denial")
	require.Empty(t, connection)

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
	require.Equal(t, 1, eventCount(t, pool, "grants.list", "forbidden"))
	for action, operation := range operations {
		code(t, operation(aliceSession), auth.Forbidden)
		expected := 1
		if action == "grants.list" {
			expected = 2
		}
		require.Equal(t, expected, eventCount(t, pool, action, "forbidden"), action)
		actor, target, sessionID, _ := lastGrantEvent(t, pool, action, "forbidden")
		require.Equal(t, []string{alice.ID, "", aliceSession.ID}, []string{actor, target, sessionID}, action)
	}
	for action, operation := range operations {
		code(t, operation(revoked), auth.Unauthenticated)
		require.Equal(t, 1, eventCount(t, pool, action, "unauthenticated"), action)
		actor, _, sessionID, _ := lastGrantEvent(t, pool, action, "unauthenticated")
		require.Equal(t, []string{admin.User.ID, revoked.ID}, []string{actor, sessionID}, action)
	}
	events := countRows(t, pool, "auth_events")
	for _, operation := range operations {
		code(t, operation(auth.Session{}), auth.Unauthenticated)
	}
	require.Equal(t, events, countRows(t, pool, "auth_events"), "a caller without a session is not an attempt")

	// A member's own listing is allowed, by either form of their reference,
	// and records nothing.
	for _, ref := range []string{"", "alice", alice.ID} {
		list, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{User: ref})
		require.NoError(t, err, ref)
		require.Empty(t, list.Grants)
		require.False(t, list.Truncated)
	}
	require.Equal(t, events, countRows(t, pool, "auth_events"))
	require.Zero(t, countRows(t, pool, "grants"))
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
	events := countRows(t, pool, "auth_events")

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
	require.Equal(t, events, countRows(t, pool, "auth_events"), "member reads record no event")

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
	require.Equal(t, 1, eventCount(t, pool, "connections.list", "forbidden"))
	require.Equal(t, 1, eventCount(t, pool, "connection.get", "forbidden"))
	events = countRows(t, pool, "auth_events")

	// A grant revoked mid-session takes effect on the next read.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: "payments-prod"}, false)
	require.NoError(t, err)
	after, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, summaryNames(after))
	_, err = s.GetGrantedConnection(t.Context(), aliceSession, "payments-prod")
	code(t, err, auth.ConnectionNotFound)
	require.Equal(t, events+1, countRows(t, pool, "auth_events"), "only the revocation was recorded")
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
	events := countRows(t, pool, "auth_events")

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
	require.Equal(t, events, countRows(t, pool, "auth_events"), "authorization records nothing of its own")

	_, err = s.SetConnectionEnabled(t.Context(), admin, "payments-prod", false, false)
	require.NoError(t, err)
	for _, actor := range []auth.Session{aliceSession, admin} {
		_, err := s.AuthorizeConnection(t.Context(), actor, "payments-prod")
		code(t, err, auth.ConnectionDisabled)
		require.Equal(t, hintConnectionDisabled, hintOf(t, err))
	}
	_, err = s.SetConnectionEnabled(t.Context(), admin, "payments-prod", true, false)
	require.NoError(t, err)
	events = countRows(t, pool, "auth_events")

	// A revoked grant takes effect on the next call despite a valid session.
	_, err = s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: payments.ID}, false)
	require.NoError(t, err)
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "payments-prod")
	code(t, err, auth.ConnectionNotFound)
	require.Equal(t, events+1, countRows(t, pool, "auth_events"), "only the revocation was recorded")

	// A revoked session is refused and recorded; no session at all is not an
	// attempt and records nothing.
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	events = countRows(t, pool, "auth_events")
	_, err = s.AuthorizeConnection(t.Context(), revoked, "payments-prod")
	code(t, err, auth.Unauthenticated)
	require.Equal(t, events+1, countRows(t, pool, "auth_events"))
	actor, _, sessionID, _ := lastGrantEvent(t, pool, "connection.get", "unauthenticated")
	require.Equal(t, []string{admin.User.ID, revoked.ID}, []string{actor, sessionID})
	events = countRows(t, pool, "auth_events")
	_, err = s.AuthorizeConnection(t.Context(), auth.Session{}, "payments-prod")
	code(t, err, auth.Unauthenticated)
	require.Equal(t, events, countRows(t, pool, "auth_events"))
	require.Zero(t, eventCount(t, pool, "connection.get", "success"))
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
			require.Equal(t, hintConnectionGrants(remaining), hintOf(t, err))
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
	// The three dry runs answered the same way and recorded nothing.
	require.Equal(t, 4, eventCount(t, pool, "connection.delete", "connection_in_use"))
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
	grants, events := countRows(t, pool, "grants"), countRows(t, pool, "auth_events")

	created, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, true)
	require.NoError(t, err)
	require.True(t, created.Created)
	require.True(t, created.DryRun)
	require.Equal(t, alice.ID, created.Grant.User.ID)
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
	require.Equal(t, hintConnectionGrants(1), hintOf(t, err))

	require.Equal(t, grants, countRows(t, pool, "grants"))
	require.Equal(t, events, countRows(t, pool, "auth_events"))
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

	var recorded int
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth_events WHERE action='grants.list'`).Scan(&recorded))
	require.Zero(t, recorded, "a successful listing records no event")
}

func TestGrantAuditFailureRollsBack(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	metrics := createConnection(t, s, admin, connectionRequest("metrics-prod"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "metrics-prod"}, false)
	require.NoError(t, err)
	grants, events := countRows(t, pool, "grants"), countRows(t, pool, "auth_events")
	execSQL(t, pool, `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SENTINEL_PRIVATE_DRIVER'; END $$;
		CREATE TRIGGER reject_event BEFORE INSERT ON auth_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)

	for name, operation := range map[string]func() error{
		"create": func() error {
			_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
			return err
		},
		"revoke": func() error {
			_, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "metrics-prod"}, false)
			return err
		},
		"unknown user": func() error {
			_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "nobody-here", Connection: "metrics-prod"}, false)
			return err
		},
		"member": func() error {
			_, err := s.ListGrants(t.Context(), aliceSession, auth.GrantFilter{User: "personal-admin"})
			return err
		},
	} {
		err := operation()
		code(t, err, auth.ServiceUnavailable)
		require.NotContains(t, err.Error(), "SENTINEL", name)
	}
	// Operations that record no event keep working: the reads, and the two
	// idempotent no-ops that commit without one.
	repeat, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: alice.ID, Connection: metrics.ID}, false)
	require.NoError(t, err)
	require.False(t, repeat.Created)
	absent, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.False(t, absent.Revoked)
	list, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Len(t, list.Grants, 1)
	granted, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod"}, summaryNames(granted))
	_, err = s.AuthorizeConnection(t.Context(), aliceSession, "metrics-prod")
	require.NoError(t, err)

	require.Equal(t, grants, countRows(t, pool, "grants"))
	require.Equal(t, events, countRows(t, pool, "auth_events"))
	execSQL(t, pool, `DROP TRIGGER reject_event ON auth_events`)
	created, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{User: "alice", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	require.True(t, created.Created)
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
	events := countRows(t, pool, "auth_events")
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
	require.Equal(t, events, countRows(t, pool, "auth_events"), "a timed-out mutation records nothing")
	require.Zero(t, countRows(t, pool, "grants"))

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
		require.Equal(t, hintConnectionGrants(1), hintOf(t, deleteErr))
	}
	require.Equal(t, countRows(t, pool, "connections"), countRows(t, pool, "grants"))
}
