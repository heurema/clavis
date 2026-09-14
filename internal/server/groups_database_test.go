package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/auth"
)

// The group routes, membership and the effective listing end to end against
// PostgreSQL: the bodies are the DTOs the CLI marshals, and the administrator
// and member sessions run through the same handler the server mounts. What
// only real rows can prove is here: one connection reached both directly and
// through a group is listed once for the member and as two configured paths
// for the administrator, and the delete guard's counted hint reaches the wire.
func TestRealHTTPGroupRoutesRoundTrip(t *testing.T) {
	pool, path, password := serverDatabase(t)
	handler := realHandler(t, pool, path)
	rows := func(query string, args ...any) int {
		t.Helper()
		var count int
		require.NoError(t, pool.QueryRow(t.Context(), query, args...).Scan(&count))
		return count
	}
	admin := bearerLogin(t, handler, "personal-admin", password)

	memberPassword := auth.Secret("member-password-fixture-2")
	response := sendJSON(t, handler, admin, "POST", auth.UsersPath,
		jsonBody(t, auth.CreateUserRequest{Username: "alice", Password: memberPassword}))
	require.Equal(t, 201, response.Code)
	var alice auth.UserRecord
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &alice))
	response = sendJSON(t, handler, admin, "POST", auth.UsersPath,
		jsonBody(t, auth.CreateUserRequest{Username: "bob", Password: memberPassword}))
	require.Equal(t, 201, response.Code)
	response = sendJSON(t, handler, admin, "POST", auth.ConnectionsPath, jsonBody(t, auth.CreateConnectionRequest{
		Name: "ledger-primary", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": "http://127.0.0.1:8428", "auth": "none"}, Labels: map[string]string{},
	}))
	require.Equal(t, 201, response.Code)
	var connection auth.Connection
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &connection))
	member := bearerLogin(t, handler, "alice", memberPassword)

	// Create: the dry run answers 200 and writes nothing, the committed create
	// answers 201 with a group that holds neither members nor grants yet.
	request := jsonBody(t, auth.GroupRequest{Name: "finance-managers", Description: "Finance managers"})
	response = sendJSON(t, handler, admin, "POST", auth.GroupsPath+"?dryRun=true", request)
	require.Equal(t, 200, response.Code)
	var mutation auth.GroupMutation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.True(t, mutation.DryRun)
	require.Zero(t, rows(`SELECT count(*) FROM groups`), "a dry run commits nothing")
	response = sendJSON(t, handler, admin, "POST", auth.GroupsPath, request)
	require.Equal(t, 201, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.False(t, mutation.DryRun)
	group := mutation.Group
	require.Equal(t, "finance-managers", group.Name)
	require.Equal(t, "Finance managers", group.Description)
	require.Zero(t, group.Members)
	require.Zero(t, group.Grants)
	require.Equal(t, 1, rows(`SELECT count(*) FROM groups`))

	// A browser cookie is not a CLI session: the group routes are bearer-only,
	// so a cookie-only request is refused before anything is written.
	browser := requestAuth(handler, "POST", "/login",
		url.Values{"username": {"personal-admin"}, "password": {string(password)}}.Encode(),
		http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}})
	require.Equal(t, 303, browser.Code)
	require.Len(t, browser.Result().Cookies(), 1)
	cookie := browser.Result().Cookies()[0]
	response = sendJSON(t, handler, http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}, "POST",
		auth.GroupsPath, jsonBody(t, auth.GroupRequest{Name: "warehouse-readers"}))
	require.Equal(t, 401, response.Code)
	require.Equal(t, 1, rows(`SELECT count(*) FROM groups`), "a cookie-only request mutates nothing")
	// Group operations are administrator-only whatever the transport.
	response = sendJSON(t, handler, member, "GET", auth.GroupsPath, "")
	require.Equal(t, 403, response.Code)

	// Membership is idempotent: the add that created it answers 201, the
	// repeat answers 200 and leaves the stored row alone.
	membership := jsonBody(t, map[string]string{"user": "alice"})
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupMemberAddPath, "finance-managers"), membership)
	require.Equal(t, 201, response.Code)
	var added auth.MembershipMutation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &added))
	require.True(t, added.Added)
	require.Equal(t, auth.GrantParty{ID: group.ID, Name: "finance-managers"}, added.Membership.Group)
	require.Equal(t, auth.GrantParty{ID: alice.ID, Name: "alice"}, added.Membership.User)
	require.Equal(t, "personal-admin", added.Membership.CreatedBy.Name)
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupMemberAddPath, group.ID), membership)
	require.Equal(t, 200, response.Code, "a repeated membership is idempotent")
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &added))
	require.False(t, added.Added)
	require.Equal(t, 1, rows(`SELECT count(*) FROM group_members WHERE group_id = $1`, group.ID))

	// One connection, two configured paths: the group holds a grant and so
	// does the member, which is what makes "listed once" worth proving.
	response = sendJSON(t, handler, admin, "POST", auth.GrantsPath,
		jsonBody(t, auth.GrantRequest{Group: "finance-managers", Connection: "ledger-primary"}))
	require.Equal(t, 201, response.Code)
	var granted auth.GrantMutation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &granted))
	require.True(t, granted.Created)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientGroup, ID: group.ID, Name: "finance-managers"},
		granted.Grant.Recipient)
	response = sendJSON(t, handler, admin, "POST", auth.GrantsPath,
		jsonBody(t, auth.GrantRequest{User: "alice", Connection: "ledger-primary"}))
	require.Equal(t, 201, response.Code)

	// The read routes report what an administrator needs before deleting.
	response = sendJSON(t, handler, admin, "GET", groupPath(auth.GroupPath, "finance-managers"), "")
	require.Equal(t, 200, response.Code)
	var record auth.Group
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &record))
	require.Equal(t, group.ID, record.ID)
	require.Equal(t, 1, record.Members)
	require.Equal(t, 1, record.Grants, "the count is the group's own grants, not the member's direct one")
	response = sendJSON(t, handler, admin, "GET", groupPath(auth.GroupMembersPath, group.ID), "")
	require.Equal(t, 200, response.Code)
	var members auth.MemberList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &members))
	require.False(t, members.Truncated)
	require.Len(t, members.Members, 1)
	require.Equal(t, "alice", members.Members[0].Username)
	require.Equal(t, "personal-admin", members.Members[0].AddedBy.Name)

	// whoami: the connection once whatever the number of paths, and the group
	// beside it, each list with its own truncation flag.
	response = sendJSON(t, handler, member, "GET", auth.WhoAmIPath, "")
	require.Equal(t, 200, response.Code)
	var identity auth.Identity
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &identity))
	require.Equal(t, []string{"ledger-primary"}, identity.Connections, "two paths to one connection list it once")
	require.Equal(t, []string{"finance-managers"}, identity.Groups)
	require.False(t, identity.ConnectionsTruncated)
	require.False(t, identity.GroupsTruncated)

	// The effective listing is provenance: the subject's own record beside one
	// entry per path, the direct one before the one the group supplies.
	response = sendJSON(t, handler, admin, "GET", auth.GrantsEffectivePath+"?user=alice", "")
	require.Equal(t, 200, response.Code)
	var access auth.AccessList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &access))
	require.Equal(t, alice.ID, access.User.ID)
	require.Equal(t, "alice", access.User.Username)
	require.Equal(t, auth.Member, access.User.Role)
	require.False(t, access.User.Disabled)
	require.False(t, access.Truncated)
	require.Len(t, access.Entries, 2)
	require.Equal(t, auth.GrantParty{ID: connection.ID, Name: "ledger-primary"}, access.Entries[0].Connection)
	require.Equal(t, auth.AccessDirect, access.Entries[0].Source)
	require.Nil(t, access.Entries[0].Group)
	require.Equal(t, auth.GrantParty{ID: connection.ID, Name: "ledger-primary"}, access.Entries[1].Connection)
	require.Equal(t, auth.AccessGroup, access.Entries[1].Source)
	require.Equal(t, &auth.GrantParty{ID: group.ID, Name: "finance-managers"}, access.Entries[1].Group)

	// A member reads their own paths, by no reference or by either spelling of
	// their own, and no one else's.
	for _, route := range []string{
		auth.GrantsEffectivePath,
		auth.GrantsEffectivePath + "?user=alice",
		auth.GrantsEffectivePath + "?user=" + alice.ID,
	} {
		response = sendJSON(t, handler, member, "GET", route, "")
		require.Equal(t, 200, response.Code, route)
		var own auth.AccessList
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &own))
		require.Equal(t, access, own, route)
	}
	response = sendJSON(t, handler, member, "GET", auth.GrantsEffectivePath+"?user=bob", "")
	require.Equal(t, 403, response.Code)
	require.Contains(t, response.Body.String(), auth.Forbidden)

	// A group filter asks about access configured for a set of people, so a
	// member is refused whether or not the group exists.
	for _, filter := range []string{"finance-managers", "no-such-group", group.ID} {
		response = sendJSON(t, handler, member, "GET", auth.GrantsPath+"?group="+filter, "")
		require.Equal(t, 403, response.Code, filter)
		require.Contains(t, response.Body.String(), auth.Forbidden, filter)
	}

	// Delete is guarded on the grants that name the group, and the dry run
	// reports the count rather than hiding it, which is the point of asking.
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupDeletePath, "finance-managers")+"?dryRun=true", "")
	require.Equal(t, 409, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, auth.GroupInUse, failure.Error.Code)
	require.Equal(t, "1 grant remains; revoke it with `clavis grants revoke` first.", failure.Error.Hint)
	require.Equal(t, 1, rows(`SELECT count(*) FROM groups`))

	// Revoking the group's grant frees the delete; the member's own grant is
	// a different row and stays.
	response = sendJSON(t, handler, admin, "POST", auth.GrantRevokePath,
		jsonBody(t, auth.GrantRequest{Group: group.ID, Connection: connection.ID}))
	require.Equal(t, 200, response.Code)
	var revocation auth.GrantRevocation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &revocation))
	require.True(t, revocation.Revoked)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientGroup, ID: group.ID, Name: "finance-managers"},
		revocation.Recipient)

	// Removing a membership is idempotent the way adding it is.
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupMemberRemovePath, "finance-managers"), membership)
	require.Equal(t, 200, response.Code)
	var removal auth.MembershipRemoval
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &removal))
	require.True(t, removal.Removed)
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupMemberRemovePath, "finance-managers"), membership)
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &removal))
	require.False(t, removal.Removed, "a repeated removal removes nothing more")
	require.Zero(t, rows(`SELECT count(*) FROM group_members`))

	// A grant-free group deletes and reports the UUID and name it had.
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupDeletePath, "finance-managers"), "")
	require.Equal(t, 200, response.Code)
	var deletion auth.GroupDeletion
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &deletion))
	require.Equal(t, auth.GrantParty{ID: group.ID, Name: "finance-managers"}, deletion.Group)
	require.False(t, deletion.DryRun)
	require.Zero(t, rows(`SELECT count(*) FROM groups`))
	response = sendJSON(t, handler, admin, "POST", groupPath(auth.GroupDeletePath, "finance-managers"), "")
	require.Equal(t, 404, response.Code)
	require.Contains(t, response.Body.String(), auth.GroupNotFound)

	// The member keeps what their own grant supplies and loses the group. The
	// identity is decoded fresh, because an empty list is an absent member
	// rather than an empty array.
	response = sendJSON(t, handler, member, "GET", auth.WhoAmIPath, "")
	require.Equal(t, 200, response.Code)
	var remaining auth.Identity
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &remaining))
	require.Equal(t, []string{"ledger-primary"}, remaining.Connections, "the direct grant outlives the group")
	require.Empty(t, remaining.Groups)
}
