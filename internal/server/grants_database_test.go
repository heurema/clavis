package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/auth"
)

// The grant routes and the member views end to end against PostgreSQL: the
// bodies are the DTOs the CLI marshals, and both sessions run through the
// same handler the server mounts.
func TestRealHTTPGrantRoutesRoundTrip(t *testing.T) {
	pool, path, password := serverDatabase(t)
	handler := realHandler(t, pool, path)
	body := func(value any) string { return jsonBody(t, value) }
	login := func(username string, secret auth.Secret) http.Header {
		return bearerLogin(t, handler, username, secret)
	}
	send := func(headers http.Header, method, route, payload string) *httptest.ResponseRecorder {
		return sendJSON(t, handler, headers, method, route, payload)
	}
	admin := login("personal-admin", password)

	memberPassword := auth.Secret("member-password-fixture-1")
	response := send(admin, "POST", auth.UsersPath, body(auth.CreateUserRequest{Username: "alice", Password: memberPassword}))
	require.Equal(t, 201, response.Code)
	var created auth.UserRecord
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &created))
	target, secret := probeTarget(t)
	response = send(admin, "POST", auth.ConnectionsPath, body(auth.CreateConnectionRequest{
		Name: "ledger-primary", Title: "Ledger", Provider: auth.ProviderPostgreSQL, Target: target,
		Labels: map[string]string{"env": "prod"}, Secret: secret,
	}))
	require.Equal(t, 201, response.Code)
	var connection auth.Connection
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &connection))
	response = send(admin, "POST", auth.ConnectionsPath, body(auth.CreateConnectionRequest{
		Name: "metrics-eu", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": "http://127.0.0.1:8428", "auth": "none"}, Labels: map[string]string{},
	}))
	require.Equal(t, 201, response.Code)
	member := login("alice", memberPassword)

	// Before any grant the member sees nothing and cannot administer.
	response = send(member, "GET", auth.WhoAmIPath, "")
	require.Equal(t, 200, response.Code)
	var identity auth.Identity
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &identity))
	require.Empty(t, identity.Connections)
	response = send(member, "GET", auth.ConnectionsPath, "")
	require.Equal(t, 200, response.Code)
	require.JSONEq(t, `{"connections":[],"truncated":false}`, response.Body.String())
	response = send(member, "POST", auth.GrantsPath, body(auth.GrantRequest{User: "alice", Connection: "ledger-primary"}))
	require.Equal(t, 403, response.Code)

	// Grant by username and name; a dry run first leaves nothing.
	grant := body(auth.GrantRequest{User: "alice", Connection: "ledger-primary"})
	response = send(admin, "POST", auth.GrantsPath+"?dryRun=true", grant)
	require.Equal(t, 200, response.Code)
	var rows int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM grants`).Scan(&rows))
	require.Zero(t, rows)
	response = send(admin, "POST", auth.GrantsPath, grant)
	require.Equal(t, 201, response.Code)
	var mutation auth.GrantMutation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.True(t, mutation.Created)
	require.Equal(t, auth.Recipient{Kind: auth.RecipientUser, ID: created.ID, Name: "alice"}, mutation.Grant.Recipient)
	require.Equal(t, auth.GrantParty{ID: connection.ID, Name: "ledger-primary"}, mutation.Grant.Connection)
	require.Equal(t, "personal-admin", mutation.Grant.CreatedBy.Name)
	response = send(admin, "POST", auth.GrantsPath, grant)
	require.Equal(t, 200, response.Code, "a repeated grant is idempotent")
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.False(t, mutation.Created)
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM grants WHERE user_id = $1 AND connection_id = $2`, created.ID, connection.ID).Scan(&rows))
	require.Equal(t, 1, rows, "a repeated grant writes no second row")

	// The member now sees the summary shape and nothing more.
	response = send(member, "GET", auth.WhoAmIPath, "")
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &identity))
	require.Equal(t, []string{"ledger-primary"}, identity.Connections)
	response = send(member, "GET", auth.ConnectionsPath+"?"+url.Values{"selector": {"env=prod"}}.Encode(), "")
	require.Equal(t, 200, response.Code)
	var summaries auth.ConnectionSummaryList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &summaries))
	require.Len(t, summaries.Connections, 1)
	require.Equal(t, "ledger-primary", summaries.Connections[0].Name)
	require.NotContains(t, response.Body.String(), `"target"`)
	require.NotContains(t, response.Body.String(), target["url"])
	response = send(member, "GET", strings.Replace(auth.ConnectionPath, "{connectionID}", "ledger-primary", 1), "")
	require.Equal(t, 200, response.Code)
	require.NotContains(t, response.Body.String(), `"target"`)
	response = send(member, "GET", strings.Replace(auth.ConnectionPath, "{connectionID}", "metrics-eu", 1), "")
	require.Equal(t, 404, response.Code, "an ungranted connection does not exist for a member")
	response = send(member, "GET", auth.GrantsPath, "")
	require.Equal(t, 200, response.Code)
	var list auth.GrantList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &list))
	require.Len(t, list.Grants, 1)
	response = send(member, "GET", auth.GrantsPath+"?user=personal-admin", "")
	require.Equal(t, 403, response.Code)

	// Administrators list with filters and see the join both ways.
	response = send(admin, "GET", auth.GrantsPath+"?connection="+connection.ID, "")
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &list))
	require.Len(t, list.Grants, 1)
	require.Equal(t, "alice", list.Grants[0].Recipient.Name)

	// The delete guard counts grants; disable first so the guard is the only
	// remaining reason.
	response = send(admin, "POST", strings.Replace(auth.ConnectionDisablePath, "{connectionID}", "ledger-primary", 1), "")
	require.Equal(t, 200, response.Code)
	response = send(admin, "POST", strings.Replace(auth.ConnectionDeletePath, "{connectionID}", "ledger-primary", 1)+"?dryRun=true", "")
	require.Equal(t, 409, response.Code)
	require.Contains(t, response.Body.String(), "CONNECTION_IN_USE")
	require.Contains(t, response.Body.String(), "1 grant")
	response = send(member, "GET", auth.ConnectionsPath, "")
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &summaries))
	require.Len(t, summaries.Connections, 1)
	require.False(t, summaries.Connections[0].Enabled, "a disabled granted connection stays visible")

	// Username addressing on an existing user route: block by name.
	response = send(admin, "POST", strings.Replace(auth.UserBlockPath, "{userID}", "alice", 1), "")
	require.Equal(t, 200, response.Code)
	response = send(member, "GET", auth.WhoAmIPath, "")
	require.Equal(t, 401, response.Code, "blocking revokes the member's sessions")
	response = send(admin, "POST", strings.Replace(auth.UserUnblockPath, "{userID}", "alice", 1), "")
	require.Equal(t, 200, response.Code)
	member = login("alice", memberPassword)
	response = send(member, "GET", auth.WhoAmIPath, "")
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &identity))
	require.Equal(t, []string{"ledger-primary"}, identity.Connections, "grants survive blocking")

	// Revoke twice: the second is a no-op; then delete works.
	revoke := body(auth.GrantRequest{User: created.ID, Connection: connection.ID})
	response = send(admin, "POST", auth.GrantRevokePath, revoke)
	require.Equal(t, 200, response.Code)
	var revocation auth.GrantRevocation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &revocation))
	require.True(t, revocation.Revoked)
	require.Equal(t, "alice", revocation.Recipient.Name)
	response = send(admin, "POST", auth.GrantRevokePath, revoke)
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &revocation))
	require.False(t, revocation.Revoked)
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM grants`).Scan(&rows))
	require.Zero(t, rows, "a repeated revocation removes nothing more")
	response = send(member, "GET", auth.ConnectionsPath, "")
	require.Equal(t, 200, response.Code)
	require.JSONEq(t, `{"connections":[],"truncated":false}`, response.Body.String())
	response = send(admin, "POST", strings.Replace(auth.ConnectionDeletePath, "{connectionID}", "ledger-primary", 1), "")
	require.Equal(t, 200, response.Code)
	response = send(admin, "POST", auth.GrantsPath, body(auth.GrantRequest{User: "nobody", Connection: "metrics-eu"}))
	require.Equal(t, 404, response.Code)
	require.Contains(t, response.Body.String(), "USER_NOT_FOUND")
}
