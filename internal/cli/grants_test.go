package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

// The hints below are the fixture's application-owned guidance for the grant
// routes. They never echo a submitted value, exactly as the contract requires.
const (
	userNotFoundHint  = "List users to find the username or UUID"
	grantNotFoundHint = "List connections to find the name or UUID"
)

func (f *cliAuthFixture) grantIndex(userID, connectionID string) int {
	for i, grant := range f.grants {
		if grant.User.ID == userID && grant.Connection.ID == connectionID {
			return i
		}
	}
	return -1
}

// serveGrants implements the design's grant route table over the fixture's
// stores: documented statuses, the dryRun query parameter, idempotent create
// and revoke, hints on every failure and the member scope on listing.
func (f *cliAuthFixture) serveGrants(w http.ResponseWriter, r *http.Request, actor auth.Identity, body []byte, fail func(string)) {
	f.grantCalls++
	f.grantQuery = r.URL.RawQuery
	encode := func(status int, value any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	failHint := func(code, hint string) {
		status, safe, _ := auth.LookupFailure(code)
		safe.Hint = hint
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
	}
	list := r.Method == http.MethodGet && r.URL.Path == auth.GrantsPath
	create := r.Method == http.MethodPost && r.URL.Path == auth.GrantsPath
	revoke := r.Method == http.MethodPost && r.URL.Path == auth.GrantRevokePath
	if (!list && !create && !revoke) || (create || revoke) != (len(body) != 0) ||
		(len(body) != 0 && r.Header.Get("Content-Type") != "application/json") {
		fail(auth.InvalidArgument)
		return
	}
	query := r.URL.Query()
	dryRun := false
	for key, values := range query {
		valid := len(values) == 1
		switch key {
		case auth.DryRunQuery:
			valid = valid && values[0] == "true" && !list
			dryRun = true
		case "user", "connection", "limit":
			valid = valid && list
		default:
			valid = false
		}
		if !valid {
			fail(auth.InvalidArgument)
			return
		}
	}
	role := actor.User.Role
	if i := f.userIndex(actor.User.ID); i >= 0 {
		role = f.users[i].Role
	}
	if list {
		f.listGrants(actor, role, query, encode, failHint)
		return
	}
	if role != auth.Admin {
		fail(auth.Forbidden)
		return
	}
	f.grantBody = body
	var input auth.GrantRequest
	if !strictJSON(body, &input) || !auth.ValidUserRef(input.User) || !auth.ValidConnectionRef(input.Connection) {
		fail(auth.InvalidArgument)
		return
	}
	user := f.userRefIndex(input.User)
	if user < 0 {
		failHint(auth.UserNotFound, userNotFoundHint)
		return
	}
	connection := f.connectionIndex(input.Connection)
	if connection < 0 {
		failHint(auth.ConnectionNotFound, grantNotFoundHint)
		return
	}
	party := auth.GrantParty{ID: f.users[user].ID, Name: f.users[user].Username}
	target := auth.GrantParty{ID: f.connections[connection].ID, Name: f.connections[connection].Name}
	existing := f.grantIndex(party.ID, target.ID)
	if revoke {
		if existing >= 0 && !dryRun {
			f.grants = append(f.grants[:existing], f.grants[existing+1:]...)
			f.grantMutations++
		}
		encode(http.StatusOK, auth.GrantRevocation{User: party, Connection: target, Revoked: existing >= 0, DryRun: dryRun})
		return
	}
	if existing >= 0 {
		// An existing grant is returned unchanged with 200: creation is
		// idempotent, so a retrying agent needs no special case.
		encode(http.StatusOK, auth.GrantMutation{Grant: f.grants[existing], DryRun: dryRun})
		return
	}
	granted := auth.Grant{User: party, Connection: target, CreatedAt: time.Now().UTC().Truncate(time.Second),
		CreatedBy: auth.GrantParty{ID: actor.User.ID, Name: actor.User.Username}}
	if dryRun {
		encode(http.StatusOK, auth.GrantMutation{Grant: granted, Created: true, DryRun: true})
		return
	}
	f.grants = append(f.grants, granted)
	f.grantMutations++
	encode(http.StatusCreated, auth.GrantMutation{Grant: granted, Created: true})
}

// listGrants is the one grant route a member may call, and the service scopes
// it: a member sees their own grants and nothing else.
func (f *cliAuthFixture) listGrants(actor auth.Identity, role auth.Role, query map[string][]string,
	encode func(int, any), failHint func(code, hint string)) {
	limit := auth.MaxGrantListing
	if raw := query["limit"]; len(raw) == 1 {
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > auth.MaxGrantListing {
			failHint(auth.InvalidArgument, "--limit accepts 1 to "+strconv.Itoa(auth.MaxGrantListing))
			return
		}
		limit = value
	}
	var user, connection string
	if raw := query["user"]; len(raw) == 1 {
		user = raw[0]
	}
	if raw := query["connection"]; len(raw) == 1 {
		connection = raw[0]
	}
	if role != auth.Admin {
		if user != "" && f.userRefIndex(user) != f.userIndex(actor.User.ID) {
			failHint(auth.Forbidden, "Members may list only their own grants")
			return
		}
		user = actor.User.ID
	}
	matched := []auth.Grant{}
	for _, grant := range f.grants {
		if user != "" && grant.User.ID != strings.ToLower(user) && grant.User.Name != user {
			continue
		}
		if connection != "" && grant.Connection.ID != strings.ToLower(connection) && grant.Connection.Name != connection {
			continue
		}
		matched = append(matched, grant)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].User.Name != matched[j].User.Name {
			return matched[i].User.Name < matched[j].User.Name
		}
		return matched[i].Connection.Name < matched[j].Connection.Name
	})
	truncated := f.grantTruncated
	if len(matched) > limit {
		matched, truncated = matched[:limit], true
	}
	encode(http.StatusOK, auth.GrantList{Grants: matched, Truncated: truncated})
}

// memberFixture signs a member in against the shared fixture and grants them
// one of two connections, which is the shape every member scenario needs.
func memberFixture(t *testing.T) (*cliAuthFixture, *httptest.Server, string, auth.Secret) {
	t.Helper()
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	fixture.mu.Lock()
	granted, other := testConnection("payments-prod-reporting"), testConnection("warehouse-primary")
	other.ID, other.Labels, other.Enabled = testUserID(), map[string]string{"env": "staging"}, false
	fixture.connections = append(fixture.connections, granted, other)
	member := auth.UserRecord{ID: testUserID(), Username: "alice", Role: auth.Member,
		CreatedAt: time.Now().UTC().Truncate(time.Second)}
	fixture.users = append(fixture.users, member)
	fixture.grants = append(fixture.grants, auth.Grant{
		User:       auth.GrantParty{ID: member.ID, Name: member.Username},
		Connection: auth.GrantParty{ID: granted.ID, Name: granted.Name},
		CreatedAt:  time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC),
		CreatedBy:  auth.GrantParty{ID: testIdentity().User.ID, Name: testIdentity().User.Username},
	})
	token := testToken()
	fixture.sessions[token] = auth.Identity{
		User:      auth.User{ID: member.ID, Username: member.Username, Role: auth.Member},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	}
	fixture.mu.Unlock()
	return fixture, server, member.ID, token
}

// runAs replaces the cached credential so the next command runs as the given
// session, which is how a member's own reads are exercised end to end.
func runAs(t *testing.T, server *httptest.Server, token auth.Secret, identity auth.Identity) {
	t.Helper()
	cache, err := openCache(context.Background(), server.URL)
	require.NoError(t, err)
	defer cache.close()
	require.NoError(t, cache.write(cachedSession{Origin: server.URL,
		LoginResponse: auth.LoginResponse{Token: token, Identity: identity}}))
}

func grantsRun(t *testing.T, server *httptest.Server, args ...string) (int, Result, string) {
	t.Helper()
	return cliInvoke(t, "", append(args, "--server", server.URL)...)
}

func grantsText(t *testing.T, server *httptest.Server, args ...string) (int, string) {
	t.Helper()
	var out, prompt bytes.Buffer
	arguments := append([]string{"clavis", "--output=text"}, append(args, "--server", server.URL)...)
	exit := RunWithIO(context.Background(), arguments, IO{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &prompt, ReadPassword: ReadTerminalPassword,
	})
	require.Empty(t, prompt.String())
	return exit, out.String()
}

// TestGrantsWorkflow walks the documented lifecycle over the fixture: grant by
// names, idempotent create, repeated revoke and the rendered text.
func TestGrantsWorkflow(t *testing.T) {
	cliHome(t)
	fixture, server, memberID, _ := memberFixture(t)
	fixture.mu.Lock()
	fixture.grants = nil
	fixture.mu.Unlock()

	exit, result, output := grantsRun(t, server, "grants", "create", "--user", "alice", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.True(t, result.OK)
	granted, ok := result.Data.(map[string]any)["grant"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, map[string]any{"id": memberID, "name": "alice"}, granted["user"])
	require.Equal(t, "payments-prod-reporting", granted["connection"].(map[string]any)["name"])
	require.True(t, auth.ValidUserID(granted["connection"].(map[string]any)["id"].(string)))
	require.Equal(t, "cli-test", granted["createdBy"].(map[string]any)["name"])
	require.Equal(t, true, result.Data.(map[string]any)["created"])
	require.NotContains(t, output, "token")

	// The request body is exactly the two references, sent unchanged.
	expected, err := json.Marshal(auth.GrantRequest{User: "alice", Connection: "payments-prod-reporting"})
	require.NoError(t, err)
	fixture.mu.Lock()
	require.Equal(t, string(expected), string(fixture.grantBody))
	require.Empty(t, fixture.grantQuery, "a committed create sends no query")
	calls, mutations := fixture.grantCalls, fixture.grantMutations
	fixture.mu.Unlock()

	// Creating the same grant again is idempotent: one request, created false.
	exit, result, _ = grantsRun(t, server, "grants", "create", "--user", memberID, "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, false, result.Data.(map[string]any)["created"])
	fixture.mu.Lock()
	require.Equal(t, calls+1, fixture.grantCalls, "an idempotent create is still one request")
	require.Equal(t, mutations, fixture.grantMutations)
	fixture.mu.Unlock()

	exit, output = grantsText(t, server, "grants", "list")
	require.Equal(t, 0, exit)
	require.Regexp(t, `^alice payments-prod-reporting \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\n$`, output)

	// A dry-run revocation reports what it would do and removes nothing.
	exit, result, _ = grantsRun(t, server, "grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting", "--dry-run")
	require.Equal(t, 0, exit)
	require.Equal(t, true, result.Data.(map[string]any)["revoked"])
	require.Equal(t, true, result.Data.(map[string]any)["dryRun"])
	fixture.mu.Lock()
	require.Equal(t, auth.DryRunQuery+"=true", fixture.grantQuery)
	require.Len(t, fixture.grants, 1)
	fixture.mu.Unlock()

	// Revoking twice: the first removes it, the second reports false, both 0.
	exit, output = grantsText(t, server, "grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, "Revoked: true\n", output)
	exit, output = grantsText(t, server, "grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, "Revoked: false\n", output)
	exit, result, _ = grantsRun(t, server, "grants", "list")
	require.Equal(t, 0, exit)
	require.Empty(t, result.Data.(map[string]any)["grants"])
}

// The grant text block is the agent-facing rendering: both names, the time and
// the granting administrator, with the dry-run marker only when it was asked.
func TestGrantsTextRendering(t *testing.T) {
	moment := time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC)
	grant := auth.Grant{
		User:       auth.GrantParty{ID: testIdentity().User.ID, Name: "alice"},
		Connection: auth.GrantParty{ID: "0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11", Name: "payments-prod-reporting"},
		CreatedAt:  moment,
		CreatedBy:  auth.GrantParty{ID: testIdentity().User.ID, Name: "personal-admin"},
	}
	other := grant
	other.Connection = auth.GrantParty{ID: grant.Connection.ID, Name: "warehouse-primary"}
	block := "Grant: alice → payments-prod-reporting\nGranted: 2026-09-11T08:30:00Z by personal-admin\n"
	lines := "alice payments-prod-reporting 2026-09-11T08:30:00Z\nalice warehouse-primary 2026-09-11T08:30:00Z\n"
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"list":           {success(auth.GrantList{Grants: []auth.Grant{grant, other}}), lines},
		"list-truncated": {success(auth.GrantList{Grants: []auth.Grant{grant}, Truncated: true}), strings.Split(lines, "\n")[0] + "\nTruncated: list is limited to 1000 grants\n"},
		"list-empty":     {success(auth.GrantList{Grants: []auth.Grant{}}), ""},
		"created":        {success(auth.GrantMutation{Grant: grant, Created: true}), block + "Created: true\n"},
		"existing":       {success(auth.GrantMutation{Grant: grant}), block + "Created: false\n"},
		"created-dry":    {success(auth.GrantMutation{Grant: grant, Created: true, DryRun: true}), block + "Created: true\nDry run: true\n"},
		"revoked":        {success(auth.GrantRevocation{User: grant.User, Connection: grant.Connection, Revoked: true}), "Revoked: true\n"},
		"revoked-none":   {success(auth.GrantRevocation{User: grant.User, Connection: grant.Connection}), "Revoked: false\n"},
		"revoked-dry":    {success(auth.GrantRevocation{User: grant.User, Connection: grant.Connection, Revoked: true, DryRun: true}), "Revoked: true\nDry run: true\n"},
		"failure-hint": {failureWithHint(auth.UserNotFound, "User not found", userNotFoundHint),
			"USER_NOT_FOUND: User not found\nHint: " + userNotFoundHint + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, render(&out, tc.result, "text"))
			require.Equal(t, tc.want, out.String())
			var encoded bytes.Buffer
			require.NoError(t, render(&encoded, tc.result, "json"))
			require.Equal(t, 1, decode(t, encoded.String()).SchemaVersion)
		})
	}
}

// Every refused reference exits 2 with a hint and reaches no request at all.
func TestGrantsArgumentsRejectedBeforeIO(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	fixture.mu.Lock()
	before := fixture.grantCalls
	fixture.mu.Unlock()
	for _, args := range [][]string{
		{"grants", "create"},
		{"grants", "create", "--user", "alice"},
		{"grants", "create", "--connection", "payments-prod-reporting"},
		{"grants", "create", "--user", "ALICE", "--connection", "payments-prod-reporting"},
		{"grants", "create", "--user", "ab", "--connection", "payments-prod-reporting"},
		{"grants", "create", "--user", "alice", "--connection", "PAYMENTS"},
		{"grants", "create", "--user", "alice", "--connection", "payments-prod-reporting", "extra"},
		{"grants", "revoke", "--user", "1alice", "--connection", "payments-prod-reporting"},
		{"grants", "revoke", "--user", "alice"},
		{"grants", "list", "--user", "ALICE"},
		{"grants", "list", "--connection", "P!"},
		{"grants", "list", "--limit", "0"},
		{"grants", "list", "--limit", "1001"},
		{"grants", "list", "extra"},
		{"grants", "unknown"},
		{"grants", "list", "--timeout=0"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			exit, result, output := grantsRun(t, server, args...)
			require.Equal(t, 2, exit)
			require.Equal(t, auth.InvalidArgument, result.Error.Code)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
		})
	}
	// A non-loopback plain-HTTP origin is refused by the shared origin policy
	// before any group-specific validation runs.
	exit, result, _ := cliInvoke(t, "", "grants", "list", "--server=http://localhost:8080")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.grantCalls, "no request may be made")
}

func TestGrantsDocumentedFailures(t *testing.T) {
	cliHome(t)
	password := testToken()
	_, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	// An unknown user and an unknown connection are the two documented
	// not-found results, each with the fixture's own hint.
	exit, result, _ := grantsRun(t, server, "grants", "create", "--user", "nobody-here", "--connection", "payments-prod-reporting")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.UserNotFound, result.Error.Code)
	require.Equal(t, userNotFoundHint, result.Error.Hint)
	exit, result, _ = grantsRun(t, server, "grants", "revoke", "--user", "cli-test", "--connection", "no-such-connection")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.ConnectionNotFound, result.Error.Code)
	require.Equal(t, grantNotFoundHint, result.Error.Hint)

	// An undocumented code on a grant route is not a result the CLI renders.
	for _, tc := range []struct {
		route apiCall
		code  string
	}{
		{apiCall{http.MethodGet, auth.GrantsPath, "", http.StatusOK}, auth.UserNotFound},
		{apiCall{http.MethodGet, auth.GrantsPath, "", http.StatusOK}, auth.ConnectionNotFound},
		{apiCall{http.MethodPost, auth.GrantsPath, "", http.StatusCreated}, auth.ConnectionExists},
		{apiCall{http.MethodPost, auth.GrantRevokePath, "", http.StatusOK}, auth.ConnectionInUse},
		{apiCall{http.MethodGet, auth.GrantsPath, "", http.StatusOK}, auth.ConnectionDisabled},
		{apiCall{http.MethodPost, auth.GrantsPath, "", http.StatusCreated}, auth.ConnectionDisabled},
		{apiCall{http.MethodPost, auth.GrantRevokePath, "", http.StatusOK}, auth.ConnectionDisabled},
	} {
		hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			status, safe, _ := auth.LookupFailure(tc.code)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
		}))
		var list auth.GrantList
		failed := (authTransport{hostile.URL, time.Second}).send(context.Background(), tc.route, testToken(), nil, &list)
		hostile.Close()
		require.NotNil(t, failed)
		require.Equal(t, "INVALID_RESPONSE", failed.Error.Code, tc.code)
	}
}

// A grant body that is not the documented shape is refused rather than
// rendered: a missing name, a bad timestamp or an unknown member.
func TestGrantsTransportStrictResponses(t *testing.T) {
	valid := `{"grant":{"user":{"id":"7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba","name":"alice"},` +
		`"connection":{"id":"0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11","name":"payments-prod-reporting"},` +
		`"createdAt":"2026-09-11T08:30:00Z",` +
		`"createdBy":{"id":"7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba","name":"personal-admin"}},"created":true,"dryRun":false}`
	for name, body := range map[string]string{
		"valid":             valid,
		"unknown member":    strings.Replace(valid, `"created":true`, `"created":true,"extra":1`, 1),
		"missing user name": strings.Replace(valid, `"name":"alice"`, `"name":""`, 1),
		"uppercase name":    strings.Replace(valid, `"name":"alice"`, `"name":"ALICE"`, 1),
		"bad user id":       strings.Replace(valid, `"id":"7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"`, `"id":"nope"`, 1),
		"offset time":       strings.Replace(valid, `"2026-09-11T08:30:00Z"`, `"2026-09-11T08:30:00+02:00"`, 1),
		"zero time":         strings.Replace(valid, `"2026-09-11T08:30:00Z"`, `"0001-01-01T00:00:00Z"`, 1),
		"bad connection":    strings.Replace(valid, `"payments-prod-reporting"`, `"PAYMENTS"`, 1),
		"case alias":        strings.Replace(valid, `"created"`, `"Created"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			var mutation auth.GrantMutation
			route := apiCall{http.MethodPost, auth.GrantsPath, "", http.StatusCreated}
			failed := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), &auth.GrantRequest{}, &mutation)
			if name == "valid" {
				require.Nil(t, failed)
				require.Equal(t, "alice", mutation.Grant.User.Name)
				return
			}
			require.NotNil(t, failed)
			require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
		})
	}
}

func TestGrantsRequireCachedSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t, testToken())
	for _, args := range [][]string{
		{"grants", "list"},
		{"grants", "create", "--user", "alice", "--connection", "payments-prod-reporting"},
		{"grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting"},
	} {
		exit, result, _ := grantsRun(t, server, args...)
		require.Equal(t, 1, exit)
		require.Equal(t, auth.Unauthenticated, result.Error.Code)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.grantCalls)
}

// A member sees only their own grants, only their granted connections, and the
// reduced projection of each: no target, no bounds, no timestamps.
func TestMemberReadsAreScopedAndReduced(t *testing.T) {
	cliHome(t)
	fixture, server, memberID, token := memberFixture(t)
	fixture.mu.Lock()
	fixture.grants = append(fixture.grants, auth.Grant{
		User:       auth.GrantParty{ID: testIdentity().User.ID, Name: "cli-test"},
		Connection: auth.GrantParty{ID: fixture.connections[1].ID, Name: fixture.connections[1].Name},
		CreatedAt:  time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC),
		CreatedBy:  auth.GrantParty{ID: testIdentity().User.ID, Name: "cli-test"},
	})
	fixture.mu.Unlock()
	runAs(t, server, token, auth.Identity{
		User:      auth.User{ID: memberID, Username: "alice", Role: auth.Member},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	})

	// grants list is scoped by the server, not by a flag the member passes.
	exit, output := grantsText(t, server, "grants", "list")
	require.Equal(t, 0, exit)
	require.Equal(t, "alice payments-prod-reporting 2026-09-11T08:30:00Z\n", output)
	require.NotContains(t, output, "warehouse-primary")

	// The listing carries the reduced projection and nothing else.
	exit, result, _ := grantsRun(t, server, "connections", "list")
	require.Equal(t, 0, exit, "%+v", result.Error)
	listed := result.Data.(map[string]any)["connections"].([]any)
	require.Len(t, listed, 1)
	summary := listed[0].(map[string]any)
	require.Equal(t, "payments-prod-reporting", summary["name"])
	for _, absent := range []string{"target", "statementTimeoutMs", "maxRows", "maxBytes", "createdAt", "updatedAt"} {
		require.NotContains(t, keys(summary), absent)
	}
	for _, present := range []string{"id", "name", "title", "description", "scope", "provider", "labels", "enabled", "lastCheck"} {
		require.Contains(t, keys(summary), present)
	}

	// A selector narrows a member's listing exactly as an administrator's.
	exit, result, _ = grantsRun(t, server, "connections", "list", "--selector", "env=staging")
	require.Equal(t, 0, exit)
	require.Empty(t, result.Data.(map[string]any)["connections"])

	exit, output = grantsText(t, server, "connections", "get", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, "Connection: payments-prod-reporting\nID: 7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba\n"+
		"Title: Payments reporting\nProvider: postgresql\nLabels: env=prod team=data\n"+
		"Status: enabled\nLast check: never\n", output)
	require.NotContains(t, output, "Target:")
	require.NotContains(t, output, "Max rows:")

	// An ungranted connection is absent, not disclosed.
	exit, result, _ = grantsRun(t, server, "connections", "get", "--connection", "warehouse-primary")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.ConnectionNotFound, result.Error.Code)

	// whoami names what the member may use.
	exit, output = grantsText(t, server, "whoami")
	require.Equal(t, 0, exit)
	require.Contains(t, output, "Role: member\n")
	require.Contains(t, output, "Connections: payments-prod-reporting\n")

	// Every mutating connection route stays administrator-only.
	for _, args := range [][]string{
		{"connections", "check", "--connection", "payments-prod-reporting"},
		{"connections", "disable", "--connection", "payments-prod-reporting"},
		{"grants", "create", "--user", "alice", "--connection", "payments-prod-reporting"},
		{"grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting"},
	} {
		exit, result, _ = grantsRun(t, server, args...)
		require.Equal(t, 1, exit, args)
		require.Equal(t, auth.Forbidden, result.Error.Code, args)
	}
}

// A member's whoami with no grants at all names nothing rather than claiming
// access, and an administrator's identity carries no list.
func TestWhoamiConnectionsAreMemberOnly(t *testing.T) {
	cliHome(t)
	fixture, server, memberID, token := memberFixture(t)
	fixture.mu.Lock()
	fixture.grants = nil
	fixture.mu.Unlock()
	runAs(t, server, token, auth.Identity{
		User:      auth.User{ID: memberID, Username: "alice", Role: auth.Member},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	})
	exit, result, output := grantsRun(t, server, "whoami")
	require.Equal(t, 0, exit)
	require.NotContains(t, keys(result.Data.(map[string]any)), "connections")
	require.NotContains(t, output, "token")

	// The administrator's own session reports no connections at all.
	password := testToken()
	_, adminServer := newCLIFixture(t, password)
	loginCLI(t, adminServer, password)
	exit, output = grantsText(t, adminServer, "whoami")
	require.Equal(t, 0, exit)
	require.Contains(t, output, "Role: admin\n")
	require.NotContains(t, output, "Connections:")
}

// A response that mixes the two documented connection shapes matches neither
// and is refused rather than rendered with missing or extra fields.
func TestConnectionReadsRefuseMixedShapes(t *testing.T) {
	full, err := json.Marshal(testConnection("payments-prod-reporting"))
	require.NoError(t, err)
	summary, err := json.Marshal(testConnection("payments-prod-reporting").Summary())
	require.NoError(t, err)
	var withTarget map[string]any
	require.NoError(t, json.Unmarshal(summary, &withTarget))
	withTarget["target"] = map[string]string{"url": "postgres://reporting@db:5432/payments"}
	mixed, err := json.Marshal(withTarget)
	require.NoError(t, err)
	var withoutBounds map[string]any
	require.NoError(t, json.Unmarshal(full, &withoutBounds))
	delete(withoutBounds, "maxRows")
	partial, err := json.Marshal(withoutBounds)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		body  []byte
		valid bool
	}{
		"full record":      {full, true},
		"member summary":   {summary, true},
		"summary + target": {mixed, false},
		"record - bounds":  {partial, false},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			var record connectionRecord
			route := apiCall{http.MethodGet, auth.ConnectionsPath + "/payments-prod-reporting", "", http.StatusOK}
			failed := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), nil, &record)
			if !tc.valid {
				require.NotNil(t, failed)
				require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
				return
			}
			require.Nil(t, failed)
			if name == "full record" {
				require.IsType(t, auth.Connection{}, record.data())
				return
			}
			require.IsType(t, auth.ConnectionSummary{}, record.data())
		})
	}
}

// Administrative targets travel unchanged: the CLI accepts a username as
// readily as a UUID and never rewrites it.
func TestUserReferencesAreSentUnchanged(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	secret := testToken()
	exit, result, _ := cliInvoke(t, string(secret)+"\n", "users", "create", "--username=alice", "--password-stdin", "--server", server.URL)
	require.Equal(t, 0, exit, "%+v", result.Error)
	created := result.Data.(map[string]any)["id"].(string)

	for _, reference := range []string{"alice", created, strings.ToUpper(created)} {
		exit, result, _ = grantsRun(t, server, "users", "block", "--user", reference)
		require.Equal(t, 0, exit, reference)
		require.Equal(t, created, result.Data.(map[string]any)["user"].(map[string]any)["id"])
		exit, _, _ = grantsRun(t, server, "users", "unblock", "--user", reference)
		require.Equal(t, 0, exit, reference)
	}
	exit, result, _ = grantsRun(t, server, "sessions", "revoke", "--user", "alice")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.Equal(t, true, result.Data.(map[string]any)["revoked"])
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, 1, fixture.revoke)

	// A username that no account carries is the documented not-found result.
	_, server = newCLIFixture(t, password)
	loginCLI(t, server, password)
	exit, result, _ = grantsRun(t, server, "users", "block", "--user", "nobody-here")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.UserNotFound, result.Error.Code)
}

// A UUID-shaped username cannot be created, and the refusal explains the rule
// so an agent does not retry the same name.
func TestUserCreationRefusesUUIDShapedNames(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	before := fixture.admin
	exit, result, _ := cliInvoke(t, string(testToken())+"\n", "users", "create",
		"--username="+testIdentity().User.ID, "--password-stdin", "--server", server.URL)
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	require.Equal(t, auth.UsernameHint, result.Error.Hint)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.admin, "an invalid username never reaches the server")
}
