package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

// usersInvoke runs one command with an injected hidden-input adapter so tests
// can prove when the prompt is (not) reached.
func usersInvoke(t *testing.T, reader HiddenPasswordReader, stdin string, args ...string) (int, Result, string, string) {
	t.Helper()
	var out, prompt bytes.Buffer
	exit := RunWithIO(context.Background(), append([]string{"clavis"}, args...), IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &prompt, ReadPassword: reader,
	})
	return exit, decode(t, out.String()), out.String(), prompt.String()
}

func loginCLI(t *testing.T, server *httptest.Server, password auth.Secret) {
	t.Helper()
	exit, _, _ := cliInvoke(t, string(password), "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
	require.Equal(t, 0, exit)
}

func testRecord(username string) auth.UserRecord {
	return auth.UserRecord{ID: testUserID(), Username: username, Role: auth.Member, CreatedAt: time.Now().UTC().Truncate(time.Second)}
}

func TestUsersWorkflow(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	self := testIdentity().User.ID
	// Characters that need JSON escaping must survive the wire unchanged.
	secret := `pw"\/` + "\x01<>&" + string(testToken())

	exit, result, output := cliInvoke(t, secret+"\n", "users", "create", "--username=alice", "--password-stdin", "--server", server.URL)
	require.Equal(t, 0, exit)
	require.True(t, result.OK)
	record, ok := result.Data.(map[string]any)
	require.True(t, ok)
	require.ElementsMatch(t, []string{"id", "username", "role", "disabled", "createdAt"}, keys(record))
	require.Equal(t, "alice", record["username"])
	require.Equal(t, "member", record["role"])
	require.Equal(t, false, record["disabled"])
	require.NotContains(t, output, "password")
	require.False(t, strings.Contains(output, string(password)))
	require.False(t, strings.Contains(output, secret[len(secret)-43:]))
	alice, _ := record["id"].(string)
	require.True(t, auth.ValidUserID(alice))
	expected, err := json.Marshal(auth.CreateUserRequest{Username: "alice", Password: auth.Secret(secret)})
	require.NoError(t, err)
	fixture.mu.Lock()
	require.Equal(t, string(expected), string(fixture.createBody))
	require.True(t, strings.HasPrefix(string(fixture.createBody), `{"username":"alice","password":"`))
	fixture.mu.Unlock()

	exit, result, output = cliInvoke(t, "", "users", "list", "--server", server.URL)
	require.Equal(t, 0, exit)
	list, ok := result.Data.(map[string]any)
	require.True(t, ok)
	require.Len(t, list["users"], 2)
	require.Equal(t, false, list["truncated"])
	require.NotContains(t, output, "password")
	fixture.mu.Lock()
	for token := range fixture.sessions {
		require.False(t, strings.Contains(output, string(token)))
	}
	fixture.mu.Unlock()

	mutation := func(args ...string) (Result, map[string]any) {
		t.Helper()
		exit, result, output := cliInvoke(t, "", append(args, "--server", server.URL)...)
		require.Equal(t, 0, exit, "%s: %+v", strings.Join(args, " "), result.Error)
		require.NotContains(t, output, "password")
		value, ok := result.Data.(map[string]any)
		require.True(t, ok)
		user, ok := value["user"].(map[string]any)
		require.True(t, ok)
		return result, user
	}
	result, user := mutation("users", "block", "--user", strings.ToUpper(alice))
	require.Equal(t, true, result.Data.(map[string]any)["sessionsRevoked"])
	require.Equal(t, true, user["disabled"])
	result, user = mutation("users", "unblock", "--user", alice)
	require.Equal(t, false, result.Data.(map[string]any)["sessionsRevoked"])
	require.Equal(t, false, user["disabled"])

	replacement := testToken()
	exit, result, output, prompt := usersInvoke(t, func(ctx context.Context, input io.Reader, prompt io.Writer) ([]byte, error) {
		_, err := io.WriteString(prompt, "Password: ")
		return []byte(replacement), err
	}, "", "users", "reset-password", "--user", alice, "--server", server.URL)
	require.Equal(t, 0, exit)
	require.Equal(t, "Password: ", prompt)
	require.Equal(t, true, result.Data.(map[string]any)["sessionsRevoked"])
	require.False(t, strings.Contains(output, string(replacement)))
	require.NotContains(t, output, "password")

	exit, result, _ = cliInvoke(t, string(replacement), "users", "create", "--username=alice", "--password-stdin", "--server", server.URL)
	require.Equal(t, 1, exit)
	_, taken, _ := auth.LookupFailure(auth.UsernameTaken)
	require.Equal(t, &Error{taken.Code, taken.Message}, result.Error)
	// Self-block and self-demotion are refused before any guard or mutation.
	_, selfTarget, _ := auth.LookupFailure(auth.SelfTarget)
	for _, args := range [][]string{{"users", "block", "--user", self}, {"users", "set-role", "--user", self, "--role=member"}} {
		fixture.mu.Lock()
		before := fixture.requests
		fixture.mu.Unlock()
		exit, result, output = cliInvoke(t, "", append(args, "--server", server.URL)...)
		require.Equal(t, 1, exit)
		require.Equal(t, &Error{selfTarget.Code, selfTarget.Message}, result.Error)
		require.Nil(t, result.Data)
		require.NotContains(t, output, "password")
		fixture.mu.Lock()
		require.Equal(t, before+1, fixture.requests, "exactly one request for %v", args)
		require.Equal(t, auth.UserRecord{ID: self, Username: "cli-test", Role: auth.Admin, CreatedAt: fixture.users[0].CreatedAt}, fixture.users[0])
		fixture.mu.Unlock()
	}
	exit, result, _ = cliInvoke(t, "", "users", "block", "--user", testUserID(), "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.UserNotFound, result.Error.Code)
	_, user = mutation("users", "set-role", "--user", alice, "--role=admin")
	require.Equal(t, "admin", user["role"])
	_, user = mutation("users", "set-role", "--user", alice, "--role=member")
	require.Equal(t, "member", user["role"])
	// Another administrator demotes the actor; the next request re-reads the role.
	fixture.mu.Lock()
	fixture.users[0].Role = auth.Member
	fixture.mu.Unlock()

	// A member's stored session: every command is one forbidden request.
	_, forbidden, _ := auth.LookupFailure(auth.Forbidden)
	for _, args := range [][]string{
		{"users", "list"}, {"users", "create", "--username=bob", "--password-stdin"},
		{"users", "block", "--user", alice}, {"users", "unblock", "--user", alice},
		{"users", "reset-password", "--user", alice, "--password-stdin"},
		{"users", "set-role", "--user", alice, "--role=member"},
	} {
		fixture.mu.Lock()
		before := fixture.requests
		fixture.mu.Unlock()
		exit, result, _ = cliInvoke(t, string(replacement), append(args, "--server", server.URL)...)
		require.Equal(t, 1, exit)
		require.Equal(t, &Error{forbidden.Code, forbidden.Message}, result.Error)
		fixture.mu.Lock()
		require.Equal(t, before+1, fixture.requests, "exactly one request for %v", args)
		require.Len(t, fixture.users, 2)
		fixture.mu.Unlock()
	}
}

func keys(value map[string]any) []string {
	names := make([]string, 0, len(value))
	for name := range value {
		names = append(names, name)
	}
	return names
}

func TestUsersArgumentsRejectedBeforeIO(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	id := testIdentity().User.ID
	forbidden := HiddenPasswordReader(func(context.Context, io.Reader, io.Writer) ([]byte, error) {
		t.Fatal("invalid arguments must be rejected before reading a password")
		return nil, nil
	})
	for _, tc := range []struct {
		args           []string
		noninteractive bool
	}{
		{args: []string{"users", "block", "--user=invalid"}},
		{args: []string{"users", "unblock", "--user=7fde7ce1-cc8d-4de8-a9c0"}},
		{args: []string{"users", "reset-password", "--user=invalid", "--password-stdin"}},
		{args: []string{"users", "reset-password"}},
		{args: []string{"users", "set-role", "--user", id, "--role=owner"}},
		{args: []string{"users", "set-role", "--user", id}},
		{args: []string{"users", "set-role", "--role=admin"}},
		{args: []string{"users", "list", "extra"}},
		{args: []string{"users", "block", "--user", id, "extra"}},
		{args: []string{"users", "create", "--password-stdin"}},
		{args: []string{"users", "create", "--username=UPPER", "--password-stdin"}},
		{args: []string{"users", "create", "--username=alice", "--password=value"}},
		{args: []string{"users", "create", "--username=alice"}, noninteractive: true},
		{args: []string{"users", "reset-password", "--user", id}, noninteractive: true},
		{args: []string{"users", "unknown"}},
		{args: []string{"users", "list", "--timeout=0"}},
		{args: []string{"users", "list", "--server=http://localhost:8080"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			reader := forbidden
			if tc.noninteractive {
				reader = ReadTerminalPassword
			}
			args := append([]string{"--output=text"}, tc.args...)
			exit, result, output, prompt := usersInvoke(t, reader, string(testToken()), args...)
			require.Equal(t, 2, exit)
			require.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
			require.Empty(t, prompt)
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.admin)
}

func TestUsersRequireCachedSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t, testToken())
	id := testIdentity().User.ID
	for _, args := range [][]string{
		{"users", "list"}, {"users", "create", "--username=alice", "--password-stdin"},
		{"users", "block", "--user", id}, {"users", "unblock", "--user", id},
		{"users", "reset-password", "--user", id, "--password-stdin"},
		{"users", "set-role", "--user", id, "--role=admin"},
	} {
		exit, result, _ := cliInvoke(t, string(testToken()), append(args, "--server", server.URL)...)
		require.Equal(t, 1, exit)
		require.Equal(t, auth.Unauthenticated, result.Error.Code)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.requests)
}

func TestUsersTransportStrictResponses(t *testing.T) {
	record := testRecord("alice")
	validRecord, err := json.Marshal(record)
	require.NoError(t, err)
	validMutation, err := json.Marshal(auth.UserMutation{User: record, SessionsRevoked: true})
	require.NoError(t, err)
	validList, err := json.Marshal(auth.UserList{Users: []auth.UserRecord{record}})
	require.NoError(t, err)
	block := userPath(auth.UserBlockPath, record.ID)
	unblock := userPath(auth.UserUnblockPath, record.ID)
	errorBody := func(code string) string {
		return `{"error":{"code":"` + code + `","message":"sentinel"}}`
	}
	for _, tc := range []struct {
		name        string
		method      string
		path        string
		output      any
		status      int
		contentType string
		body        string
	}{
		{"create-wrong-status", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 200, "application/json", string(validRecord)},
		{"block-201", http.MethodPost, block, &auth.UserMutation{}, 201, "application/json", string(validMutation)},
		{"list-201", http.MethodGet, auth.UsersPath, &auth.UserList{}, 201, "application/json", string(validList)},
		{"list-element-alias", http.MethodGet, auth.UsersPath, &auth.UserList{}, 200, "application/json", strings.Replace(string(validList), `"id":`, `"ID":`, 1)},
		{"list-element-unknown", http.MethodGet, auth.UsersPath, &auth.UserList{}, 200, "application/json", strings.Replace(string(validList), `"role"`, `"passwordHash":"sentinel","role"`, 1)},
		{"list-element-bad-uuid", http.MethodGet, auth.UsersPath, &auth.UserList{}, 200, "application/json", strings.Replace(string(validList), record.ID, "sentinel", 1)},
		{"list-wrong-shape", http.MethodGet, auth.UsersPath, &auth.UserList{}, 200, "application/json", string(validRecord)},
		{"list-null", http.MethodGet, auth.UsersPath, &auth.UserList{}, 200, "application/json", `null`},
		{"mutation-unknown", http.MethodPost, block, &auth.UserMutation{}, 200, "application/json", strings.TrimSuffix(string(validMutation), "}") + `,"token":"sentinel"}`},
		{"mutation-alias", http.MethodPost, block, &auth.UserMutation{}, 200, "application/json", strings.Replace(string(validMutation), `"sessionsRevoked"`, `"SessionsRevoked"`, 1)},
		{"mutation-wrong-shape", http.MethodPost, block, &auth.UserMutation{}, 200, "application/json", string(validRecord)},
		{"mutation-empty", http.MethodPost, block, &auth.UserMutation{}, 200, "application/json", `{}`},
		{"record-non-utc", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 201, "application/json", strings.Replace(string(validRecord), `Z"`, `+02:00"`, 1)},
		{"record-bad-role", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 201, "application/json", strings.Replace(string(validRecord), `"member"`, `"owner"`, 1)},
		{"record-with-password", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 201, "application/json", strings.TrimSuffix(string(validRecord), "}") + `,"password":"sentinel"}`},
		{"record-html", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 201, "text/html", string(validRecord)},
		{"record-malformed", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 201, "application/json", `{"id":"sentinel"`},
		{"taken-on-block", http.MethodPost, block, &auth.UserMutation{}, 409, "application/json", errorBody(auth.UsernameTaken)},
		{"taken-on-list", http.MethodGet, auth.UsersPath, &auth.UserList{}, 409, "application/json", errorBody(auth.UsernameTaken)},
		{"last-admin-on-unblock", http.MethodPost, unblock, &auth.UserMutation{}, 409, "application/json", errorBody(auth.LastAdministrator)},
		{"last-admin-on-create", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 409, "application/json", errorBody(auth.LastAdministrator)},
		{"self-target-on-unblock", http.MethodPost, unblock, &auth.UserMutation{}, 409, "application/json", errorBody(auth.SelfTarget)},
		{"self-target-on-password", http.MethodPost, userPath(auth.UserPasswordPath, record.ID), &auth.UserMutation{}, 409, "application/json", errorBody(auth.SelfTarget)},
		{"self-target-on-create", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 409, "application/json", errorBody(auth.SelfTarget)},
		{"self-target-on-list", http.MethodGet, auth.UsersPath, &auth.UserList{}, 409, "application/json", errorBody(auth.SelfTarget)},
		{"self-target-wrong-status", http.MethodPost, block, &auth.UserMutation{}, 403, "application/json", errorBody(auth.SelfTarget)},
		{"not-found-on-list", http.MethodGet, auth.UsersPath, &auth.UserList{}, 404, "application/json", errorBody(auth.UserNotFound)},
		{"not-found-on-create", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 404, "application/json", errorBody(auth.UserNotFound)},
		{"rate-limited-on-block", http.MethodPost, block, &auth.UserMutation{}, 429, "application/json", errorBody(auth.RateLimited)},
		{"rate-limited-on-list", http.MethodGet, auth.UsersPath, &auth.UserList{}, 429, "application/json", errorBody(auth.RateLimited)},
		{"credentials-on-create", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 401, "application/json", errorBody(auth.InvalidCredentials)},
		{"wrong-status-code", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 403, "application/json", errorBody(auth.UsernameTaken)},
		{"unknown-code", http.MethodPost, auth.UsersPath, &auth.UserRecord{}, 409, "application/json", errorBody("SECRET")},
		{"error-without-message", http.MethodPost, block, &auth.UserMutation{}, 404, "application/json", `{"error":{"code":"USER_NOT_FOUND","message":""}}`},
		{"server-error", http.MethodPost, block, &auth.UserMutation{}, 500, "application/json", `{"error":{"code":"SERVICE_UNAVAILABLE","message":"sentinel"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, tc.method, r.Method)
				require.Equal(t, tc.path, r.URL.Path)
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			result := (authTransport{server.URL, time.Second}).call(context.Background(), tc.method, tc.path, testToken(), nil, tc.output)
			require.NotNil(t, result)
			require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
			require.Equal(t, int32(1), calls.Load())
			for _, format := range []string{"json", "text"} {
				var out bytes.Buffer
				require.NoError(t, render(&out, *result, format))
				require.NotContains(t, out.String(), "sentinel")
			}
		})
	}
}

func TestUsersTransportRedirectsAndDocumentedFailures(t *testing.T) {
	record := testRecord("alice")
	routes := []struct {
		method string
		path   string
		output any
	}{
		{http.MethodGet, auth.UsersPath, &auth.UserList{}},
		{http.MethodPost, auth.UsersPath, &auth.UserRecord{}},
		{http.MethodPost, userPath(auth.UserBlockPath, record.ID), &auth.UserMutation{}},
		{http.MethodPost, userPath(auth.UserUnblockPath, record.ID), &auth.UserMutation{}},
		{http.MethodPost, userPath(auth.UserPasswordPath, record.ID), &auth.UserMutation{}},
		{http.MethodPost, userPath(auth.UserRolePath, record.ID), &auth.UserMutation{}},
	}
	var destinationCalls, calls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, route := range routes {
		result := (authTransport{redirect.URL, time.Second}).call(context.Background(), route.method, route.path, testToken(), nil, route.output)
		require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
	}
	require.Equal(t, int32(len(routes)), calls.Load(), "mutations must not retry")
	require.Zero(t, destinationCalls.Load())

	common := []string{auth.InvalidArgument, auth.Unauthenticated, auth.Forbidden, auth.ServiceUnavailable, platform.CodeSetupRequired}
	for i, route := range routes {
		codes := append([]string{}, common...)
		switch i {
		case 1:
			codes = append(codes, auth.UsernameTaken, auth.RateLimited)
		case 2, 5:
			codes = append(codes, auth.UserNotFound, auth.LastAdministrator, auth.SelfTarget)
		case 3:
			codes = append(codes, auth.UserNotFound)
		case 4:
			codes = append(codes, auth.UserNotFound, auth.RateLimited)
		}
		for _, code := range codes {
			status, safe, _ := auth.LookupFailure(code)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: platform.Failure{Code: code, Message: string(testToken())}})
			}))
			result := (authTransport{server.URL, time.Second}).call(context.Background(), route.method, route.path, testToken(), nil, route.output)
			server.Close()
			require.NotNil(t, result, "%s %s %s", route.method, route.path, code)
			require.Equal(t, safe.Code, result.Error.Code, "%s %s", route.path, code)
			require.Equal(t, safe.Message, result.Error.Message)
			require.Nil(t, result.Data)
		}
	}
}

func TestUsersTextRendering(t *testing.T) {
	created := time.Date(2026, 9, 11, 10, 30, 0, 0, time.FixedZone("CEST", 2*3600))
	alice := auth.UserRecord{ID: "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba", Username: "alice", Role: auth.Member, CreatedAt: created}
	bob := auth.UserRecord{ID: "0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11", Username: "bob", Role: auth.Admin, Disabled: true, CreatedAt: created}
	lines := "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba alice member enabled\n0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11 bob admin blocked\n"
	user := "User: alice (7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba)\nRole: member\nStatus: enabled\nCreated: 2026-09-11T08:30:00Z\n"
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"list":           {success(auth.UserList{Users: []auth.UserRecord{alice, bob}}), lines},
		"list-truncated": {success(auth.UserList{Users: []auth.UserRecord{alice, bob}, Truncated: true}), lines + "Truncated: list is limited to 1000 users\n"},
		"list-empty":     {success(auth.UserList{Users: []auth.UserRecord{}}), ""},
		"record":         {success(alice), user},
		"mutation":       {success(auth.UserMutation{User: alice, SessionsRevoked: true}), user + "Sessions revoked: true\n"},
		"mutation-kept":  {success(auth.UserMutation{User: bob, SessionsRevoked: false}), strings.Replace(strings.Replace(strings.Replace(user, "alice (7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba)", "bob (0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11)", 1), "member", "admin", 1), "enabled", "blocked", 1) + "Sessions revoked: false\n"},
		"failure":        {failure(auth.LastAdministrator, "At least one enabled administrator must remain", nil), "LAST_ADMINISTRATOR: At least one enabled administrator must remain\n"},
		"self-target":    {failure(auth.SelfTarget, "Administrators cannot block or demote their own account", nil), "SELF_TARGET: Administrators cannot block or demote their own account\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, render(&out, tc.result, "text"))
			require.Equal(t, tc.want, out.String())
			require.NotContains(t, strings.ToLower(out.String()), "password")
		})
	}
}

// A full listing of maximum-length usernames must fit the listing limit, while
// every other route keeps the general response bound and the listing still has
// its own ceiling.
func TestUsersListingBodyLimit(t *testing.T) {
	full := auth.UserList{}
	for n := range auth.MaxUserListing {
		record := testRecord(fmt.Sprintf("u%063d", n))
		record.ID = fmt.Sprintf("%08x-0000-4000-8000-%012x", n, n)
		full.Users = append(full.Users, record)
	}
	fullBody, err := json.Marshal(full)
	require.NoError(t, err)
	require.Greater(t, len(fullBody), auth.MaxResponseBody)
	require.LessOrEqual(t, len(fullBody), auth.MaxListingBody)
	serve := func(t *testing.T, body []byte, method, path string, output any) *Result {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if method == http.MethodPost && path == auth.UsersPath {
				w.WriteHeader(http.StatusCreated)
			}
			_, _ = w.Write(body)
		}))
		defer server.Close()
		return (authTransport{server.URL, time.Second}).call(context.Background(), method, path, testToken(), nil, output)
	}
	var list auth.UserList
	require.Nil(t, serve(t, fullBody, http.MethodGet, auth.UsersPath, &list))
	require.Len(t, list.Users, auth.MaxUserListing)

	padded := append([]byte(strings.Repeat(" ", auth.MaxListingBody)), fullBody...)
	result := serve(t, padded, http.MethodGet, auth.UsersPath, &auth.UserList{})
	require.NotNil(t, result)
	require.Equal(t, "INVALID_RESPONSE", result.Error.Code)

	record, err := json.Marshal(testRecord("alice"))
	require.NoError(t, err)
	oversized := append([]byte(strings.Repeat(" ", auth.MaxResponseBody)), record...)
	result = serve(t, oversized, http.MethodPost, auth.UsersPath, &auth.UserRecord{})
	require.NotNil(t, result)
	require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
}
