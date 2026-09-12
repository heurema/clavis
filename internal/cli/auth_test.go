package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cliHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "clavis-cli-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	home, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("CLAVIS_SERVER_URL", "http://127.0.0.1:8080")
	return home
}

func testToken() auth.Secret {
	body := make([]byte, 32)
	if _, err := rand.Read(body); err != nil {
		panic("test random generation failed")
	}
	return auth.Secret(base64.RawURLEncoding.EncodeToString(body))
}

func testIdentity() auth.Identity {
	return auth.Identity{User: auth.User{
		ID: "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba", Username: "cli-test", Role: auth.Admin,
	}, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second)}
}

// The fixture rejects undocumented method/body/credential combinations. It is
// intentionally not a substitute for integration with the real server lane.
type cliAuthFixture struct {
	mu       sync.Mutex
	password auth.Secret
	sessions map[auth.Secret]auth.Identity
	// users is the administration store; the actor's role is re-read from it
	// on every administration request, as the real service does.
	users      []auth.UserRecord
	truncated  bool
	createBody []byte
	// connections is the connection store. The raw query, the request bodies
	// and the committed mutations are recorded so tests can pin the wire shape.
	connections   []auth.Connection
	connSecrets   map[string]auth.Secret
	connTruncated bool
	connBody      []byte
	connQuery     string
	connCalls     int
	connMutations int
	connOutcome   auth.CheckOutcome
	requests      int
	login         int
	logout        int
	whoami        int
	revoke        int
	admin         int
}

func newCLIFixture(t *testing.T, password auth.Secret) (*cliAuthFixture, *httptest.Server) {
	t.Helper()
	identity := testIdentity()
	fixture := &cliAuthFixture{password: password, sessions: map[auth.Secret]auth.Identity{},
		connSecrets: map[string]auth.Secret{}, connOutcome: auth.CheckReachable,
		users: []auth.UserRecord{{
			ID: identity.User.ID, Username: identity.User.Username, Role: identity.User.Role,
			CreatedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		}}}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	return fixture, server
}

func (f *cliAuthFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code string) {
		status, safe, _ := auth.LookupFailure(code)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, auth.MaxCredentialBody+1))
	// Only the connection routes document query parameters.
	connections := r.URL.Path == auth.ConnectionsPath || strings.HasPrefix(r.URL.Path, auth.ConnectionsPath+"/")
	if err != nil || len(body) > auth.MaxCredentialBody || r.Header.Get("Cookie") != "" ||
		(r.URL.RawQuery != "" && !connections) || r.Header.Get("Accept") != "application/json" {
		fail(auth.InvalidArgument)
		return
	}
	if r.URL.Path == auth.LoginPath {
		f.login++
		var input auth.LoginRequest
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" ||
			r.Header.Get("Content-Type") != "application/json" || !strictJSON(body, &input) {
			fail(auth.InvalidArgument)
			return
		}
		if input.Username != "cli-test" || input.Password != f.password {
			fail(auth.InvalidCredentials)
			return
		}
		token, identity := testToken(), testIdentity()
		f.sessions[token] = identity
		_ = json.NewEncoder(w).Encode(auth.LoginResponse{Token: token, Identity: identity})
		return
	}
	token := auth.Secret(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	identity, exists := f.sessions[token]
	if !exists || !identity.ExpiresAt.After(time.Now()) {
		fail(auth.Unauthenticated)
		return
	}
	if r.URL.Path == auth.UsersPath || (strings.HasPrefix(r.URL.Path, auth.UsersPath+"/") && !strings.HasSuffix(r.URL.Path, "/sessions/revoke")) {
		f.serveUsers(w, r, identity, body, fail)
		return
	}
	if connections {
		f.serveConnections(w, r, identity, body, fail)
		return
	}
	if len(body) != 0 {
		fail(auth.InvalidArgument)
		return
	}
	switch {
	case r.URL.Path == auth.WhoAmIPath && r.Method == http.MethodGet:
		f.whoami++
		_ = json.NewEncoder(w).Encode(identity)
	case r.URL.Path == auth.LogoutPath && r.Method == http.MethodPost:
		f.logout++
		delete(f.sessions, token)
		_ = json.NewEncoder(w).Encode(auth.Revocation{Revoked: true})
	case r.URL.Path == strings.Replace(auth.RevokePath, "{userID}", identity.User.ID, 1) && r.Method == http.MethodPost:
		f.revoke++
		if identity.User.Role != auth.Admin {
			fail(auth.Forbidden)
			return
		}
		clear(f.sessions)
		_ = json.NewEncoder(w).Encode(auth.Revocation{Revoked: true})
	default:
		fail(auth.InvalidArgument)
	}
}

func (f *cliAuthFixture) userIndex(id string) int {
	for i, user := range f.users {
		if user.ID == id {
			return i
		}
	}
	return -1
}

func (f *cliAuthFixture) enabledAdmins() int {
	count := 0
	for _, user := range f.users {
		if user.Role == auth.Admin && !user.Disabled {
			count++
		}
	}
	return count
}

func (f *cliAuthFixture) revokeUser(id string) {
	for token, identity := range f.sessions {
		if identity.User.ID == id {
			delete(f.sessions, token)
		}
	}
}

func testUserID() string {
	body := make([]byte, 16)
	if _, err := rand.Read(body); err != nil {
		panic("test random generation failed")
	}
	raw := hex.EncodeToString(body)
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}

// serveUsers implements the design's administration route table over the
// fixture's user store, including the last-administrator guard.
func (f *cliAuthFixture) serveUsers(w http.ResponseWriter, r *http.Request, actor auth.Identity, body []byte, fail func(string)) {
	f.admin++
	encode := func(status int, value any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	role := actor.User.Role
	if i := f.userIndex(actor.User.ID); i >= 0 {
		role = f.users[i].Role
	}
	create := r.URL.Path == auth.UsersPath && r.Method == http.MethodPost
	hasBody := create || strings.HasSuffix(r.URL.Path, "/password") || strings.HasSuffix(r.URL.Path, "/role")
	list := r.Method == http.MethodGet && r.URL.Path == auth.UsersPath
	if (r.Method != http.MethodPost && !list) ||
		hasBody != (len(body) != 0) || (hasBody && r.Header.Get("Content-Type") != "application/json") {
		fail(auth.InvalidArgument)
		return
	}
	if role != auth.Admin {
		fail(auth.Forbidden)
		return
	}
	switch {
	case list:
		encode(http.StatusOK, auth.UserList{Users: f.users, Truncated: f.truncated})
	case create:
		f.createBody = body
		var input auth.CreateUserRequest
		if !strictJSON(body, &input) || !auth.ValidUsername(input.Username) || !auth.ValidPassword(input.Password) {
			fail(auth.InvalidArgument)
			return
		}
		for _, user := range f.users {
			if user.Username == input.Username {
				fail(auth.UsernameTaken)
				return
			}
		}
		record := auth.UserRecord{ID: testUserID(), Username: input.Username, Role: auth.Member, CreatedAt: time.Now().UTC().Truncate(time.Second)}
		f.users = append(f.users, record)
		encode(http.StatusCreated, record)
	default:
		id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, auth.UsersPath+"/"), "/")
		i := f.userIndex(id)
		if i < 0 {
			fail(auth.UserNotFound)
			return
		}
		target := &f.users[i]
		lastAdmin := target.Role == auth.Admin && !target.Disabled && f.enabledAdmins() == 1
		revoked := false
		switch action {
		case "block":
			if target.ID == actor.User.ID {
				fail(auth.SelfTarget)
				return
			}
			if lastAdmin {
				fail(auth.LastAdministrator)
				return
			}
			target.Disabled = true
			f.revokeUser(target.ID)
			revoked = true
		case "unblock":
			target.Disabled = false
		case "password":
			var input auth.ResetPasswordRequest
			if !strictJSON(body, &input) || !auth.ValidPassword(input.Password) {
				fail(auth.InvalidArgument)
				return
			}
			f.revokeUser(target.ID)
			revoked = true
		case "role":
			var input auth.SetRoleRequest
			if !strictJSON(body, &input) || !validRole(input.Role) {
				fail(auth.InvalidArgument)
				return
			}
			if input.Role == auth.Member && target.ID == actor.User.ID {
				fail(auth.SelfTarget)
				return
			}
			if input.Role == auth.Member && lastAdmin {
				fail(auth.LastAdministrator)
				return
			}
			target.Role = input.Role
		default:
			fail(auth.InvalidArgument)
			return
		}
		encode(http.StatusOK, auth.UserMutation{User: *target, SessionsRevoked: revoked})
	}
}

func cliInvoke(t *testing.T, stdin string, args ...string) (int, Result, string) {
	t.Helper()
	var out, prompt bytes.Buffer
	exit := RunWithIO(context.Background(), append([]string{"clavis"}, args...), IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &prompt, ReadPassword: ReadTerminalPassword,
	})
	require.Empty(t, prompt.String())
	return exit, decode(t, out.String()), out.String()
}

func TestAuthWorkflow(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	exit, result, output := cliInvoke(t, string(password)+"\r\n", "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
	require.Equal(t, 0, exit)
	require.True(t, result.OK)
	require.False(t, strings.Contains(output, string(password)))
	require.NotContains(t, output, `"token"`)
	fixture.mu.Lock()
	var original auth.Secret
	for token := range fixture.sessions {
		original = token
	}
	fixture.mu.Unlock()
	require.False(t, strings.Contains(output, string(original)))

	// Failed login must preserve the old session and cache.
	exit, result, _ = cliInvoke(t, string(testToken()), "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.InvalidCredentials, result.Error.Code)
	exit, _, _ = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 0, exit)

	// Replacement cleans up only the old cached token.
	exit, _, _ = cliInvoke(t, string(password), "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
	require.Equal(t, 0, exit)
	fixture.mu.Lock()
	_, oldExists := fixture.sessions[original]
	require.False(t, oldExists)
	require.Len(t, fixture.sessions, 1)
	for token, identity := range fixture.sessions {
		identity.User.Role = auth.Member
		fixture.sessions[token] = identity
	}
	fixture.mu.Unlock()
	exit, result, output = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 0, exit)
	require.Contains(t, output, `"role":"member"`, "must use the server, not cached admin role")
	exit, result, _ = cliInvoke(t, "", "sessions", "revoke", "--user", testIdentity().User.ID, "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Forbidden, result.Error.Code)
	fixture.mu.Lock()
	for token, identity := range fixture.sessions {
		identity.User.Role = auth.Admin
		fixture.sessions[token] = identity
	}
	fixture.mu.Unlock()
	exit, _, _ = cliInvoke(t, "", "sessions", "revoke", "--user", testIdentity().User.ID, "--server", server.URL)
	require.Equal(t, 0, exit)
	exit, result, _ = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Unauthenticated, result.Error.Code)
	for range 2 {
		exit, _, _ = cliInvoke(t, "", "logout", "--server", server.URL)
		require.Equal(t, 0, exit)
	}
}

func TestAuthOriginIsolationAndOfflineLogout(t *testing.T) {
	cliHome(t)
	password := testToken()
	_, first := newCLIFixture(t, password)
	fixture, second := newCLIFixture(t, password)
	for _, origin := range []string{first.URL, second.URL} {
		exit, _, _ := cliInvoke(t, string(password), "login", "--username=cli-test", "--password-stdin", "--server", origin)
		require.Equal(t, 0, exit)
	}
	first.Close()
	exit, result, output := cliInvoke(t, "", "logout", "--server", first.URL, "--timeout=100ms")
	require.Equal(t, 1, exit)
	require.Contains(t, result.Error.Message, "remote revocation was not confirmed")
	require.Nil(t, result.Data)
	require.NotContains(t, output, `"revoked":true`)
	exit, _, _ = cliInvoke(t, "", "logout", "--server", first.URL)
	require.Equal(t, 0, exit)
	exit, _, _ = cliInvoke(t, "", "whoami", "--server", second.URL)
	require.Equal(t, 0, exit)
	fixture.mu.Lock()
	for token, identity := range fixture.sessions {
		identity.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		fixture.sessions[token] = identity
	}
	fixture.mu.Unlock()
	exit, result, _ = cliInvoke(t, "", "whoami", "--server", second.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Unauthenticated, result.Error.Code)
	exit, _, _ = cliInvoke(t, "", "logout", "--server", second.URL)
	require.Equal(t, 0, exit)
}

func TestAuthArgumentsAndInput(t *testing.T) {
	cliHome(t)
	for _, args := range [][]string{
		{"login"}, {"login", "--username=cli-test"}, {"login", "--username=UPPER", "--password-stdin"},
		{"login", "--password=value"}, {"login", "--token=value"}, {"whoami", "extra"},
		{"logout", "--timeout=0"}, {"whoami", "--timeout=-1s"}, {"whoami", "--timeout=invalid"},
		{"whoami", "--output=yaml"}, {"whoami", "--server=http://localhost:8080"},
		{"sessions", "unknown"}, {"sessions", "revoke", "--user=invalid"}, {"sessions", "revoke"},
		{"sessions", "revoke", "--user", testIdentity().User.ID, "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			args = append([]string{"--output=text"}, args...)
			exit, value, output := cliInvoke(t, string(testToken()), args...)
			require.Equal(t, 2, exit)
			require.Equal(t, "INVALID_ARGUMENT", value.Error.Code)
			require.True(t, json.Valid([]byte(output)))
		})
	}
	for _, input := range []string{
		"", strings.Repeat("a", 14), strings.Repeat("a", 1025), strings.Repeat("a", 1024) + "\n\n",
		strings.Repeat("a", 15) + "\r", strings.Repeat("a", 15) + "\x00",
		strings.Repeat("a", 15) + "\xff",
	} {
		_, err := passwordFromStdin(context.Background(), strings.NewReader(input))
		require.Error(t, err)
	}
	for _, ending := range []string{"", "\n", "\r\n"} {
		for _, input := range []string{strings.Repeat("\x01", 1024), "  " + string(testToken()) + " \t"} {
			got, err := passwordFromStdin(context.Background(), strings.NewReader(input+ending))
			require.NoError(t, err)
			require.True(t, string(got) == input, "password bytes changed")
		}
	}
}

func TestMaxEscapedPasswordAndInjectedPrompt(t *testing.T) {
	cliHome(t)
	password := auth.Secret(strings.Repeat("\x01", auth.MaxPasswordBytes))
	_, server := newCLIFixture(t, password)
	exit, _, _ := cliInvoke(t, string(password)+"\r\n", "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
	require.Equal(t, 0, exit)
	var stdout, stderr bytes.Buffer
	exit = RunWithIO(context.Background(), []string{"clavis", "login", "--username=cli-test", "--server", server.URL}, IO{
		Stdout: &stdout, Stderr: &stderr,
		ReadPassword: func(ctx context.Context, input io.Reader, prompt io.Writer) ([]byte, error) {
			_, err := io.WriteString(prompt, "Password: ")
			return []byte(password), err
		},
	})
	require.Equal(t, 0, exit)
	require.Equal(t, "Password: ", stderr.String())
	require.True(t, decode(t, stdout.String()).OK)
	stdout.Reset()
	exit = RunWithIO(context.Background(), []string{"clavis", "login", "--username=cli-test"}, IO{
		Stdout: &stdout,
		ReadPassword: func(context.Context, io.Reader, io.Writer) ([]byte, error) {
			return nil, context.Canceled
		},
	})
	require.Equal(t, 1, exit)
	require.Equal(t, "TIMEOUT", decode(t, stdout.String()).Error.Code)
}

func TestCanonicalAuthOrigins(t *testing.T) {
	for raw, want := range map[string]string{
		"https://EXAMPLE.com:0443/":    "https://example.com",
		"http://127.0.0.1:080/":        "http://127.0.0.1",
		"http://[0:0:0:0:0:0:0:1]:80":  "http://[::1]",
		"https://[2001:0db8::1]:00444": "https://[2001:db8::1]:444",
	} {
		got, err := auth.CanonicalOrigin(raw)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	for _, raw := range []string{
		"http://localhost", "http://example.com", "http://127.0.0.1.example.com",
		"https://user:pass@example.com", "https://example.com/base", "https://example.com//",
		"https://example.com/%2f", "https://example.com?", "https://example.com#",
		"https://example.com:0", "https://example.com:65536", "https://example.com:",
		"http://[::1%25lo0]", "http://2130706433", "file:///tmp/test",
	} {
		_, err := auth.CanonicalOrigin(raw)
		require.Error(t, err, raw)
	}
}

func TestAuthOriginFailuresAreSafeBeforeCredentialInput(t *testing.T) {
	for _, raw := range []string{
		"http://secret.example", "https://user:secret@example.com",
		"https://secret.example:0", "https://secret.example:", "https://secret.example/%zz",
		"https://secret.example/base", "https://secret.example#", "https://secret.example?",
		"http://[::ffff:192.0.2.1]",
	} {
		t.Run(raw, func(t *testing.T) {
			var stdout bytes.Buffer
			exit := RunWithIO(context.Background(), []string{
				"clavis", "login", "--username=cli-test", "--server", raw,
			}, IO{
				Stdout: &stdout,
				ReadPassword: func(context.Context, io.Reader, io.Writer) ([]byte, error) {
					t.Fatal("invalid origins must be rejected before reading credentials")
					return nil, nil
				},
			})
			require.Equal(t, 2, exit)
			require.Equal(t, "INVALID_ARGUMENT", decode(t, stdout.String()).Error.Code)
			require.NotContains(t, stdout.String(), "secret")
		})
	}
}

func TestTokenEncodingAndCredentialEnvironmentIgnored(t *testing.T) {
	token := testToken()
	require.True(t, auth.ValidToken(token))
	for _, invalid := range []auth.Secret{"", token + "\n", token + "\r\n", token + "=", auth.Secret(strings.Repeat("x", 42))} {
		require.False(t, auth.ValidToken(invalid))
	}
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	t.Setenv("CLAVIS_PASSWORD", string(password))
	t.Setenv("CLAVIS_TOKEN", string(token))
	exit, result, output := cliInvoke(t, "", "login", "--username=cli-test", "--server", server.URL)
	require.Equal(t, 2, exit)
	require.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
	require.False(t, strings.Contains(output, string(password)))
	exit, result, _ = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Unauthenticated, result.Error.Code)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.login)
	require.Zero(t, fixture.whoami)
}

func TestWhoamiWithoutOrExpiredLocalCredentialCallsServer(t *testing.T) {
	cliHome(t)
	var requests atomic.Int32
	token := testToken()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, auth.WhoAmIPath, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			status, safe, _ := auth.LookupFailure(auth.Unauthenticated)
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
			return
		}
		require.True(t, r.Header.Get("Authorization") == "Bearer "+string(token))
		identity := testIdentity()
		identity.User.Role = auth.Member
		_ = json.NewEncoder(w).Encode(identity)
	}))
	defer server.Close()
	exit, result, _ := cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Unauthenticated, result.Error.Code)
	require.Equal(t, int32(1), requests.Load())
	cache, err := openCache(context.Background(), server.URL)
	require.NoError(t, err)
	identity := testIdentity()
	identity.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	require.NoError(t, cache.write(cachedSession{Origin: server.URL, LoginResponse: auth.LoginResponse{Token: token, Identity: identity}}))
	cache.close()
	exit, _, output := cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 0, exit)
	require.Contains(t, output, `"role":"member"`)
	require.Equal(t, int32(2), requests.Load())
}

func TestAuthTransportStrictResponses(t *testing.T) {
	valid, err := json.Marshal(auth.LoginResponse{Token: testToken(), Identity: testIdentity()})
	require.NoError(t, err)
	for _, tc := range []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"unknown", 200, "application/json", strings.TrimSuffix(string(valid), "}") + `,"private":"sentinel"}`},
		{"uppercase", 200, "application/json", strings.Replace(string(valid), `"token":`, `"TOKEN":`, 1)},
		{"duplicate", 200, "application/json", strings.TrimSuffix(string(valid), "}") + `,"token":"sentinel"}`},
		{"trailing", 200, "application/json", string(valid) + `{}`},
		{"oversized", 200, "application/json", strings.Repeat(" ", auth.MaxResponseBody) + string(valid)},
		{"wrong-type", 200, "text/html", string(valid)},
		{"malformed", 200, "application/json", `{"token":"sentinel"`},
		{"null", 200, "application/json", `null`},
		{"empty", 200, "application/json", `{}`},
		{"unknown-error", 401, "application/json", `{"error":{"code":"SECRET","message":"sentinel"}}`},
		{"wrong-status", 403, "application/json", `{"error":{"code":"UNAUTHENTICATED","message":"sentinel"}}`},
		{"success-status", 201, "application/json", string(valid)},
		{"bad-role", 200, "application/json", strings.Replace(string(valid), `"admin"`, `"superuser"`, 1)},
		{"bad-uuid", 200, "application/json", strings.Replace(string(valid), testIdentity().User.ID, "not-a-uuid", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			var response auth.LoginResponse
			result := (authTransport{server.URL, time.Second}).request(context.Background(), auth.LoginPath, "", &auth.LoginRequest{}, &response)
			require.NotNil(t, result)
			require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
			for _, format := range []string{"json", "text"} {
				var out bytes.Buffer
				require.NoError(t, render(&out, *result, format))
				require.NotContains(t, out.String(), "sentinel")
			}
		})
	}
}

func TestAuthTransportRedirectDeadlineTLSAndErrors(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	var calls atomic.Int32
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, path := range []string{auth.LoginPath, auth.WhoAmIPath, auth.LogoutPath, strings.Replace(auth.RevokePath, "{userID}", testIdentity().User.ID, 1)} {
		var value auth.Revocation
		result := (authTransport{redirect.URL, time.Second}).request(context.Background(), path, testToken(), nil, &value)
		require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
	}
	require.Equal(t, int32(4), calls.Load(), "mutations must not retry")
	require.Zero(t, destinationCalls.Load())
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"user":`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer stalled.Close()
	start := time.Now()
	var identity auth.Identity
	result := (authTransport{stalled.URL, 60 * time.Millisecond}).request(context.Background(), auth.WhoAmIPath, testToken(), nil, &identity)
	require.Equal(t, "TIMEOUT", result.Error.Code)
	require.Less(t, time.Since(start), time.Second)
	tls := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS reached handler") }))
	tls.Config.ErrorLog = log.New(io.Discard, "", 0)
	tls.StartTLS()
	defer tls.Close()
	result = (authTransport{tls.URL, time.Second}).request(context.Background(), auth.WhoAmIPath, testToken(), nil, &identity)
	require.Equal(t, "SERVER_UNREACHABLE", result.Error.Code)
	for _, code := range []string{auth.InvalidArgument, auth.InvalidCredentials, auth.Unauthenticated, auth.Forbidden, auth.RateLimited, auth.ServiceUnavailable, platform.CodeSetupRequired, platform.CodeSchemaError} {
		status, safe, _ := auth.LookupFailure(code)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: platform.Failure{Code: code, Message: string(testToken())}})
		}))
		var value auth.LoginResponse
		path := auth.LoginPath
		if code == auth.Unauthenticated {
			path = auth.WhoAmIPath
		}
		result := (authTransport{server.URL, time.Second}).request(context.Background(), path, "", nil, &value)
		server.Close()
		require.Equal(t, safe.Code, result.Error.Code)
		require.Equal(t, safe.Message, result.Error.Message)
	}
}

func TestDoctorInitializationAllowlist(t *testing.T) {
	for _, code := range []string{platform.CodeInitializing, platform.CodeSetupRequired, platform.CodeBootstrapFailed, platform.CodeSchemaError} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/prefix/health/ready", r.URL.Path)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(platform.Response{Status: "not_ready", Error: &platform.Failure{Code: code, Message: "sentinel"}})
		}))
		result := Doctor(context.Background(), server.URL+"/prefix", time.Second)
		server.Close()
		require.Equal(t, code, result.Error.Code)
		require.Equal(t, Diagnosis{"reachable", "ready"}, result.Data)
		require.NotContains(t, result.Error.Message, "sentinel")
	}
}
