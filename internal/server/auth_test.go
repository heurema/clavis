package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/heurema/clavis/internal/auth"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/web"
	"github.com/stretchr/testify/require"
)

type backendFixture struct {
	loginErr, errorAuth, logoutErr, revokeErr, recordErr error
	loginCalls, authCalls, logoutCalls, revokeCalls      int
	lastInput                                            auth.LoginInput
	events                                               []auth.Event
	role                                                 auth.Role
	block                                                func(context.Context)
	fakeAdministration
	fakeConnections
}

var fixtureToken = auth.Secret(strings.Repeat("A", 43))
var fixtureIdentity = auth.Identity{User: auth.User{ID: "12345678-1234-4234-8234-123456789abc", Username: "personal-admin", Role: auth.Admin}, ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}

func (f *backendFixture) Login(ctx context.Context, input auth.LoginInput) (auth.LoginResponse, error) {
	f.loginCalls++
	f.lastInput = input
	if f.block != nil {
		f.block(ctx)
	}
	return auth.LoginResponse{Token: fixtureToken, Identity: fixtureIdentity}, f.loginErr
}
func (f *backendFixture) Authenticate(ctx context.Context, _ auth.Secret, kind auth.Kind) (auth.Session, error) {
	f.authCalls++
	if f.block != nil {
		f.block(ctx)
	}
	identity := fixtureIdentity
	if f.role != "" {
		identity.User.Role = f.role
	}
	return auth.Session{ID: "12345678-1234-4234-8234-123456789aaa", Kind: kind, Identity: identity}, f.errorAuth
}
func (f *backendFixture) Logout(ctx context.Context, _ auth.Session) error {
	f.logoutCalls++
	if f.block != nil {
		f.block(ctx)
	}
	return f.logoutErr
}
func (f *backendFixture) RevokeUserSessions(ctx context.Context, _ auth.Session, _ string) error {
	f.revokeCalls++
	if f.block != nil {
		f.block(ctx)
	}
	return f.revokeErr
}
func (f *backendFixture) RecordEvent(ctx context.Context, event auth.Event) error {
	f.events = append(f.events, event)
	if f.block != nil {
		f.block(ctx)
	}
	return f.recordErr
}

func fixtureViews() AuthViews {
	component := func(value any) templ.Component {
		return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			_, err := fmt.Fprint(w, "<!doctype html><html><body>")
			if err != nil {
				return err
			}
			// Fixture models contain only safe data; production escaping belongs to
			// the separate web lane, not this transport test.
			if err := json.NewEncoder(w).Encode(value); err != nil {
				return err
			}
			_, err = fmt.Fprint(w, "</body></html>")
			return err
		})
	}
	return AuthViews{
		Login: func(m web.LoginModel) templ.Component { return component(m) },
		Admin: func(m web.AdminModel) templ.Component { return component(m) },
		Error: func(m web.AuthErrorModel) templ.Component { return component(m) },
	}
}

func authHandler(t *testing.T, f *backendFixture, checker platform.Checker, origin string) http.Handler {
	t.Helper()
	if checker == nil {
		checker = platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
	}
	// The fixture supplies every dependency, so the tests exercise the same
	// composition boundary the production entry point uses.
	handler, err := HandlerWithAuth(time.Second, checker, f, f, f, f, origin, fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	return handler
}

func requestAuth(handler http.Handler, method, path, body string, headers http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:43210"
	request.Header = headers.Clone()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestServiceOwnsReadinessAndPreservesRejectionPrecedence(t *testing.T) {
	for _, state := range []platform.State{
		platform.DependencyUnavailable, platform.Initializing, platform.SetupRequired,
		platform.BootstrapFailed, platform.SchemaError,
	} {
		t.Run(string(state), func(t *testing.T) {
			calls := 0
			checker := platform.CheckFunc(func(ctx context.Context) platform.Readiness {
				calls++
				_, bounded := ctx.Deadline()
				require.True(t, bounded)
				return platform.Readiness{State: state}
			})
			// An unready real service must never reach its pool, even directly.
			service, err := store.NewLocalAuth(nil, checker, auth.DefaultSessionTTL)
			require.NoError(t, err)
			recorder := &backendFixture{}
			healthCalls := 0
			health := platform.CheckFunc(func(ctx context.Context) platform.Readiness {
				healthCalls++
				return checker.Check(ctx)
			})
			handler, err := HandlerWithAuth(time.Second, health, service, recorder, service, service, "http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
			require.NoError(t, err)
			code := (platform.Readiness{State: state}).Response().Error.Code
			for _, tc := range []struct {
				method, path, body string
				headers            http.Header
				status             int
				code               string
				checks             int
			}{
				{"POST", auth.LoginPath, `{"username":"personal-admin","password":"valid test password"}`, http.Header{"Content-Type": {"application/json"}}, 503, code, 1},
				{"GET", auth.WhoAmIPath, "", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}, 503, code, 1},
				{"POST", auth.LogoutPath, "", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}, 503, code, 1},
				{"POST", "/api/admin/users/not-a-user/sessions/revoke", "", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}, 503, code, 1},
				{"POST", "/login", "username=personal-admin&password=valid+test+password", http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}}, 503, code, 1},
				{"GET", "/admin", "", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 503, code, 1},
				{"POST", "/logout", "", http.Header{"Origin": {"http://127.0.0.1"}, "Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 503, auth.ServiceUnavailable, 1},
				{"POST", auth.LoginPath, "{}", http.Header{"Origin": {"https://attacker.invalid"}, "Content-Type": {"application/json"}}, 403, auth.Forbidden, 0},
				{"POST", auth.LoginPath, "{}", http.Header{"Content-Type": {"application/json"}}, 400, auth.InvalidArgument, 0},
				{"POST", auth.LogoutPath, "unexpected", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}, 400, auth.InvalidArgument, 0},
				{"GET", auth.WhoAmIPath, "", http.Header{}, 401, auth.Unauthenticated, 0},
			} {
				calls = 0
				response := requestAuth(handler, tc.method, tc.path, tc.body, tc.headers)
				require.Equal(t, tc.status, response.Code, tc.path)
				require.Contains(t, response.Body.String(), tc.code, tc.path)
				require.Equal(t, tc.checks, calls, tc.path)
				require.Zero(t, healthCalls, "authentication must invoke the service's checker")
				if tc.path != "/logout" {
					require.Empty(t, response.Header().Get("Set-Cookie"))
				}
			}
			for _, call := range []func() error{
				func() error {
					_, err := service.Login(t.Context(), auth.LoginInput{Username: "personal-admin", Password: "valid test password", Kind: auth.CLI, Peer: netip.MustParseAddr("127.0.0.1")})
					return err
				},
				func() error { _, err := service.Authenticate(t.Context(), fixtureToken, auth.CLI); return err },
				func() error {
					return service.Logout(t.Context(), auth.Session{ID: fixtureIdentity.User.ID, Identity: fixtureIdentity})
				},
				func() error {
					return service.RevokeUserSessions(t.Context(), auth.Session{ID: fixtureIdentity.User.ID, Identity: fixtureIdentity}, fixtureIdentity.User.ID)
				},
			} {
				calls = 0
				err := call()
				status, failure := auth.FailureFor(err)
				require.Equal(t, 503, status)
				require.Equal(t, code, failure.Error.Code)
				require.Equal(t, 1, calls)
			}
			calls = 0
			response := requestAuth(handler, "GET", "/health/ready", "", http.Header{})
			require.Equal(t, 503, response.Code)
			require.Equal(t, 1, calls, "public health must still invoke its checker")
			require.Equal(t, 1, healthCalls)
		})
	}
}

func TestHandlerWithAuthRequiresCompleteComposition(t *testing.T) {
	checker := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
	fixture := &backendFixture{}
	for _, tc := range []struct {
		checker     platform.Checker
		service     auth.Service
		recorder    auth.EventRecorder
		admin       auth.Administration
		connections auth.Connections
	}{
		{nil, fixture, fixture, fixture, fixture},
		{checker, nil, fixture, fixture, fixture},
		{checker, fixture, nil, fixture, fixture},
		{checker, fixture, fixture, nil, fixture},
		{checker, fixture, fixture, fixture, nil},
	} {
		handler, err := HandlerWithAuth(time.Second, tc.checker, tc.service, tc.recorder, tc.admin, tc.connections, "http://127.0.0.1", AuthViews{}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		require.Nil(t, handler)
		require.Error(t, err)
		status, failure := auth.FailureFor(err)
		require.Equal(t, 400, status)
		require.Equal(t, auth.InvalidArgument, failure.Error.Code)
	}
}

func TestNilServiceFixturesFailClosed(t *testing.T) {
	checker := platform.CheckFunc(func(context.Context) platform.Readiness {
		t.Fatal("protected fixtures must not rely on a readiness check")
		return platform.Readiness{State: platform.Ready}
	})
	handler := HandlerWithReadiness(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for _, tc := range []struct {
		method, path, body string
		headers            http.Header
	}{
		{"POST", auth.LoginPath, `{"username":"personal-admin","password":"valid test password"}`, http.Header{"Content-Type": {"application/json"}}},
		{"GET", auth.WhoAmIPath, "", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}},
		{"POST", auth.LogoutPath, "", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}},
		{"POST", "/api/admin/users/" + fixtureIdentity.User.ID + "/sessions/revoke", "", http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}},
		{"POST", "/login", "username=personal-admin&password=valid+test+password", http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}}},
		{"GET", "/admin", "", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}},
		{"POST", "/logout", "", http.Header{"Origin": {"http://127.0.0.1"}, "Cookie": {developmentCookie + "=" + string(fixtureToken)}}},
	} {
		response := requestAuth(handler, tc.method, tc.path, tc.body, tc.headers)
		require.Equal(t, 503, response.Code, tc.path)
		require.NotContains(t, response.Body.String(), string(fixtureToken))
		require.NotContains(t, response.Body.String(), "valid test password")
		if tc.path != "/logout" {
			require.Empty(t, response.Header().Get("Set-Cookie"))
		} else {
			require.Equal(t, -1, response.Result().Cookies()[0].MaxAge)
		}
	}
}

func TestStrictJSONCredentialsAndAnonymousAudits(t *testing.T) {
	valid := `{"username":"personal-admin","password":"SENTINEL_PRIVATE_PASSWORD"}`
	for _, tc := range []struct {
		name, body, content string
		status              int
	}{
		{"valid", valid, "application/json", 200},
		{"form", "username=personal-admin&password=SENTINEL_PRIVATE_PASSWORD", "application/x-www-form-urlencoded", 400},
		{"unknown", strings.TrimSuffix(valid, "}") + `,"secret":"SENTINEL"}`, "application/json", 400},
		{"trailing", valid + ` {}`, "application/json", 400},
		{"duplicate", strings.TrimSuffix(valid, "}") + `,"username":"another"}`, "application/json", 400},
		{"case-alias", strings.Replace(valid, "username", "Username", 1), "application/json", 400},
		{"null", `{"username":"personal-admin","password":null}`, "application/json", 400},
		{"array", `[]`, "application/json", 400},
		{"huge", strings.Repeat(" ", 8193), "application/json", 400},
		{"decoded-huge", `{"username":"personal-admin","password":"` + strings.Repeat("x", 1025) + `"}`, "application/json", 400},
		{"bad-utf8", valid + "\xff", "application/json", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &backendFixture{}
			handler := authHandler(t, f, nil, "http://127.0.0.1")
			response := requestAuth(handler, "POST", auth.LoginPath, tc.body, http.Header{"Content-Type": {tc.content}, "Accept": {"text/html"}, "Hx-Request": {"true"}})
			require.Equal(t, tc.status, response.Code)
			require.Equal(t, "application/json", response.Header().Get("Content-Type"))
			require.Empty(t, response.Header().Get("Location"))
			require.Empty(t, response.Header().Get("Set-Cookie"))
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.NotContains(t, response.Body.String(), "SENTINEL")
			if tc.status == 200 {
				require.Equal(t, 1, f.loginCalls)
				require.Empty(t, f.events)
				require.Equal(t, auth.CLI, f.lastInput.Kind)
			} else {
				require.Zero(t, f.loginCalls)
				require.Equal(t, []auth.Event{{Action: auth.EventLogin, Outcome: auth.OutcomeInvalidArgument}}, f.events)
			}
		})
	}
	f := &backendFixture{}
	handler := authHandler(t, f, nil, "http://127.0.0.1")
	password := auth.Secret(strings.Repeat("\x01", 1024))
	body, err := json.Marshal(auth.LoginRequest{Username: "personal-admin", Password: password})
	require.NoError(t, err)
	require.Greater(t, len(body), 4096)
	response := requestAuth(handler, "POST", auth.LoginPath, string(body), http.Header{"Content-Type": {"application/json"}, "X-Forwarded-For": {"8.8.8.8"}})
	require.Equal(t, 200, response.Code)
	require.Equal(t, password, f.lastInput.Password)
	require.Equal(t, netip.MustParseAddr("127.0.0.1"), f.lastInput.Peer)
}

func TestOriginTransportAndCredentialIsolation(t *testing.T) {
	for _, origin := range []string{"", "null", "https://attacker.invalid", "http://127.0.0.1 http://attacker.invalid"} {
		for _, path := range []string{"/login", "/logout"} {
			f := &backendFixture{}
			handler := authHandler(t, f, nil, "http://127.0.0.1")
			headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {developmentCookie + "=" + string(fixtureToken)}}
			if origin != "" {
				headers.Set("Origin", origin)
			}
			response := requestAuth(handler, "POST", path, "", headers)
			require.Equal(t, 403, response.Code)
			require.Empty(t, response.Header().Get("Set-Cookie"))
			require.Zero(t, f.loginCalls+f.logoutCalls+f.authCalls)
			require.Len(t, f.events, 1)
		}
	}
	for _, headers := range []http.Header{
		{"Origin": {"http://127.0.0.1", "http://127.0.0.1"}},
		{"Origin": {"http://127.0.0.1"}, "Sec-Fetch-Site": {"cross-site"}},
		{"Origin": {"http://127.0.0.1"}, "Sec-Fetch-Site": {"same-site"}},
		{"Origin": {"http://127.0.0.1"}, "Sec-Fetch-Site": {"same-origin", "cross-site"}},
	} {
		f := &backendFixture{}
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/logout", "", headers)
		require.Equal(t, 403, response.Code)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.Zero(t, f.logoutCalls)
	}
	for _, tc := range []struct {
		headers http.Header
		status  int
	}{
		{http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 401},
		{http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}, 200},
		{http.Header{"Authorization": {"Bearer " + string(fixtureToken), "Bearer " + string(fixtureToken)}}, 400},
		{http.Header{"Authorization": {"Bearer " + string(fixtureToken)}, "Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 400},
		{http.Header{"Authorization": {"Bearer " + string(fixtureToken)}, "Origin": {"https://attacker.invalid"}}, 403},
	} {
		f := &backendFixture{}
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "GET", auth.WhoAmIPath, "", tc.headers)
		require.Equal(t, tc.status, response.Code)
		require.Empty(t, response.Header().Get("Location"))
		require.NotContains(t, response.Body.String(), string(fixtureToken))
	}
	f := &backendFixture{}
	headers := http.Header{"Origin": {"http://127.0.0.1"}, "Authorization": {"Bearer " + string(fixtureToken)}}
	response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/logout", "", headers)
	require.Equal(t, 400, response.Code)
	require.Empty(t, response.Header().Get("Set-Cookie"))
	require.Zero(t, f.authCalls)
	for _, cookie := range []string{
		developmentCookie + "=bad\\value; " + developmentCookie + "=" + string(fixtureToken),
		browserCookie + "=" + string(fixtureToken) + "; " + developmentCookie + "=" + string(fixtureToken),
	} {
		headers := http.Header{"Origin": {"http://127.0.0.1"}, "Cookie": {cookie}}
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/logout", "", headers)
		require.Equal(t, 400, response.Code)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.Zero(t, f.authCalls)
		f.recordErr = errors.New("storage unavailable")
		response = requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/logout", "", headers)
		require.Equal(t, 503, response.Code)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.Zero(t, f.authCalls)
		f.recordErr = nil
	}
}

func TestBrowserOutcomesCookiesAndPublicBypass(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1", "https://clavis.example"} {
		f := &backendFixture{}
		handler := authHandler(t, f, nil, origin)
		body := url.Values{"username": {"personal-admin"}, "password": {"SENTINEL_PRIVATE_PASSWORD"}}.Encode()
		response := requestAuth(handler, "POST", "/login", body, http.Header{"Origin": {origin}, "Content-Type": {"application/x-www-form-urlencoded"}})
		require.Equal(t, 303, response.Code)
		require.Equal(t, "/admin", response.Header().Get("Location"))
		require.NotContains(t, response.Body.String(), string(fixtureToken))
		require.Equal(t, auth.Browser, f.lastInput.Kind)
		cookies := response.Result().Cookies()
		require.Len(t, cookies, 1)
		cookie := cookies[0]
		require.True(t, cookie.HttpOnly)
		require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		require.Empty(t, cookie.Domain)
		require.Equal(t, "/", cookie.Path)
		require.Equal(t, strings.HasPrefix(origin, "https:"), cookie.Secure)
		require.False(t, cookie.Expires.After(fixtureIdentity.ExpiresAt))
		for _, tc := range []struct {
			err    error
			status int
		}{
			{&auth.Error{Code: auth.InvalidCredentials}, 401}, {&auth.Error{Code: auth.RateLimited, RetryAfter: 3 * time.Second}, 429},
			{&auth.Error{Code: platform.CodeSetupRequired}, 503}, {errors.New("SENTINEL_PRIVATE_DRIVER"), 503},
		} {
			f.loginErr = tc.err
			response := requestAuth(handler, "POST", "/login", body, http.Header{"Origin": {origin}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie.Name + "=" + cookie.Value}})
			require.Equal(t, tc.status, response.Code)
			require.Empty(t, response.Header().Get("Set-Cookie"))
			require.Contains(t, response.Body.String(), "<!doctype html>")
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Equal(t, "frame-ancestors 'none'", response.Header().Get("Content-Security-Policy"))
			if tc.status == 429 {
				require.Equal(t, "3", response.Header().Get("Retry-After"))
			}
		}
		f.errorAuth = &auth.Error{Code: auth.Unauthenticated}
		response = requestAuth(handler, "POST", "/logout", "", http.Header{"Origin": {origin}, "Cookie": {cookie.Name + "=" + cookie.Value}})
		require.Equal(t, 303, response.Code)
		require.Equal(t, -1, response.Result().Cookies()[0].MaxAge)
		f.errorAuth = nil
		f.logoutErr = errors.New("SENTINEL_PRIVATE_DRIVER")
		response = requestAuth(handler, "POST", "/logout", "", http.Header{"Origin": {origin}, "Cookie": {cookie.Name + "=" + cookie.Value}})
		require.Equal(t, 503, response.Code)
		require.Equal(t, -1, response.Result().Cookies()[0].MaxAge)
		require.Contains(t, response.Body.String(), `"RemoteRevocationUnconfirmed":true`)
		require.NotContains(t, response.Body.String(), "SENTINEL")
		for _, tc := range []struct {
			role   auth.Role
			err    error
			status int
		}{{auth.Admin, nil, 200}, {auth.Member, nil, 403}, {"", &auth.Error{Code: auth.Unauthenticated}, 303}, {"", errors.New("SENTINEL"), 503}} {
			f.role = tc.role
			f.errorAuth = tc.err
			response := requestAuth(handler, "GET", "/admin", "", http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}})
			require.Equal(t, tc.status, response.Code)
			require.Empty(t, response.Header().Get("Set-Cookie"))
		}
	}
	checker := platform.CheckFunc(func(context.Context) platform.Readiness {
		t.Fatal("public/local-only path must not touch DB")
		return platform.Readiness{}
	})
	f := &backendFixture{recordErr: errors.New("unavailable")}
	handler := authHandler(t, f, checker, "http://127.0.0.1")
	for _, path := range []string{"/", "/login", "/assets/appearance.js", "/health/live"} {
		for _, cookie := range []string{"", developmentCookie + "=malformed", developmentCookie + "=" + string(fixtureToken)} {
			response := requestAuth(handler, "GET", path, "", http.Header{"Cookie": {cookie}})
			require.Equal(t, 200, response.Code)
		}
	}
	for _, cookie := range []string{"", developmentCookie + "=malformed"} {
		response := requestAuth(handler, "POST", "/logout", "", http.Header{"Origin": {"http://127.0.0.1"}, "Cookie": {cookie}})
		require.Equal(t, 303, response.Code)
		require.Equal(t, -1, response.Result().Cookies()[0].MaxAge)
	}
	require.Zero(t, f.authCalls+f.loginCalls+f.logoutCalls)
	require.Empty(t, f.events)
}

func TestRejectionAuditFailureDeadlineAndNoDuplicate(t *testing.T) {
	f := &backendFixture{recordErr: errors.New("SENTINEL_PRIVATE_DRIVER")}
	handler := authHandler(t, f, nil, "http://127.0.0.1")
	for _, path := range []string{auth.LoginPath, auth.LogoutPath, "/api/admin/users/" + fixtureIdentity.User.ID + "/sessions/revoke", "/logout"} {
		response := requestAuth(handler, "POST", path, "", http.Header{})
		require.Equal(t, 503, response.Code)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.NotContains(t, response.Body.String(), "SENTINEL")
	}
	f.recordErr = nil
	f.events = nil
	f.loginErr = &auth.Error{Code: auth.InvalidCredentials}
	response := requestAuth(handler, "POST", auth.LoginPath, `{"username":"personal-admin","password":"valid test password"}`, http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, 401, response.Code)
	require.Empty(t, f.events)
	f.block = func(ctx context.Context) { <-ctx.Done() }
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest("POST", auth.LogoutPath, nil).WithContext(ctx)
	response = httptest.NewRecorder()
	start := time.Now()
	handler.ServeHTTP(response, request)
	require.Equal(t, 503, response.Code)
	require.Less(t, time.Since(start), time.Second)
}

func TestRealSocketBodyDeadlineReturnsSafeJSON(t *testing.T) {
	f := &backendFixture{}
	httpServer := httptest.NewServer(authHandler(t, f, nil, "http://127.0.0.1"))
	defer httpServer.Close()
	connection, err := net.Dial("tcp", strings.TrimPrefix(httpServer.URL, "http://"))
	require.NoError(t, err)
	defer func() { _ = connection.Close() }()
	require.NoError(t, connection.SetDeadline(time.Now().Add(7*time.Second)))
	_, err = fmt.Fprint(connection, "POST /api/auth/login HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
	require.NoError(t, err)
	start := time.Now()
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, 503, response.StatusCode)
	require.Contains(t, string(data), auth.ServiceUnavailable)
	require.Less(t, time.Since(start), 6*time.Second)
}
