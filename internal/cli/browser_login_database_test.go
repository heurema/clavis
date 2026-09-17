package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/server"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realServer runs the production handler and templates over an isolated
// schema of the test database, with the bootstrap administrator ready.
func realServer(t *testing.T) (*httptest.Server, auth.Secret) {
	t.Helper()
	dsn := os.Getenv("CLAVIS_BACKEND_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set CLAVIS_BACKEND_TEST_DATABASE_URL to isolated PostgreSQL")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	require.NoError(t, err)
	var random [32]byte
	_, err = rand.Read(random[:])
	require.NoError(t, err)
	schema := "cli_login_" + hex.EncodeToString(random[:8])
	_, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	cfg := admin.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		assert.NoError(t, err)
		admin.Close()
	})
	password := auth.Secret(base64.RawURLEncoding.EncodeToString(random[:]))
	path := filepath.Join(t.TempDir(), "bootstrap-secret")
	require.NoError(t, os.WriteFile(path, []byte(password), 0o600))
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	service, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionIdleTimeout, auth.DefaultSessionMaxLifetime)
	require.NoError(t, err)
	httpServer := httptest.NewUnstartedServer(nil)
	origin := "http://" + httpServer.Listener.Addr().String()
	handler, err := server.HandlerWithAuth(time.Second, checker, service, service, service, service, service, service, service,
		origin, server.AuthViews{}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	httpServer.Config.Handler = handler
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	return httpServer, password
}

// signInAndApprove is the person at the browser: the link shows the sign-in
// form, the form returns to the link, and Approve redirects to the CLI's
// loopback callback. It returns the code the callback carried.
func signInAndApprove(origin, username string, password auth.Secret, link string) (auth.Secret, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, target string, form url.Values) (*http.Response, string, error) {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		request, err := http.NewRequest(method, target, body)
		if err != nil {
			return nil, "", err
		}
		if form != nil {
			request.Header.Set("Origin", origin)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, "", err
		}
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(response.Body)
		return response, string(data), err
	}
	parsed, err := url.Parse(link)
	if err != nil || !strings.HasPrefix(link, origin+auth.AuthorizePath+"?") {
		return "", fmt.Errorf("unexpected link")
	}
	// The form's action carries the return target, so the sign-in posts to it.
	action := "/login?" + url.Values{"next": {parsed.RequestURI()}}.Encode()
	response, page, err := send("GET", link, nil)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(page, `action="`+action+`"`) {
		return "", fmt.Errorf("the signed-out link did not show the sign-in form returning to it")
	}
	response, _, err = send("POST", origin+action, url.Values{
		"username": {username}, "password": {string(password)},
	})
	if err != nil || response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != parsed.RequestURI() {
		return "", fmt.Errorf("sign-in did not return to the link")
	}
	response, page, err = send("GET", origin+response.Header.Get("Location"), nil)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(page, "Approve") {
		return "", fmt.Errorf("the signed-in link did not offer Approve")
	}
	query := parsed.Query()
	response, _, err = send("POST", origin+auth.AuthorizePath, url.Values{
		"port": {query.Get("port")}, "challenge": {query.Get("challenge")}, "state": {query.Get("state")},
	})
	if err != nil || response.StatusCode != http.StatusSeeOther {
		return "", fmt.Errorf("approve did not redirect")
	}
	callback := response.Header.Get("Location")
	if !strings.HasPrefix(callback, "http://127.0.0.1:"+query.Get("port")+"/callback?") {
		return "", fmt.Errorf("approve redirected elsewhere")
	}
	target, err := url.Parse(callback)
	if err != nil {
		return "", err
	}
	response, page, err = send("GET", callback, nil)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(page, "Signed in.") {
		return "", fmt.Errorf("the callback did not answer its page")
	}
	return auth.Secret(target.Query().Get("code")), nil
}

// Browser login end to end: the real routes, templates and store, with a
// fake opener doing what the person does in the browser.
func TestBrowserLoginAgainstTheRealServer(t *testing.T) {
	cliHome(t)
	httpServer, password := realServer(t)
	origin := httpServer.URL
	var code auth.Secret
	var out, errout bytes.Buffer
	exit := RunWithIO(context.Background(), []string{"clavis", "login", "--server", origin}, IO{
		Stdout: &out, Stderr: &errout, ReadPassword: refusePassword(t),
		OpenBrowser: func(_ context.Context, link string) error {
			var err error
			code, err = signInAndApprove(origin, "personal-admin", password, link)
			assert.NoError(t, err)
			return nil
		},
	})
	require.Equal(t, 0, exit, out.String())
	result := decode(t, out.String())
	require.True(t, result.OK)
	identity, _ := result.Data.(map[string]any)
	require.Equal(t, "personal-admin", identity["user"].(map[string]any)["username"])
	require.Contains(t, identity, "idleExpiresAt")
	require.True(t, auth.ValidToken(code))
	for _, output := range []string{out.String(), errout.String()} {
		require.NotContains(t, output, string(code))
	}
	link := printedLink(t, errout.String())

	// The stored session works against the real server and shows both expiries.
	out.Reset()
	exit = RunWithIO(context.Background(), []string{"clavis", "whoami", "--server", origin, "--output=text"}, IO{Stdout: &out})
	require.Equal(t, 0, exit, out.String())
	require.Regexp(t, `\nExpires: \S+Z\nIdle until: \S+Z\n`, out.String())

	// The code was consumed by the CLI's redemption.
	request, err := http.NewRequest("POST", origin+auth.TokenPath, strings.NewReader(
		`{"code":"`+string(code)+`","verifier":"`+string(testToken())+`"}`))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	var failure auth.ErrorResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&failure))
	_ = response.Body.Close()
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Equal(t, auth.InvalidCredentials, failure.Error.Code)

	// The old password route is gone, and the listener is closed.
	response, err = http.Post(origin+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"personal-admin","password":"`+string(password)+`"}`))
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	requireListenerClosed(t, callbackPort(t, link))

	exit, _, _ = cliInvoke(t, "", "logout", "--server", origin)
	require.Equal(t, 0, exit)
}
