package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/web"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file creates a member fixture and counts stored
// authorizations as an independent assertion; everything else goes through
// the real routes.

type authorizeFlow struct {
	pool     *pgxpool.Pool
	handler  http.Handler
	logs     *bytes.Buffer
	password auth.Secret
}

func newAuthorizeFlow(t *testing.T) authorizeFlow {
	t.Helper()
	pool, path, password := serverDatabase(t)
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	local, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionIdleTimeout, auth.DefaultSessionMaxLifetime)
	require.NoError(t, err)
	service := local.WithKeyring(serverTestKeyring(t))
	logs := &bytes.Buffer{}
	handler, err := HandlerWithAuth(time.Second, checker, service, service, service, service, service, service, service,
		"http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(logs, nil)))
	require.NoError(t, err)
	_, err = pool.Exec(t.Context(), `INSERT INTO users(id,username,password_hash,role)
		SELECT $1,'member-user',password_hash,'member' FROM users WHERE username='personal-admin'`, fixtureIdentity.User.ID)
	require.NoError(t, err)
	return authorizeFlow{pool: pool, handler: handler, logs: logs, password: password}
}

func (f authorizeFlow) authorizations(t *testing.T) int {
	t.Helper()
	var count int
	require.NoError(t, f.pool.QueryRow(t.Context(), `SELECT count(*) FROM cli_authorizations`).Scan(&count))
	return count
}

// browserSignIn posts the sign-in form with a return target and returns the
// cookie header and the redirect.
func (f authorizeFlow) browserSignIn(t *testing.T, username, next string) (string, string) {
	t.Helper()
	body := url.Values{"username": {username}, "password": {string(f.password)}}.Encode()
	response := requestAuth(f.handler, "POST", "/login?"+url.Values{"next": {next}}.Encode(), body,
		http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}})
	require.Equal(t, 303, response.Code)
	cookies := response.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0].Name + "=" + cookies[0].Value, response.Header().Get("Location")
}

func randomPKCE(t *testing.T) (auth.Secret, auth.CLIAuthorization) {
	t.Helper()
	random := func() string {
		var data [32]byte
		_, err := rand.Read(data[:])
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(data[:])
	}
	verifier := auth.Secret(random())
	digest := sha256.Sum256([]byte(verifier))
	return verifier, auth.CLIAuthorization{Port: 49152, Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), State: random()}
}

func (f authorizeFlow) redeem(t *testing.T, code, verifier auth.Secret) *http.Response {
	t.Helper()
	response := requestAuth(f.handler, "POST", auth.TokenPath, jsonBody(t, auth.TokenRequest{Code: code, Verifier: verifier}),
		http.Header{"Content-Type": {"application/json"}})
	return response.Result()
}

// Scenarios: signed-out browser, opening the link creates nothing, and a member
// approves a CLI sign-in; then code replay, against the real store.
func TestRealBrowserAuthorizationFlow(t *testing.T) {
	flow := newAuthorizeFlow(t)
	verifier, link := randomPKCE(t)

	response := requestAuth(flow.handler, "GET", link.Link(), "", nil)
	require.Equal(t, 200, response.Code)
	var signIn web.LoginModel
	fixtureModel(t, response.Body.String(), &signIn)
	require.Equal(t, web.LoginModel{Action: wantAction(link.Link())}, signIn)

	cookie, location := flow.browserSignIn(t, "member-user", link.Link())
	require.Equal(t, link.Link(), location, "a member returns to the authorization, not /admin/users")

	for range 3 {
		response = requestAuth(flow.handler, "GET", location, "", http.Header{"Cookie": {cookie}})
		require.Equal(t, 200, response.Code)
		require.Contains(t, response.Body.String(), `"Username":"member-user"`)
		require.Contains(t, response.Body.String(), `"Port":49152`)
	}
	require.Zero(t, flow.authorizations(t), "opening the link stores nothing")

	response = requestAuth(flow.handler, "POST", auth.AuthorizePath, url.Values{
		"port": {"49152"}, "challenge": {link.Challenge}, "state": {link.State},
	}.Encode(), http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie}})
	require.Equal(t, 303, response.Code)
	callback, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:49152/callback", callback.Scheme+"://"+callback.Host+callback.Path)
	require.Equal(t, link.State, callback.Query().Get("state"))
	code := auth.Secret(callback.Query().Get("code"))
	require.True(t, auth.ValidToken(code))
	require.Equal(t, 1, flow.authorizations(t))

	// Browser credentials on the token route are refused without consuming it.
	refused := requestAuth(flow.handler, "POST", auth.TokenPath, jsonBody(t, auth.TokenRequest{Code: code, Verifier: verifier}),
		http.Header{"Content-Type": {"application/json"}, "Cookie": {cookie}})
	require.Equal(t, 400, refused.Code)
	require.Equal(t, 1, flow.authorizations(t))

	redeemed := flow.redeem(t, code, verifier)
	require.Equal(t, 200, redeemed.StatusCode)
	var issued auth.LoginResponse
	require.NoError(t, json.NewDecoder(redeemed.Body).Decode(&issued))
	require.Equal(t, "member-user", issued.User.Username)
	require.Equal(t, auth.Member, issued.User.Role)
	require.False(t, issued.IdleExpiresAt.IsZero())
	require.True(t, issued.IdleExpiresAt.Before(issued.ExpiresAt))
	whoami := requestAuth(flow.handler, "GET", auth.WhoAmIPath, "", http.Header{"Authorization": {"Bearer " + string(issued.Token)}})
	require.Equal(t, 200, whoami.Code)

	replay := flow.redeem(t, code, verifier)
	require.Equal(t, 401, replay.StatusCode)
	var failure auth.ErrorResponse
	require.NoError(t, json.NewDecoder(replay.Body).Decode(&failure))
	require.Equal(t, auth.InvalidCredentials, failure.Error.Code)

	logs := flow.logs.String()
	require.Contains(t, logs, `"route":"/api/auth/token"`)
	for _, secret := range []string{string(code), string(verifier), link.State, link.Challenge, string(issued.Token)} {
		require.NotContains(t, logs, secret)
	}
}

// Scenarios: cross-site approval and invalid link parameters store nothing
// with a real session; a wrong verifier consumes the code over HTTP.
func TestRealApprovalRefusalsAndWrongVerifier(t *testing.T) {
	flow := newAuthorizeFlow(t)
	verifier, link := randomPKCE(t)
	cookie, _ := flow.browserSignIn(t, "personal-admin", link.Link())
	body := url.Values{"port": {"49152"}, "challenge": {link.Challenge}, "state": {link.State}}.Encode()
	for _, headers := range []http.Header{
		{"Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie}},
		{"Origin": {"https://attacker.invalid"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie}},
		{"Origin": {"http://127.0.0.1"}, "Sec-Fetch-Site": {"cross-site"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie}},
	} {
		response := requestAuth(flow.handler, "POST", auth.AuthorizePath, body, headers)
		require.Equal(t, 403, response.Code)
		require.Empty(t, response.Header().Get("Location"))
	}
	invalid := url.Values{"port": {"80"}, "challenge": {link.Challenge}, "state": {link.State}}.Encode()
	response := requestAuth(flow.handler, "POST", auth.AuthorizePath, invalid,
		http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie}})
	require.Equal(t, 400, response.Code)
	response = requestAuth(flow.handler, "GET", auth.AuthorizePath+"?"+invalid, "", http.Header{"Cookie": {cookie}})
	require.Equal(t, 400, response.Code)
	require.Zero(t, flow.authorizations(t))

	response = requestAuth(flow.handler, "POST", auth.AuthorizePath, body,
		http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie}})
	require.Equal(t, 303, response.Code)
	callback, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	code := auth.Secret(callback.Query().Get("code"))
	wrong, _ := randomPKCE(t)
	require.Equal(t, 401, flow.redeem(t, code, wrong).StatusCode)
	require.Equal(t, 401, flow.redeem(t, code, verifier).StatusCode)
	require.Zero(t, flow.authorizations(t))
}
