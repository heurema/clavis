package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/config"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func serverDatabase(t *testing.T) (*pgxpool.Pool, string, auth.Secret) {
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
	schema := "backend_http_" + hex.EncodeToString(random[:8])
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
		require.NoError(t, err)
		admin.Close()
	})
	password := auth.Secret(base64.RawURLEncoding.EncodeToString(random[:]))
	path := filepath.Join(t.TempDir(), "bootstrap-secret")
	require.NoError(t, os.WriteFile(path, []byte(password), 0600))
	return pool, path, password
}

func TestRealHTTPLoginFailsClosedBeforeInitializationAndAfterPoolClose(t *testing.T) {
	pool, _, _ := serverDatabase(t)
	checker := store.NewInitializer(pool, "", "")
	service, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	checks := 0
	// Health has a separate counter: authentication must use the service's
	// initializer, not the HTTP readiness checker.
	health := platform.CheckFunc(func(ctx context.Context) platform.Readiness {
		checks++
		return checker.Check(ctx)
	})
	handler, err := HandlerWithAuth(time.Second, health, service, service, service, service, "http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	reject := func(t *testing.T) {
		t.Helper()
		code := checker.Check(t.Context()).Response().Error.Code
		for _, tc := range []struct {
			path, body string
			headers    http.Header
		}{
			{auth.LoginPath, `{"username":"personal-admin","password":"valid test password"}`, http.Header{"Content-Type": {"application/json"}}},
			{"/login", "username=personal-admin&password=valid+test+password", http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}}},
		} {
			response := requestAuth(handler, "POST", tc.path, tc.body, tc.headers)
			require.Equal(t, 503, response.Code)
			require.Contains(t, response.Body.String(), code)
			require.Empty(t, response.Header().Get("Set-Cookie"))
			require.NotContains(t, response.Body.String(), "valid test password")
		}
		require.Zero(t, checks)
	}
	t.Run("unmigrated", reject)
	require.NoError(t, store.Migrate(t.Context(), pool))
	require.Equal(t, platform.SetupRequired, checker.Attempt(t.Context()).State)
	t.Run("uninitialized", reject)
	pool.Close()
	t.Run("unavailable", reject)
}

func TestRealHTTPAuthenticationEventsAndLockDeadlines(t *testing.T) {
	pool, path, password := serverDatabase(t)
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	readinessCalls := 0
	readiness := platform.CheckFunc(func(ctx context.Context) platform.Readiness {
		readinessCalls++
		return checker.Check(ctx)
	})
	service, err := store.NewLocalAuth(pool, readiness, auth.DefaultSessionTTL)
	require.NoError(t, err)
	handler, err := HandlerWithAuth(time.Second, readiness, service, service, service, service, "http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	encoded, err := json.Marshal(auth.LoginRequest{Username: "personal-admin", Password: password})
	require.NoError(t, err)
	signIn := func() auth.LoginResponse {
		before := readinessCalls
		response := requestAuth(handler, "POST", auth.LoginPath, string(encoded), http.Header{"Content-Type": {"application/json"}})
		require.Equal(t, 200, response.Code)
		require.Equal(t, before+1, readinessCalls, "the real service checks readiness once; the adapter must not duplicate it")
		var issued auth.LoginResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &issued))
		return issued
	}
	issued := signIn()
	headers := http.Header{"Authorization": {"Bearer " + string(issued.Token)}}
	response := requestAuth(handler, "GET", auth.WhoAmIPath, "", headers)
	require.Equal(t, 200, response.Code)
	require.NotContains(t, response.Body.String(), string(issued.Token))
	before := 0
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events`).Scan(&before))
	response = requestAuth(handler, "POST", auth.LoginPath, `{"SENTINEL_PRIVATE_BODY":"x"}`, http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, 400, response.Code)
	var count int
	var event string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events`).Scan(&count))
	require.Equal(t, before+1, count)
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT row_to_json(auth_events)::text FROM auth_events WHERE outcome='invalid_argument'`).Scan(&event))
	require.NotContains(t, event, "SENTINEL")
	require.Contains(t, event, `"actor_id":null`)
	require.Contains(t, event, `"target_id":null`)
	require.Contains(t, event, `"session_id":null`)
	for _, operation := range []string{"login", "logout", "revoke", "audit"} {
		t.Run(operation, func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			require.NoError(t, err)
			if operation == "audit" {
				_, err = tx.Exec(t.Context(), `LOCK TABLE auth_events IN ACCESS EXCLUSIVE MODE`)
			} else {
				_, err = tx.Exec(t.Context(), `SELECT id FROM users WHERE id=$1 FOR UPDATE`, issued.User.ID)
			}
			require.NoError(t, err)
			start := time.Now()
			switch operation {
			case "login":
				response = requestAuth(handler, "POST", auth.LoginPath, string(encoded), http.Header{"Content-Type": {"application/json"}})
			case "logout":
				response = requestAuth(handler, "POST", auth.LogoutPath, "", headers)
			case "revoke":
				response = requestAuth(handler, "POST", "/api/admin/users/"+issued.User.ID+"/sessions/revoke", "", headers)
			case "audit":
				response = requestAuth(handler, "POST", auth.LogoutPath, "", http.Header{})
			}
			require.Equal(t, 503, response.Code)
			require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
			require.Less(t, time.Since(start), 6*time.Second)
			require.Greater(t, time.Since(start), 4*time.Second)
			require.NoError(t, tx.Rollback(t.Context()))
			response = requestAuth(handler, "GET", auth.WhoAmIPath, "", headers)
			require.Equal(t, 200, response.Code)
		})
	}
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM sessions`).Scan(&count))
	require.Equal(t, 1, count)
	response = requestAuth(handler, "POST", "/api/admin/users/"+issued.User.ID+"/sessions/revoke", "", headers)
	require.Equal(t, 200, response.Code)
	response = requestAuth(handler, "GET", auth.WhoAmIPath, "", headers)
	require.Equal(t, 401, response.Code)
	newSession := signIn()
	require.NotEqual(t, issued.Token, newSession.Token)
}

func TestNormalServeInitializesAndResolvesPortZero(t *testing.T) {
	pool, path, password := serverDatabase(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	origin := "http://" + listener.Addr().String()
	cfg := config.Config{HTTPAddr: "127.0.0.1:0", DBCheckTimeout: time.Second, ShutdownTimeout: time.Second,
		BootstrapUsername: "personal-admin", BootstrapPasswordFile: path, SessionTTL: auth.DefaultSessionTTL}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, cfg, pool, slog.New(slog.NewJSONHandler(io.Discard, nil))) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	require.Eventually(t, func() bool {
		response, err := client.Get(origin + "/health/ready")
		if err != nil {
			return false
		}
		defer func() { _ = response.Body.Close() }()
		return response.StatusCode == 200
	}, 5*time.Second, 20*time.Millisecond)
	body := "username=personal-admin&password=" + string(password)
	request, err := http.NewRequest("POST", origin+"/login", strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, 303, response.StatusCode)
	require.Equal(t, "/admin", response.Header.Get("Location"))
	require.Len(t, response.Cookies(), 1)
	require.Equal(t, developmentCookie, response.Cookies()[0].Name)
	require.False(t, response.Cookies()[0].Secure)
}

func TestBrowserLoginNeverRetargetsAnExistingSession(t *testing.T) {
	pool, path, password := serverDatabase(t)
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	service, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	// An isolated member fixture shares this test's generated password so only
	// the username changes between the two browser sign-ins.
	_, err = pool.Exec(t.Context(), `INSERT INTO users(id,username,password_hash,role)
		SELECT $1,'member-user',password_hash,'member' FROM users WHERE username='personal-admin'`, fixtureIdentity.User.ID)
	require.NoError(t, err)
	handler, err := HandlerWithAuth(time.Second, checker, service, service, service, service, "http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	headers := http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}}
	form := func(username string, password auth.Secret) string {
		return url.Values{"username": {username}, "password": {string(password)}}.Encode()
	}
	memberResponse := requestAuth(handler, "POST", "/login", form("member-user", password), headers)
	require.Equal(t, 303, memberResponse.Code)
	require.Len(t, memberResponse.Result().Cookies(), 1)
	oldCookie := memberResponse.Result().Cookies()[0]
	headers.Set("Cookie", oldCookie.Name+"="+oldCookie.Value)

	failure := requestAuth(handler, "POST", "/login", form("personal-admin", "incorrect test password"), headers)
	require.Equal(t, 401, failure.Code)
	require.Empty(t, failure.Header().Get("Set-Cookie"))
	oldSession, err := service.Authenticate(t.Context(), auth.Secret(oldCookie.Value), auth.Browser)
	require.NoError(t, err)
	require.Equal(t, "member-user", oldSession.User.Username)
	require.Equal(t, auth.Member, oldSession.User.Role)

	adminResponse := requestAuth(handler, "POST", "/login", form("personal-admin", password), headers)
	require.Equal(t, 303, adminResponse.Code)
	require.Len(t, adminResponse.Result().Cookies(), 1)
	newCookie := adminResponse.Result().Cookies()[0]
	require.False(t, oldCookie.Value == newCookie.Value, "successful login must issue an independent token")
	newSession, err := service.Authenticate(t.Context(), auth.Secret(newCookie.Value), auth.Browser)
	require.NoError(t, err)
	require.Equal(t, "personal-admin", newSession.User.Username)
	require.Equal(t, auth.Admin, newSession.User.Role)
	stillOld, err := service.Authenticate(t.Context(), auth.Secret(oldCookie.Value), auth.Browser)
	require.NoError(t, err)
	require.Equal(t, oldSession.ID, stillOld.ID)
	require.Equal(t, oldSession.Identity, stillOld.Identity)
	response := requestAuth(handler, "GET", "/admin", "", http.Header{"Cookie": {oldCookie.Name + "=" + oldCookie.Value}})
	require.Equal(t, 403, response.Code, "old member session must not inherit the new administrator login")
}
