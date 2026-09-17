package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/buildinfo"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

func TestInjectedReadinessIsBoundedAndPublicDocumentsBypassIt(t *testing.T) {
	calls := 0
	checker := platform.CheckFunc(func(ctx context.Context) platform.Readiness {
		calls++
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), time.Second)
		return platform.Readiness{State: platform.SetupRequired}
	})
	handler := HandlerWithReadiness(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	// The root redirect is public too: it never reaches the checker.
	for path, status := range map[string]int{
		"/":                     http.StatusSeeOther,
		"/livez":                http.StatusOK,
		"/assets/appearance.js": http.StatusOK,
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Cookie", "clavis.session=malformed")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, status, response.Code, path)
	}
	require.Zero(t, calls)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Contains(t, response.Body.String(), platform.CodeSetupRequired)
	require.Equal(t, 1, calls)
	// The aggregate runs the same bounded check and nests the same failure.
	aggregate := httptest.NewRecorder()
	handler.ServeHTTP(aggregate, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusServiceUnavailable, aggregate.Code)
	require.JSONEq(t, `{"status":"unhealthy","version":"`+buildinfo.Current().Version+`","checks":{"live":{"status":"alive"},"ready":{"status":"not_ready","error":{"code":"SETUP_REQUIRED","message":"Initial administrator configuration is required"}}}}`, aggregate.Body.String())
	require.Equal(t, 2, calls)
}

func TestRealRoutesNeverExposeAuthenticationFixtures(t *testing.T) {
	handler := HandlerWithReadiness(time.Second, platform.CheckFunc(func(context.Context) platform.Readiness {
		t.Fatal("an unknown route must not check readiness")
		return platform.Readiness{}
	}), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for _, path := range []string{"/register", "/bootstrap", "/api/users", "/api/bootstrap"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusNotFound, response.Code)
	}
	// /admin redirects into the shell; the shell's own routes send a visitor
	// without a session on to sign-in.
	for path, location := range map[string]string{
		"/admin":       "/admin/users",
		"/admin/users": "/login",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusSeeOther, response.Code, path)
		require.Equal(t, location, response.Header().Get("Location"), path)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.NotContains(t, response.Body.String(), "fixture")
	}
	for path, status := range map[string]int{
		"/api/auth/login":  http.StatusNotFound,
		"/api/auth/whoami": http.StatusUnauthorized,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, status, response.Code)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.NotContains(t, response.Body.String(), "fixture")
	}
}
