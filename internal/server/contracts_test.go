package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	for _, path := range []string{"/", "/health/live", "/assets/appearance.js"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Cookie", "clavis.session=malformed")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code, path)
	}
	require.Zero(t, calls)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Contains(t, response.Body.String(), platform.CodeSetupRequired)
	require.Equal(t, 1, calls)
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
	for path, status := range map[string]int{
		"/admin":           http.StatusSeeOther,
		"/api/auth/login":  http.StatusMethodNotAllowed,
		"/api/auth/whoami": http.StatusUnauthorized,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, status, response.Code)
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.NotContains(t, response.Body.String(), "fixture")
	}
}
