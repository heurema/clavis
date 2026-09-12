package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

// listFake stands in for the administration service. The browser page only
// reads, so the mutating methods must never be reached from this transport.
type listFake struct {
	list    auth.UserList
	err     error
	calls   int
	session auth.Session
}

var errNoBrowserMutation = errors.New("the administration page performs no mutations")

func (l *listFake) ListUsers(_ context.Context, session auth.Session) (auth.UserList, error) {
	l.calls++
	l.session = session
	return l.list, l.err
}

func (l *listFake) CreateUser(context.Context, auth.Session, auth.CreateUserRequest) (auth.UserRecord, error) {
	return auth.UserRecord{}, errNoBrowserMutation
}

func (l *listFake) SetUserDisabled(context.Context, auth.Session, string, bool) (auth.UserMutation, error) {
	return auth.UserMutation{}, errNoBrowserMutation
}

func (l *listFake) ResetPassword(context.Context, auth.Session, string, auth.Secret) (auth.UserMutation, error) {
	return auth.UserMutation{}, errNoBrowserMutation
}

func (l *listFake) SetRole(context.Context, auth.Session, string, auth.Role) (auth.UserMutation, error) {
	return auth.UserMutation{}, errNoBrowserMutation
}

// The adapter is composed directly so this slice depends on no route wiring.
func adminPageHandler(t *testing.T, f *backendFixture, admin auth.Administration) http.Handler {
	t.Helper()
	adapter, err := newAuthHTTP("http://127.0.0.1", f, fixtureViews())
	require.NoError(t, err)
	adapter.admin = admin
	adapter.connections = f
	adapter.grants = f
	checker := platform.CheckFunc(func(context.Context) platform.Readiness {
		return platform.Readiness{State: platform.Ready}
	})
	return handler(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
}

func adminPage(handler http.Handler) *http.Response {
	return requestAuth(handler, http.MethodGet, "/admin", "",
		http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}).Result()
}

var listedUsers = auth.UserList{
	Users: []auth.UserRecord{
		{ID: fixtureIdentity.User.ID, Username: "personal-admin", Role: auth.Admin, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		{ID: "12345678-1234-4234-8234-1234567890a2", Username: "blocked-member", Role: auth.Member, Disabled: true, CreatedAt: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)},
	},
	Truncated: true,
}

func TestAdminPageRendersTheUserList(t *testing.T) {
	f := &backendFixture{}
	fake := &listFake{list: listedUsers}
	response := adminPage(adminPageHandler(t, f, fake))
	require.Equal(t, 200, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	for _, fragment := range []string{"personal-admin", "blocked-member", `"role":"member"`, `"disabled":true`, `"Truncated":true`} {
		require.Contains(t, string(body), fragment)
	}
	require.Equal(t, 1, fake.calls)
	require.Equal(t, "12345678-1234-4234-8234-123456789aaa", fake.session.ID)
	require.Equal(t, fixtureIdentity.User, fake.session.User)
	require.Empty(t, response.Header.Get("Set-Cookie"))
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.Equal(t, "frame-ancestors 'none'", response.Header.Get("Content-Security-Policy"))
	require.Equal(t, "text/html; charset=utf-8", response.Header.Get("Content-Type"))
	require.Equal(t, "nosniff", response.Header.Get("X-Content-Type-Options"))
}

func TestAdminPageMemberIsForbiddenWithoutListing(t *testing.T) {
	f := &backendFixture{role: auth.Member}
	fake := &listFake{list: listedUsers}
	response := adminPage(adminPageHandler(t, f, fake))
	require.Equal(t, 403, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Contains(t, string(body), auth.Forbidden)
	require.NotContains(t, string(body), "blocked-member")
	require.Zero(t, fake.calls, "the role check precedes the listing")
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.Equal(t, "frame-ancestors 'none'", response.Header.Get("Content-Security-Policy"))
}

// A failed listing must fail closed instead of rendering administration
// without current data, and must not disclose the failure's details.
func TestAdminPageFailsClosedWhenTheListingFails(t *testing.T) {
	forbidden := adminPage(adminPageHandler(t, &backendFixture{}, &listFake{list: listedUsers, err: &auth.Error{Code: auth.Forbidden}}))
	require.Equal(t, 403, forbidden.StatusCode)
	require.NoError(t, forbidden.Body.Close())

	unauthenticated := adminPage(adminPageHandler(t, &backendFixture{}, &listFake{list: listedUsers, err: &auth.Error{Code: auth.Unauthenticated}}))
	require.Equal(t, 303, unauthenticated.StatusCode)
	require.Equal(t, "/login", unauthenticated.Header.Get("Location"))
	require.Empty(t, unauthenticated.Header.Get("Set-Cookie"))
	require.NoError(t, unauthenticated.Body.Close())

	for name, admin := range map[string]auth.Administration{
		"unavailable": &listFake{list: listedUsers, err: &auth.Error{Code: auth.ServiceUnavailable}},
		"opaque":      &listFake{list: listedUsers, err: errors.New("SENTINEL_PRIVATE_DRIVER")},
		"missing":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := &backendFixture{}
			response := adminPage(adminPageHandler(t, f, admin))
			require.Equal(t, 503, response.StatusCode)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Contains(t, string(body), auth.ServiceUnavailable)
			require.Contains(t, string(body), "<!doctype html>")
			require.NotContains(t, string(body), "SENTINEL")
			require.NotContains(t, string(body), "personal-admin")
			require.NotContains(t, string(body), "blocked-member")
			require.Empty(t, response.Header.Get("Set-Cookie"))
			require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			require.Equal(t, "frame-ancestors 'none'", response.Header.Get("Content-Security-Policy"))
			require.Equal(t, "text/html; charset=utf-8", response.Header.Get("Content-Type"))
			require.Equal(t, "nosniff", response.Header.Get("X-Content-Type-Options"))
		})
	}
}
