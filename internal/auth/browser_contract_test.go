package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

func TestBrowserLoginAndAdminContracts(t *testing.T) {
	require.Equal(t, auth.BrowserOutcome{Status: 303, Location: "/admin"}, auth.LoginOutcome(nil))
	require.Equal(t, auth.BrowserOutcome{Status: 200}, auth.AdminOutcome(nil))
	require.Equal(t, auth.BrowserOutcome{Status: 303, Location: "/login"}, auth.AdminOutcome(&auth.Error{Code: auth.Unauthenticated}))
	for code, status := range map[string]int{
		auth.InvalidArgument: 400, auth.InvalidCredentials: 401, auth.Forbidden: 403,
		auth.RateLimited: 429, auth.ServiceUnavailable: 503,
		platform.CodeSetupRequired: 503, platform.CodeBootstrapFailed: 503,
	} {
		result := auth.LoginOutcome(&auth.Error{Code: code})
		require.Equal(t, status, result.Status)
		require.Equal(t, code, result.ErrorCode)
		require.False(t, result.ClearCookie)
		require.Empty(t, result.Location)
	}
	require.Equal(t, http.StatusForbidden, auth.AdminOutcome(&auth.Error{Code: auth.Forbidden}).Status)
}

func TestBrowserLogoutContracts(t *testing.T) {
	for _, err := range []error{nil, &auth.Error{Code: auth.Unauthenticated}, errors.New("SENTINEL_SECRET")} {
		result := auth.LogoutOutcome(false, err)
		require.Equal(t, auth.BrowserOutcome{Status: 403, ErrorCode: auth.Forbidden}, result)
	}
	for _, err := range []error{nil, &auth.Error{Code: auth.Unauthenticated}} {
		require.Equal(t, auth.BrowserOutcome{Status: 303, Location: "/login", ClearCookie: true}, auth.LogoutOutcome(true, err))
	}
	result := auth.LogoutOutcome(true, errors.New("SENTINEL_SECRET"))
	require.Equal(t, auth.BrowserOutcome{
		Status: 503, ErrorCode: auth.ServiceUnavailable, ClearCookie: true,
		RemoteRevocationUnconfirmed: true,
	}, result)
}
