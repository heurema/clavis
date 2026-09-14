package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
)

var listedGrants = auth.GrantList{
	Grants: []auth.Grant{{
		User:       auth.GrantParty{ID: "12345678-1234-4234-8234-1234567890a1", Name: "granted-member"},
		Connection: auth.GrantParty{ID: "12345678-1234-4234-8234-1234567890c1", Name: "warehouse-primary"},
		CreatedAt:  time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC),
		CreatedBy:  auth.GrantParty{ID: fixtureIdentity.User.ID, Name: "personal-admin"},
	}},
	Truncated: true,
}

// The adapter is composed directly with the grants fake so the page's grant
// loading is proven without route wiring.
func grantsPageHandler(t *testing.T, f *backendFixture, connections auth.Connections, grants auth.Grants) http.Handler {
	t.Helper()
	adapter, err := newAuthHTTP("http://127.0.0.1", f, AuthViews{})
	require.NoError(t, err)
	adapter.admin = f
	adapter.connections = connections
	adapter.grants = grants
	checker := platform.CheckFunc(func(context.Context) platform.Readiness {
		return platform.Readiness{State: platform.Ready}
	})
	return handler(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
}

func TestGrantsPageRendersTheGrantsTable(t *testing.T) {
	f := &backendFixture{}
	connections := &connectionsPageFake{list: listedConnections}
	grants := &fakeGrants{grantList: listedGrants}
	response := requestPage(grantsPageHandler(t, f, connections, grants), "/admin/grants")
	require.Equal(t, 200, response.StatusCode)
	body := connectionsPageBody(t, response)
	for _, fragment := range []string{
		">Grants</h1>", ">granted-member<", ">warehouse-primary<", ">personal-admin<", "2026-06-07 08:09 UTC",
		"Showing the first 1000 grants; the list is limited.",
	} {
		require.Contains(t, body, fragment)
	}
	// The shell marks this page and counts all three lists beside it.
	require.Contains(t, body, `<a href="/admin/grants" aria-current="page"`)
	require.Equal(t, 1, strings.Count(body, `aria-current="page"`))
	require.Equal(t, []string{"0", "2+", "1+"}, sidebarCountsOf(body))
	// The grants page renders no other table.
	require.NotContains(t, body, "Warehouse primary")
	require.NotContains(t, body, "1234567890a1")
	require.Equal(t, 1, connections.calls)
	require.Len(t, grants.grantCalls, 1)
	require.Equal(t, "list", grants.grantCalls[0].operation)
	require.Equal(t, auth.GrantFilter{Limit: auth.MaxGrantListing}, grants.grantCalls[0].filter)
	require.Equal(t, auth.Admin, grants.grantCalls[0].role)
}

// A failed grants listing fails the page closed after the connections listing
// succeeded, and a failed connections listing never reaches the grants.
func TestGrantsPageFailsClosedInOrder(t *testing.T) {
	f := &backendFixture{}
	grants := &fakeGrants{grantErr: errors.New("private grants outage")}
	response := requestPage(grantsPageHandler(t, f, &connectionsPageFake{list: listedConnections}, grants), "/admin/grants")
	require.Equal(t, 503, response.StatusCode)
	body := connectionsPageBody(t, response)
	require.NotContains(t, body, "warehouse-primary")
	require.NotContains(t, body, "private grants outage")
	require.Contains(t, body, "Authentication is temporarily unavailable")
	require.Len(t, grants.grantCalls, 1)

	grants = &fakeGrants{grantList: listedGrants}
	response = requestPage(grantsPageHandler(t, f, &connectionsPageFake{err: &auth.Error{Code: auth.Forbidden}}, grants), "/admin/grants")
	require.Equal(t, 403, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Empty(t, grants.grantCalls, "the grants listing is not attempted after a failed connections listing")

	response = requestPage(grantsPageHandler(t, &backendFixture{role: auth.Member}, &connectionsPageFake{list: listedConnections}, grants), "/admin/grants")
	require.Equal(t, 403, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Empty(t, grants.grantCalls, "members never reach the listing")

	// A handler composed without the grants dependency refuses the page.
	adapter, err := newAuthHTTP("http://127.0.0.1", f, AuthViews{})
	require.NoError(t, err)
	adapter.admin, adapter.connections = f, &connectionsPageFake{list: listedConnections}
	checker := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
	response = requestPage(handler(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter), "/admin/grants")
	require.Equal(t, 503, response.StatusCode)
	require.NoError(t, response.Body.Close())
}
