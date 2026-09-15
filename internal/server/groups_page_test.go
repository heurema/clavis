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

// The description is text an administrator wrote, so the fixture carries
// markup to prove the page escapes it rather than trusting it.
var listedGroups = auth.GroupList{
	Groups: []auth.Group{{
		ID:          "abcdefab-1234-4234-8234-1234567890b1",
		Name:        "finance-managers",
		Description: `warehouse readers <b>only</b>`,
		Members:     4,
		Grants:      2,
		CreatedAt:   time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 5, 7, 7, 8, 9, 0, time.UTC),
	}},
	Truncated: true,
}

// The adapter is composed directly with the groups fake so the page's group
// loading is proven without route wiring.
func groupsPageHandler(t *testing.T, f *backendFixture, groups auth.Groups, connections auth.Connections) http.Handler {
	t.Helper()
	adapter, err := newAuthHTTP("http://127.0.0.1", f, AuthViews{})
	require.NoError(t, err)
	adapter.admin = f
	adapter.groups = groups
	adapter.connections = connections
	adapter.grants = f
	checker := platform.CheckFunc(func(context.Context) platform.Readiness {
		return platform.Readiness{State: platform.Ready}
	})
	return handler(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
}

func TestGroupsPageRendersTheGroupsTable(t *testing.T) {
	f := &backendFixture{}
	groups := &fakeGroups{groupList: listedGroups}
	connections := &connectionsPageFake{list: listedConnections}
	response := requestPage(groupsPageHandler(t, f, groups, connections), "/admin/groups")
	require.Equal(t, 200, response.StatusCode)
	body := connectionsPageBody(t, response)
	for _, fragment := range []string{
		">Groups</h1>", ">Name<", ">Description<", ">Members<", ">Grants<", ">Created<",
		">finance-managers<", "warehouse readers &lt;b&gt;only&lt;/b&gt;", ">4<", ">2<",
		"2026-05-06 07:08 UTC", "Showing the first 1000 groups; the list is limited.",
	} {
		require.Contains(t, body, fragment)
	}
	require.NotContains(t, body, "<b>only</b>")
	// The shell marks this page and counts all four lists beside it.
	require.Contains(t, body, `<a href="/admin/groups" aria-current="page"`)
	require.Equal(t, 1, strings.Count(body, `aria-current="page"`))
	require.Equal(t, []string{"0", "1+", "2+", "0"}, sidebarCountsOf(body))
	// The groups page renders no other table and no roster.
	require.NotContains(t, body, "warehouse-primary")
	require.NotContains(t, body, "1234567890b1")
	require.Equal(t, 1, connections.calls)
	require.Len(t, groups.groupCalls, 1)
	require.Equal(t, "list", groups.groupCalls[0].operation)
	require.Equal(t, auth.MaxGroupListing, groups.groupCalls[0].limit)
	require.Equal(t, auth.Admin, groups.groupCalls[0].role)
}

// The groups listing loads after the users and before the connections, so a
// failed group listing fails the page closed with the later lists untouched.
func TestGroupsPageFailsClosedInOrder(t *testing.T) {
	f := &backendFixture{}
	groups := &fakeGroups{groupErr: errors.New("private groups outage")}
	connections := &connectionsPageFake{list: listedConnections}
	response := requestPage(groupsPageHandler(t, f, groups, connections), "/admin/groups")
	require.Equal(t, 503, response.StatusCode)
	body := connectionsPageBody(t, response)
	require.NotContains(t, body, "finance-managers")
	require.NotContains(t, body, "private groups outage")
	require.Contains(t, body, "Authentication is temporarily unavailable")
	require.Len(t, groups.groupCalls, 1)
	require.Zero(t, connections.calls, "the connections listing is not attempted after a failed group listing")

	groups = &fakeGroups{groupList: listedGroups}
	response = requestPage(groupsPageHandler(t, &backendFixture{role: auth.Member}, groups, connections), "/admin/groups")
	require.Equal(t, 403, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Empty(t, groups.groupCalls, "members never reach the listing")

	// A handler composed without the groups dependency refuses the page.
	adapter, err := newAuthHTTP("http://127.0.0.1", f, AuthViews{})
	require.NoError(t, err)
	adapter.admin, adapter.connections, adapter.grants = f, connections, f
	checker := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
	response = requestPage(handler(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter), "/admin/groups")
	require.Equal(t, 503, response.StatusCode)
	require.NoError(t, response.Body.Close())
}

// An unauthenticated listing sends the visitor to sign-in rather than
// rendering an empty page, exactly like the other administration routes.
func TestGroupsPageUnauthenticatedListingRedirects(t *testing.T) {
	groups := &fakeGroups{groupErr: &auth.Error{Code: auth.Unauthenticated}}
	response := requestPage(groupsPageHandler(t, &backendFixture{}, groups, &connectionsPageFake{}), "/admin/groups")
	require.Equal(t, 303, response.StatusCode)
	require.Equal(t, "/login", response.Header.Get("Location"))
	require.Empty(t, response.Header.Get("Set-Cookie"))
	require.NoError(t, response.Body.Close())
	require.Len(t, groups.groupCalls, 1)
}
