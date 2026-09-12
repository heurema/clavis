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

// connectionsPageFake records exactly what the browser page handed the service.
// The page only lists, so every other method must never be reached from this
// transport.
type connectionsPageFake struct {
	list    auth.ConnectionList
	err     error
	calls   int
	session auth.Session
	terms   []auth.SelectorTerm
	limit   int
}

func (c *connectionsPageFake) ListConnections(_ context.Context, session auth.Session, terms []auth.SelectorTerm, limit int) (auth.ConnectionList, error) {
	c.calls++
	c.session, c.terms, c.limit = session, terms, limit
	return c.list, c.err
}

func (c *connectionsPageFake) GetConnection(context.Context, auth.Session, string) (auth.Connection, error) {
	return auth.Connection{}, errNoBrowserMutation
}

func (c *connectionsPageFake) CreateConnection(context.Context, auth.Session, auth.CreateConnectionRequest, bool) (auth.ConnectionMutation, error) {
	return auth.ConnectionMutation{}, errNoBrowserMutation
}

func (c *connectionsPageFake) UpdateConnection(context.Context, auth.Session, string, auth.UpdateConnectionRequest, bool) (auth.ConnectionMutation, error) {
	return auth.ConnectionMutation{}, errNoBrowserMutation
}

func (c *connectionsPageFake) SetConnectionCredentials(context.Context, auth.Session, string, auth.Secret, bool) (auth.ConnectionMutation, error) {
	return auth.ConnectionMutation{}, errNoBrowserMutation
}

func (c *connectionsPageFake) SetConnectionEnabled(context.Context, auth.Session, string, bool, bool) (auth.ConnectionMutation, error) {
	return auth.ConnectionMutation{}, errNoBrowserMutation
}

func (c *connectionsPageFake) DeleteConnection(context.Context, auth.Session, string, bool) (auth.ConnectionDeletion, error) {
	return auth.ConnectionDeletion{}, errNoBrowserMutation
}

func (c *connectionsPageFake) CheckConnection(context.Context, auth.Session, string) (auth.ConnectionCheck, error) {
	return auth.ConnectionCheck{}, errNoBrowserMutation
}

// pageTarget is everything a stored connection knows about where it points.
// None of it is display data, so none of it may appear in the response.
var pageTarget = map[string]string{
	"host":     "sentinel-host.invalid",
	"port":     "5432",
	"user":     "sentinel-role",
	"database": "sentinel-db",
	"url":      "postgres://sentinel-role@sentinel-host.invalid:5432/sentinel-db",
}

var listedConnections = auth.ConnectionList{
	Connections: []auth.Connection{
		{
			ID: "12345678-1234-4234-8234-1234567890c1", Name: "warehouse-primary", Title: "Warehouse primary",
			Description: "sentinel-description", Scope: "sentinel-scope",
			Provider: auth.ProviderPostgreSQL, Target: pageTarget,
			Labels: map[string]string{"env": "prod"}, Enabled: true,
			LastCheck: &auth.CheckResult{Outcome: auth.CheckReachable, CheckedAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)},
		},
		{
			ID: "12345678-1234-4234-8234-1234567890c2", Name: "metrics-eu", Title: "Metrics EU",
			Provider: auth.ProviderVictoriaMetrics, Target: pageTarget,
		},
	},
	Truncated: true,
}

// The production views render the page here so the transport test proves what
// the administrator actually receives, and the adapter is composed directly so
// this slice depends on no route wiring.
func connectionsPageHandler(t *testing.T, f *backendFixture, connections auth.Connections) http.Handler {
	t.Helper()
	adapter, err := newAuthHTTP("http://127.0.0.1", f, AuthViews{})
	require.NoError(t, err)
	adapter.recorder = f
	adapter.admin = f
	adapter.connections = connections
	checker := platform.CheckFunc(func(context.Context) platform.Readiness {
		return platform.Readiness{State: platform.Ready}
	})
	return handler(time.Second, checker, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
}

func connectionsPageBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	for _, forbidden := range []string{
		"postgres://", "sentinel-host.invalid", "sentinel-role", "sentinel-db",
		"sentinel-description", "sentinel-scope", "secret", string(fixtureToken),
	} {
		require.NotContains(t, string(body), forbidden)
	}
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.Equal(t, "frame-ancestors 'none'", response.Header.Get("Content-Security-Policy"))
	require.Equal(t, "text/html; charset=utf-8", response.Header.Get("Content-Type"))
	require.Equal(t, "nosniff", response.Header.Get("X-Content-Type-Options"))
	require.Empty(t, response.Header.Get("Set-Cookie"))
	return string(body)
}

func TestConnectionsPageRendersTheConnectionsTable(t *testing.T) {
	f := &backendFixture{}
	fake := &connectionsPageFake{list: listedConnections}
	response := adminPage(connectionsPageHandler(t, f, fake))
	require.Equal(t, 200, response.StatusCode)
	body := connectionsPageBody(t, response)
	for _, fragment := range []string{
		">Connections<", "warehouse-primary", "Warehouse primary", "metrics-eu", "Metrics EU",
		">postgresql<", ">victoriametrics<", ">env=prod<", ">Enabled<", ">Disabled<",
		">reachable<", "2026-03-04 05:06 UTC", ">Unchecked<",
		"Showing the first 1000 connections; the list is limited.",
	} {
		require.Contains(t, body, fragment)
	}
	require.Equal(t, 1, fake.calls)
	require.Equal(t, "12345678-1234-4234-8234-123456789aaa", fake.session.ID)
	require.Equal(t, fixtureIdentity.User, fake.session.User)
	require.Equal(t, auth.MaxConnectionListing, fake.limit)
	require.Nil(t, fake.terms, "the page lists without a selector")
	require.Empty(t, f.events, "reading the page records no event")
}

func TestConnectionsPageMemberIsForbiddenWithoutListing(t *testing.T) {
	f := &backendFixture{role: auth.Member}
	fake := &connectionsPageFake{list: listedConnections}
	response := adminPage(connectionsPageHandler(t, f, fake))
	require.Equal(t, 403, response.StatusCode)
	body := connectionsPageBody(t, response)
	require.NotContains(t, body, "warehouse-primary")
	require.NotContains(t, body, "metrics-eu")
	require.Zero(t, fake.calls, "the role check precedes the listing")
	require.Empty(t, f.events)
}

// A failed or absent connection listing fails closed exactly like the user
// list: no page without current data, and no detail about the failure.
func TestConnectionsPageFailsClosedWhenTheListingFails(t *testing.T) {
	for name, connections := range map[string]auth.Connections{
		"unavailable": &connectionsPageFake{list: listedConnections, err: &auth.Error{Code: auth.ServiceUnavailable}},
		"opaque":      &connectionsPageFake{list: listedConnections, err: errors.New("SENTINEL_PRIVATE_DRIVER")},
		"missing":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := &backendFixture{}
			response := adminPage(connectionsPageHandler(t, f, connections))
			require.Equal(t, 503, response.StatusCode)
			body := connectionsPageBody(t, response)
			require.Contains(t, body, "<!doctype html>")
			require.NotContains(t, body, "SENTINEL")
			require.NotContains(t, body, "warehouse-primary")
			require.NotContains(t, body, "metrics-eu")
			require.NotContains(t, body, ">Connections<")
			require.Empty(t, f.events)
		})
	}
}

func TestConnectionsPageUnauthenticatedListingRedirects(t *testing.T) {
	f := &backendFixture{}
	fake := &connectionsPageFake{err: &auth.Error{Code: auth.Unauthenticated}}
	response := adminPage(connectionsPageHandler(t, f, fake))
	require.Equal(t, 303, response.StatusCode)
	require.Equal(t, "/login", response.Header.Get("Location"))
	require.Empty(t, response.Header.Get("Set-Cookie"))
	require.NoError(t, response.Body.Close())
	require.Equal(t, 1, fake.calls)
	require.Empty(t, f.events)
}
