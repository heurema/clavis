package web

import (
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func renderAuth(t *testing.T, status int, view templ.Component) string {
	t.Helper()
	response := httptest.NewRecorder()
	require.NoError(t, Render(response, httptest.NewRequest("GET", "/", nil), status, view))
	assert.Equal(t, status, response.Code)
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
	body := response.Body.String()
	assert.Contains(t, body, "<!doctype html>")
	assert.Contains(t, body, `lang="en"`)
	assert.Contains(t, body, `data-appearance="true"`)
	// The appearance control is a button whose state assistive technology reads.
	assert.Contains(t, body, `<button type="button" data-appearance="true"`)
	assert.Contains(t, body, `aria-pressed=`)
	assert.Contains(t, body, `aria-label="Dark appearance"`)
	assert.NotContains(t, body, "/assets/notices.txt", "the notices travel as an asset, not as a page link")
	assert.NotContains(t, body, "hx-post")
	return body
}

func TestLoginFailureDocuments(t *testing.T) {
	for _, code := range []string{
		auth.InvalidArgument, auth.InvalidCredentials, auth.Forbidden, auth.RateLimited,
		auth.ServiceUnavailable, platform.CodeDependencyUnavailable, platform.CodeInitializing,
		platform.CodeSetupRequired, platform.CodeBootstrapFailed, platform.CodeSchemaError,
		"SENTINEL_SECRET",
	} {
		t.Run(code, func(t *testing.T) {
			outcome := auth.LoginOutcome(&auth.Error{Code: code})
			body := renderAuth(t, outcome.Status, Login(LoginModel{
				Username: "admin.user", ErrorCode: code, RetryAfterSeconds: 30,
			}))
			assert.Contains(t, body, `value="admin.user"`)
			assert.Contains(t, body, `action="/login" method="post"`)
			assert.Contains(t, body, `name="password" type="password" required`)
			assert.NotContains(t, body, `type="hidden"`)
			assert.NotContains(t, body, "SENTINEL_SECRET")
			assert.Contains(t, body, `id="auth-error"`)
			assert.Contains(t, body, `role="alert"`)
			assert.Contains(t, body, "Your password has been cleared")
			assert.Contains(t, body, `>Sign in</h1>`)
			// The username format is enforced by the input, not explained in prose.
			assert.NotContains(t, body, "username-help")
			assert.NotContains(t, body, "lowercase letters")
		})
	}
}

func TestUsernameRetentionAndIdentityEscaping(t *testing.T) {
	for _, value := range []string{"", "UPPER", "ab", "<script>SENTINEL_SECRET</script>", strings.Repeat("a", 65)} {
		assert.Empty(t, retainedUsername(value))
	}
	for _, value := range []string{"abc", "admin.user-1_2", strings.Repeat("a", 64)} {
		assert.Equal(t, value, retainedUsername(value))
	}
	body := renderAuth(t, 200, Admin(AdminModel{Page: PageUsers, User: auth.User{
		ID: "not-for-display", Username: `<script>alert("identity")</script>`, Role: auth.Admin,
	}}))
	assert.NotContains(t, body, "<script>alert")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.NotContains(t, body, "not-for-display")
	assert.Contains(t, body, `action="/logout" method="post"`)
	// The shell navigates between the three pages.
	assert.Contains(t, body, `href="/admin/users"`)
	assert.Empty(t, initial(""))
	assert.Equal(t, "P", initial("personal-admin"))
}

// countPattern reads the sidebar counts in document order, so a test asserts all
// three at once and catches a count rendered against the wrong list.
var countPattern = regexp.MustCompile(`<span class="ml-auto text-xs tabular-nums text-muted-foreground">([^<]*)</span>`)

func sidebarCounts(body string) []string {
	matches := countPattern.FindAllStringSubmatch(body, -1)
	counts := make([]string, 0, len(matches))
	for _, match := range matches {
		counts = append(counts, match[1])
	}
	return counts
}

func adminBody(t *testing.T, model AdminModel) string {
	t.Helper()
	body := renderAuth(t, 200, Admin(model))
	assert.Equal(t, 1, strings.Count(body, "<form"), "only the sign-out form belongs on this page")
	assert.Contains(t, body, `action="/logout" method="post"`)
	assert.Contains(t, body, "Sign out")
	assert.NotContains(t, body, "hx-")
	assert.Equal(t, 1, strings.Count(body, "<script"), "only the shared appearance script belongs on this page")
	assert.Contains(t, body, `<script src="/assets/appearance.js">`)
	// The shell lists the three pages and announces exactly one as current.
	assert.Contains(t, body, `aria-label="Administration"`)
	for _, href := range []string{"/admin/users", "/admin/connections", "/admin/grants"} {
		assert.Contains(t, body, `href="`+href+`"`)
	}
	assert.Equal(t, 1, strings.Count(body, `aria-current="page"`), "one current page per document")
	assert.Len(t, sidebarCounts(body), 3, "one count per navigation entry")
	// The explanatory copy went with the single administration card.
	assert.NotContains(t, body, "Manage users and connections through the CLI")
	assert.NotContains(t, body, "Signed in as")
	assert.NotContains(t, body, "Administrator access")
	return body
}

// adminPage renders one page of the shell and asserts what the shell owes every
// page: the heading, the current entry and the three bounded counts.
func adminPage(t *testing.T, model AdminModel, page AdminPage, href string, counts []string) string {
	t.Helper()
	model.Page = page
	body := adminBody(t, model)
	assert.Contains(t, body, `<a href="`+href+`" aria-current="page"`)
	assert.Contains(t, body, `<h1 class="text-xl font-semibold tracking-tight">`+pageHeading(page)+`</h1>`)
	assert.Equal(t, counts, sidebarCounts(body))
	return body
}

var pageIdentity = auth.User{ID: "12345678-1234-4234-8234-123456789abc", Username: "personal-admin", Role: auth.Admin}

func userFixtures() []auth.UserRecord {
	return []auth.UserRecord{
		{ID: "12345678-1234-4234-8234-1234567890a1", Username: "a.b-c_d", Role: auth.Admin, CreatedAt: time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)},
		{ID: "12345678-1234-4234-8234-1234567890a2", Username: "blocked_member-9", Role: auth.Member, Disabled: true, CreatedAt: time.Date(2025, 12, 31, 23, 59, 30, 0, time.FixedZone("ahead", 2*60*60))},
	}
}

func TestAdminUsersPageRendering(t *testing.T) {
	model := AdminModel{
		User: pageIdentity, Users: userFixtures(),
		Connections: connectionFixtures(), Grants: grantFixtures(),
	}
	body := adminPage(t, model, PageUsers, "/admin/users", []string{"2", "3", "2"})
	assert.Contains(t, body, "overflow-x-auto")
	assert.Contains(t, body, "<table")
	for _, fragment := range []string{
		">Username<", ">Role<", ">Status<", ">Created<",
		"a.b-c_d", "blocked_member-9", ">Admin<", ">Member<",
		"Active", "Blocked", "2024-03-04 05:06 UTC", "2025-12-31 21:59 UTC",
		"bg-status-ok", "bg-status-bad", "text-status-bad",
		"personal-admin", "· Admin",
	} {
		assert.Contains(t, body, fragment)
	}
	// Role is plain capitalised text now, not a badge holding the raw value.
	assert.NotContains(t, body, ">admin<")
	assert.NotContains(t, body, ">member<")
	assert.NotContains(t, body, "1234567890a1", "user identifiers are not display data")
	assert.NotContains(t, body, "the list is limited")
	// Only the page's own list renders a table; the other two supply counts.
	assert.Equal(t, 1, strings.Count(body, "<table"))
	assert.NotContains(t, body, "warehouse-primary")
	assert.NotContains(t, body, ">alice<")

	empty := adminPage(t, AdminModel{User: pageIdentity}, PageUsers, "/admin/users", []string{"0", "0", "0"})
	assert.Contains(t, empty, "No user accounts are listed.")
	assert.NotContains(t, empty, "<table")
	assert.NotContains(t, empty, "the list is limited")

	truncated := adminPage(t, AdminModel{User: pageIdentity, Users: userFixtures(), Truncated: true},
		PageUsers, "/admin/users", []string{"2+", "0", "0"})
	assert.Contains(t, truncated, "Showing the first 1000 users; the list is limited.")
	assert.Equal(t, "Showing the first "+strconv.Itoa(auth.MaxUserListing)+" users; the list is limited.", truncationNotice())
	assert.Equal(t, "7", listCount(7, false))
	assert.Equal(t, "1000+", listCount(auth.MaxUserListing, true))
}

func TestAdminUsersPageEscapesUntrustedText(t *testing.T) {
	body := adminPage(t, AdminModel{
		User:  auth.User{Username: "x<y", Role: auth.Admin},
		Users: []auth.UserRecord{{Username: "x<y", Role: auth.Role(`"><script>alert(1)</script>`)}},
	}, PageUsers, "/admin/users", []string{"1", "0", "0"})
	assert.Contains(t, body, "x&lt;y")
	assert.NotContains(t, body, "x<y")
	assert.NotContains(t, body, "<script>alert")
	// An unknown role renders as its escaped value rather than a guessed label.
	assert.Contains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
	assert.Equal(t, "2026-09-11 07:08 UTC", createdLabel(time.Date(2026, 9, 11, 9, 8, 7, 0, time.FixedZone("ahead", 2*60*60))))
	kind, text := userStatus(false)
	assert.Equal(t, statusOK, kind)
	assert.Equal(t, "Active", text)
	kind, text = userStatus(true)
	assert.Equal(t, statusBad, kind)
	assert.Equal(t, "Blocked", text)
}

func TestAuthErrorDocuments(t *testing.T) {
	body := renderAuth(t, 503, AuthError(AuthErrorModel{ErrorCode: "SENTINEL_SECRET", RemoteRevocationUnconfirmed: true}))
	assert.Contains(t, body, "signed out locally")
	assert.Contains(t, body, "remote session revocation could not be confirmed")
	assert.NotContains(t, body, "SENTINEL_SECRET")
	assert.NotContains(t, body, "<form")
	assert.Contains(t, body, `href="/login"`)
	body = renderAuth(t, 403, AuthError(AuthErrorModel{ErrorCode: auth.Forbidden}))
	assert.Contains(t, body, "administrator access is required")
	assert.Contains(t, body, `href="/login"`)
	assert.Contains(t, body, `action="/logout"`)
	assert.Equal(t, "Wait a few minutes before trying again.", retryMessage(-1))
	assert.Equal(t, "Wait a few minutes before trying again.", retryMessage(1<<30))
	assert.Equal(t, "Try again in 30 seconds.", retryMessage(30))
}

// sentinelTarget holds everything a connection record carries that the page
// must never display: hosts, ports, roles, databases and URLs.
var sentinelTarget = map[string]string{
	"host":     "sentinel-host.invalid",
	"port":     "5432",
	"user":     "sentinel-role",
	"database": "sentinel-db",
	"url":      "postgres://sentinel-role@sentinel-host.invalid:5432/sentinel-db",
}

func connectionFixtures() []auth.Connection {
	return []auth.Connection{
		{
			ID: "12345678-1234-4234-8234-1234567890c1", Name: "warehouse-primary", Title: "Warehouse primary",
			Description: "sentinel-description", Scope: "sentinel-scope",
			Provider: auth.ProviderPostgreSQL, Target: sentinelTarget,
			Labels: map[string]string{"zone": "eu-west", "env": "prod"}, Enabled: true,
			LastCheck: &auth.CheckResult{
				Outcome:   auth.CheckReachable,
				CheckedAt: time.Date(2026, 4, 5, 8, 9, 10, 0, time.FixedZone("ahead", 2*60*60)),
			},
		},
		{
			ID: "12345678-1234-4234-8234-1234567890c2", Name: "metrics-eu", Title: "Metrics EU",
			Provider: auth.ProviderVictoriaMetrics, Target: sentinelTarget, Enabled: false,
			LastCheck: &auth.CheckResult{
				Outcome: auth.CheckAuthRejected, CheckedAt: time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC),
			},
		},
		{
			ID: "12345678-1234-4234-8234-1234567890c3", Name: "metrics-us", Title: "Metrics US",
			Provider: auth.ProviderVictoriaMetrics, Target: sentinelTarget,
			Labels: map[string]string{"env": "staging"}, Enabled: true,
		},
	}
}

// sentinelValues is every stored target value, so one assertion covers the whole
// map rather than a hand-copied subset of it.
func sentinelValues() []string {
	values := make([]string, 0, len(sentinelTarget))
	for _, value := range sentinelTarget {
		values = append(values, value)
	}
	return values
}

func TestAdminConnectionsPageRendering(t *testing.T) {
	model := AdminModel{
		User: pageIdentity, Users: userFixtures(),
		Connections: connectionFixtures(), Grants: grantFixtures(),
	}
	body := adminPage(t, model, PageConnections, "/admin/connections", []string{"2", "3", "2"})
	assert.Equal(t, 1, strings.Count(body, "overflow-x-auto"), "the table scrolls instead of widening the page")
	for _, fragment := range []string{
		">Name<", ">Title<", ">Provider<", ">Labels<", ">Status<", ">Last check<",
		"warehouse-primary", "Warehouse primary", "metrics-eu", "Metrics EU", "metrics-us", "Metrics US",
		">postgresql<", ">victoriametrics<", ">env=prod<", ">zone=eu-west<", ">env=staging<",
		"Enabled", "Disabled", "Reachable", "auth_rejected", "Not checked",
		"bg-status-ok", "bg-status-bad", "bg-status-off", "text-status-bad",
		"2026-04-05 06:09 UTC", "2026-05-06 07:08 UTC",
	} {
		assert.Contains(t, body, fragment)
	}
	assert.Less(t, strings.Index(body, ">env=prod<"), strings.Index(body, ">zone=eu-west<"), "labels render in a stable order")
	assert.Equal(t, []string{"env=prod", "zone=eu-west"}, labelPairs(map[string]string{"zone": "eu-west", "env": "prod"}))
	assert.Empty(t, labelPairs(nil))
	// Nothing a connection knows about its target, its credentials or its
	// identifiers may reach the page.
	for _, forbidden := range append(sentinelValues(), "postgres://", "secret", "sentinel-description", "sentinel-scope", "1234567890c1") {
		assert.NotContains(t, body, forbidden)
	}
	assert.NotContains(t, body, "the list is limited")
	assert.Equal(t, 1, strings.Count(body, "<table"))
	assert.NotContains(t, body, "blocked_member-9")
}

func TestAdminConnectionsPageEmptyTruncatedAndEscaped(t *testing.T) {
	empty := adminPage(t, AdminModel{User: pageIdentity}, PageConnections, "/admin/connections", []string{"0", "0", "0"})
	assert.Contains(t, empty, "No connections are registered.")
	assert.NotContains(t, empty, "<table")

	truncated := adminPage(t, AdminModel{User: pageIdentity, Connections: connectionFixtures(), ConnectionsTruncated: true},
		PageConnections, "/admin/connections", []string{"0", "3+", "0"})
	assert.Contains(t, truncated, "Showing the first 1000 connections; the list is limited.")
	assert.Equal(t, "Showing the first "+strconv.Itoa(auth.MaxConnectionListing)+" connections; the list is limited.", connectionsTruncationNotice())

	escaped := adminPage(t, AdminModel{User: pageIdentity, Connections: []auth.Connection{{
		Name: "hostile", Title: `<script>alert("title")</script>`, Provider: auth.ProviderPostgreSQL,
		Labels:    map[string]string{"env": `prod"><script>alert(1)</script>`},
		LastCheck: &auth.CheckResult{Outcome: auth.CheckOutcome("<unreachable>"), CheckedAt: time.Unix(0, 0)},
	}}}, PageConnections, "/admin/connections", []string{"0", "1", "0"})
	assert.NotContains(t, escaped, "<script>alert")
	assert.Contains(t, escaped, "&lt;script&gt;alert(&#34;title&#34;)&lt;/script&gt;")
	assert.Contains(t, escaped, "&lt;script&gt;alert(1)&lt;/script&gt;")
	assert.Contains(t, escaped, "&lt;unreachable&gt;")
	assert.Contains(t, escaped, "1970-01-01 00:00 UTC")

	kind, text := connectionStatus(true)
	assert.Equal(t, statusOK, kind)
	assert.Equal(t, "Enabled", text)
	kind, text = connectionStatus(false)
	assert.Equal(t, statusOff, kind)
	assert.Equal(t, "Disabled", text)
	kind, text = checkStatus(auth.CheckReachable)
	assert.Equal(t, statusOK, kind)
	assert.Equal(t, "Reachable", text)
	// Every other outcome is a problem named by the outcome itself.
	for _, outcome := range []auth.CheckOutcome{auth.CheckAuthRejected, auth.CheckUnreachable, auth.CheckCredentialsUnavailable} {
		kind, text = checkStatus(outcome)
		assert.Equal(t, statusBad, kind)
		assert.Equal(t, string(outcome), text)
	}
}

func grantFixtures() []auth.Grant {
	return []auth.Grant{
		{
			User:       auth.GrantParty{ID: "12345678-1234-4234-8234-1234567890a1", Name: "alice"},
			Connection: auth.GrantParty{ID: "12345678-1234-4234-8234-1234567890c1", Name: "warehouse-primary"},
			CreatedAt:  time.Date(2026, 6, 7, 10, 11, 12, 0, time.FixedZone("ahead", 2*60*60)),
			CreatedBy:  auth.GrantParty{ID: "12345678-1234-4234-8234-123456789abc", Name: "personal-admin"},
		},
		{
			User:       auth.GrantParty{ID: "12345678-1234-4234-8234-1234567890a2", Name: "bob"},
			Connection: auth.GrantParty{ID: "12345678-1234-4234-8234-1234567890c2", Name: "metrics-eu"},
			CreatedAt:  time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC),
			CreatedBy:  auth.GrantParty{ID: "12345678-1234-4234-8234-123456789abc", Name: "personal-admin"},
		},
	}
}

func TestAdminGrantsPageRendering(t *testing.T) {
	model := AdminModel{
		User: pageIdentity, Users: userFixtures(),
		Connections: connectionFixtures(), Grants: grantFixtures(),
	}
	body := adminPage(t, model, PageGrants, "/admin/grants", []string{"2", "3", "2"})
	assert.Equal(t, 1, strings.Count(body, "overflow-x-auto"), "the table scrolls instead of widening the page")
	for _, fragment := range []string{
		">User<", ">Connection<", ">Granted<", ">Granted by<",
		">alice<", ">bob<", ">warehouse-primary<", ">metrics-eu<", ">personal-admin<",
		"2026-06-07 08:11 UTC", "2026-07-08 09:10 UTC",
	} {
		assert.Contains(t, body, fragment)
	}
	assert.Less(t, strings.Index(body, ">alice<"), strings.Index(body, ">bob<"), "grants render in listing order")
	// Identifiers are not display data.
	for _, forbidden := range []string{"1234567890a1", "1234567890a2", "1234567890c1", "1234567890c2", "the list is limited"} {
		assert.NotContains(t, body, forbidden)
	}
	assert.Equal(t, 1, strings.Count(body, "<table"))
	assert.NotContains(t, body, "Warehouse primary", "the grants page lists names, not connection titles")

	empty := adminPage(t, AdminModel{User: pageIdentity}, PageGrants, "/admin/grants", []string{"0", "0", "0"})
	assert.Contains(t, empty, "No grants are recorded.")
	assert.NotContains(t, empty, "<table")

	truncated := adminPage(t, AdminModel{User: pageIdentity, Grants: grantFixtures(), GrantsTruncated: true},
		PageGrants, "/admin/grants", []string{"0", "0", "2+"})
	assert.Contains(t, truncated, "Showing the first 1000 grants; the list is limited.")
	assert.Equal(t, "Showing the first "+strconv.Itoa(auth.MaxGrantListing)+" grants; the list is limited.", grantsTruncationNotice())

	escaped := adminPage(t, AdminModel{User: pageIdentity, Grants: []auth.Grant{{
		User:       auth.GrantParty{Name: `<script>alert("user")</script>`},
		Connection: auth.GrantParty{Name: `<img src=x onerror=alert(1)>`},
		CreatedBy:  auth.GrantParty{Name: `<b>admin</b>`},
		CreatedAt:  time.Unix(0, 0),
	}}}, PageGrants, "/admin/grants", []string{"0", "0", "1"})
	assert.NotContains(t, escaped, "<script>alert")
	assert.NotContains(t, escaped, "<img src")
	assert.NotContains(t, escaped, "<b>admin</b>")
	assert.Contains(t, escaped, "&lt;script&gt;alert(&#34;user&#34;)&lt;/script&gt;")
	assert.Contains(t, escaped, "1970-01-01 00:00 UTC")
}
