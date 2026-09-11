package web

import (
	"net/http/httptest"
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
	assert.Contains(t, body, "/assets/notices.txt")
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
	body := renderAuth(t, 200, Admin(AdminModel{User: auth.User{
		ID: "not-for-display", Username: `<script>alert("identity")</script>`, Role: auth.Admin,
	}}))
	assert.NotContains(t, body, "<script>alert")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.NotContains(t, body, "not-for-display")
	assert.Contains(t, body, `action="/logout" method="post"`)
	assert.NotContains(t, body, "href=\"/admin/users")
}

func adminBody(t *testing.T, model AdminModel) string {
	t.Helper()
	body := renderAuth(t, 200, Admin(model))
	assert.Equal(t, 1, strings.Count(body, "<form"), "only the sign-out form belongs on this page")
	assert.Contains(t, body, `action="/logout" method="post"`)
	assert.NotContains(t, body, "hx-")
	assert.Equal(t, 1, strings.Count(body, "<script"), "only the shared appearance script belongs on this page")
	assert.Contains(t, body, `<script src="/assets/appearance.js">`)
	assert.Contains(t, body, "Manage users through the CLI")
	assert.NotContains(t, body, "User and connection management are not available")
	return body
}

func TestAdminUserListRendering(t *testing.T) {
	identity := auth.User{ID: "12345678-1234-4234-8234-123456789abc", Username: "personal-admin", Role: auth.Admin}
	users := []auth.UserRecord{
		{ID: "12345678-1234-4234-8234-1234567890a1", Username: "a.b-c_d", Role: auth.Admin, CreatedAt: time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)},
		{ID: "12345678-1234-4234-8234-1234567890a2", Username: "blocked_member-9", Role: auth.Member, Disabled: true, CreatedAt: time.Date(2025, 12, 31, 23, 59, 30, 0, time.FixedZone("ahead", 2*60*60))},
	}
	body := adminBody(t, AdminModel{User: identity, Users: users})
	assert.Contains(t, body, ">Users<")
	assert.Contains(t, body, "overflow-x-auto")
	assert.Contains(t, body, "<table")
	for _, fragment := range []string{
		"a.b-c_d", "blocked_member-9", ">admin<", ">member<",
		">Enabled<", ">Blocked<", "2024-03-04 05:06 UTC", "2025-12-31 21:59 UTC",
	} {
		assert.Contains(t, body, fragment)
	}
	assert.NotContains(t, body, "1234567890a1", "user identifiers are not display data")
	assert.NotContains(t, body, "the list is limited")
	assert.NotContains(t, body, `href="/admin/users`)

	empty := adminBody(t, AdminModel{User: identity})
	assert.Contains(t, empty, "No user accounts are listed.")
	assert.NotContains(t, empty, "<table")
	assert.NotContains(t, empty, "the list is limited")

	truncated := adminBody(t, AdminModel{User: identity, Users: users, Truncated: true})
	assert.Contains(t, truncated, "Showing the first 1000 users; the list is limited.")
	assert.Equal(t, "Showing the first "+strconv.Itoa(auth.MaxUserListing)+" users; the list is limited.", truncationNotice())
}

func TestAdminUserListEscapesUntrustedText(t *testing.T) {
	body := adminBody(t, AdminModel{
		User:  auth.User{Username: "x<y", Role: auth.Admin},
		Users: []auth.UserRecord{{Username: "x<y", Role: auth.Role(`"><script>alert(1)</script>`)}},
	})
	assert.Contains(t, body, "x&lt;y")
	assert.NotContains(t, body, "x<y")
	assert.NotContains(t, body, "<script>alert")
	assert.Contains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
	assert.Equal(t, "2026-09-11 07:08 UTC", createdLabel(time.Date(2026, 9, 11, 9, 8, 7, 0, time.FixedZone("ahead", 2*60*60))))
	assert.Equal(t, "Blocked", statusLabel(true))
	assert.Equal(t, "Enabled", statusLabel(false))
}

func TestAuthErrorDocuments(t *testing.T) {
	body := renderAuth(t, 503, AuthError(AuthErrorModel{ErrorCode: "SENTINEL_SECRET", RemoteRevocationUnconfirmed: true}))
	assert.Contains(t, body, "signed out locally")
	assert.Contains(t, body, "remote session revocation could not be confirmed")
	assert.NotContains(t, body, "SENTINEL_SECRET")
	assert.NotContains(t, body, "<form")
	body = renderAuth(t, 403, AuthError(AuthErrorModel{ErrorCode: auth.Forbidden}))
	assert.Contains(t, body, "administrator access is required")
	assert.Contains(t, body, `action="/logout"`)
	assert.Equal(t, "Wait a few minutes before trying again.", retryMessage(-1))
	assert.Equal(t, "Wait a few minutes before trying again.", retryMessage(1<<30))
	assert.Equal(t, "Try again in 30 seconds.", retryMessage(30))
}

func TestInitializationFragments(t *testing.T) {
	for state, title := range map[platform.State]string{
		platform.Initializing:    "Initialization in progress",
		platform.SetupRequired:   "Administrator setup required",
		platform.BootstrapFailed: "Administrator setup failed",
		platform.SchemaError:     "Platform schema requires attention",
	} {
		t.Run(string(state), func(t *testing.T) {
			response := httptest.NewRecorder()
			require.NoError(t, Render(response, httptest.NewRequest("GET", "/ui/readiness", nil), 503, Readiness(platform.Readiness{State: state})))
			body := response.Body.String()
			assert.Contains(t, body, `data-readiness-state="`+string(state)+`"`)
			assert.Contains(t, body, title)
			assert.NotContains(t, body, "<form")
			assert.NotContains(t, body, "Database unavailable")
			assert.NotContains(t, body, "CLAVIS_BOOTSTRAP")
		})
	}
	response := httptest.NewRecorder()
	require.NoError(t, Render(response, httptest.NewRequest("GET", "/", nil), 503, Readiness(platform.Readiness{State: "SENTINEL_SECRET"})))
	assert.NotContains(t, response.Body.String(), "SENTINEL_SECRET")
	assert.Contains(t, response.Body.String(), "Database unavailable")
}
