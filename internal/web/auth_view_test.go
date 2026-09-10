package web

import (
	"net/http/httptest"
	"strings"
	"testing"

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
