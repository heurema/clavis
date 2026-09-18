package web

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func viewLink() auth.CLIAuthorization {
	digest := sha256.Sum256([]byte("verifier"))
	return auth.CLIAuthorization{Port: 51234, Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), State: strings.Repeat("s", 42) + "A"}
}

func TestAuthorizeDocumentNamesUserAndPortWithOneApprove(t *testing.T) {
	link := viewLink()
	body := renderAuth(t, 200, Authorize(AuthorizeModel{Username: `<script>alert("user")</script>`, Link: link}))
	assert.Contains(t, body, `>Approve CLI sign-in</h1>`)
	assert.NotContains(t, body, "<script>alert")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.Contains(t, body, ">51234</span>")
	assert.Equal(t, 1, strings.Count(body, "<form"), "one form and no Deny action")
	assert.Contains(t, body, `<form action="/authorize" method="post"`)
	assert.Contains(t, body, `<input type="hidden" name="port" value="51234">`)
	assert.Contains(t, body, `<input type="hidden" name="challenge" value="`+link.Challenge+`">`)
	assert.Contains(t, body, `<input type="hidden" name="state" value="`+link.State+`">`)
	assert.Equal(t, 1, strings.Count(body, `type="submit"`))
	assert.Contains(t, body, "Approve")
	assert.NotContains(t, body, "Deny")
	assert.NotContains(t, body, "callback")
}

func TestAuthorizeInvalidDocumentEchoesNothing(t *testing.T) {
	body := renderAuth(t, 400, AuthorizeInvalid())
	assert.Contains(t, body, `id="auth-error"`)
	assert.Contains(t, body, "Run clavis login again")
	assert.NotContains(t, body, "<form")
}

// The return target travels in the form's action, so every refusal renders it.
// The document still keeps only a rebuilt link, and only on its own route.
func TestLoginFormActionCarriesOnlyAValidReturnTarget(t *testing.T) {
	link := viewLink()
	reordered := "/login?next=" + url.QueryEscape("/authorize?state="+link.State+"&port=51234&challenge="+link.Challenge)
	body := renderAuth(t, 200, Login(LoginModel{Action: reordered}))
	want := "/login?next=" + url.QueryEscape(link.Link())
	assert.Contains(t, body, `<form action="`+want+`" method="post"`, "the target is rebuilt, not echoed")
	assert.NotContains(t, body, url.QueryEscape("state="+link.State+"&port"))
	assert.NotContains(t, body, `type="hidden"`, "the target is no longer a form field")
	for _, action := range []string{
		"", "/login", "/login?next=" + url.QueryEscape("//evil.example"+link.Link()),
		"/login?next=" + url.QueryEscape("/admin/users"),
		"/login?next=" + url.QueryEscape(link.Link()+"&extra=1"),
		"/login?next=" + url.QueryEscape(link.Link()) + "&next=" + url.QueryEscape(link.Link()),
		"/login?next=" + url.QueryEscape(`/authorize"><script>`),
		"//evil.example/login?next=" + url.QueryEscape(link.Link()),
		"https://evil.example/login?next=" + url.QueryEscape(link.Link()),
		"/admin/users?next=" + url.QueryEscape(link.Link()),
		`javascript:alert(1)`,
	} {
		body := renderAuth(t, 200, Login(LoginModel{Action: action}))
		require.Contains(t, body, `<form action="/login" method="post"`, action)
		require.NotContains(t, body, "evil.example")
		require.NotContains(t, body, "javascript:")
	}
}
