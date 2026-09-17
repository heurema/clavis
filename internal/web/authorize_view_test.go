package web

import (
	"crypto/sha256"
	"encoding/base64"
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

func TestLoginRendersOnlyAValidReturnTarget(t *testing.T) {
	link := viewLink()
	reordered := "/authorize?state=" + link.State + "&port=51234&challenge=" + link.Challenge
	body := renderAuth(t, 200, Login(LoginModel{Next: reordered}))
	want := strings.ReplaceAll(link.Link(), "&", "&amp;")
	assert.Contains(t, body, `<input type="hidden" name="next" value="`+want+`">`, "the target is rebuilt, not echoed")
	assert.NotContains(t, body, "state="+link.State+"&amp;port")
	for _, next := range []string{
		"//evil.example" + link.Link(), "/admin/users", link.Link() + "&extra=1", `/authorize"><script>`,
	} {
		body := renderAuth(t, 200, Login(LoginModel{Next: next}))
		require.NotContains(t, body, `name="next"`, next)
		require.NotContains(t, body, "evil.example")
	}
}
