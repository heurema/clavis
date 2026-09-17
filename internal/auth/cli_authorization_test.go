package auth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

var (
	linkVerifier  = auth.Secret(strings.Repeat("v", 43))
	linkChallenge = func() string {
		digest := sha256.Sum256([]byte(linkVerifier))
		return base64.RawURLEncoding.EncodeToString(digest[:])
	}()
	linkState = strings.Repeat("s", 42) + "A"
)

func linkValues(port, challenge, state string) url.Values {
	return url.Values{"port": {port}, "challenge": {challenge}, "state": {state}}
}

func TestParseCLIAuthorization(t *testing.T) {
	link, ok := auth.ParseCLIAuthorization(linkValues("49152", linkChallenge, linkState))
	require.True(t, ok)
	require.Equal(t, auth.CLIAuthorization{Port: 49152, Challenge: linkChallenge, State: linkState}, link)
	for _, port := range []string{"1024", "65535"} {
		_, ok := auth.ParseCLIAuthorization(linkValues(port, linkChallenge, linkState))
		require.True(t, ok, port)
	}
	for name, values := range map[string]url.Values{
		"port below range":       linkValues("1023", linkChallenge, linkState),
		"port above range":       linkValues("65536", linkChallenge, linkState),
		"port zero":              linkValues("0", linkChallenge, linkState),
		"negative port":          linkValues("-2000", linkChallenge, linkState),
		"signed port":            linkValues("+2000", linkChallenge, linkState),
		"leading zero":           linkValues("02000", linkChallenge, linkState),
		"fractional port":        linkValues("2000.0", linkChallenge, linkState),
		"word port":              linkValues("http", linkChallenge, linkState),
		"empty port":             linkValues("", linkChallenge, linkState),
		"short challenge":        linkValues("2000", linkChallenge[:42], linkState),
		"long challenge":         linkValues("2000", linkChallenge+"A", linkState),
		"padded challenge":       linkValues("2000", linkChallenge[:42]+"=", linkState),
		"standard alphabet":      linkValues("2000", strings.Repeat("+", 43), linkState),
		"non-canonical trailing": linkValues("2000", strings.Repeat("s", 42)+"t", linkState),
		"short state":            linkValues("2000", linkChallenge, linkState[:42]),
		"state with newline":     linkValues("2000", linkChallenge, linkState[:42]+"\n"),
		"missing state":          {"port": {"2000"}, "challenge": {linkChallenge}},
		"duplicate state":        {"port": {"2000"}, "challenge": {linkChallenge}, "state": {linkState, linkState}},
		"extra parameter":        {"port": {"2000"}, "challenge": {linkChallenge}, "state": {linkState}, "next": {"/"}},
	} {
		_, ok := auth.ParseCLIAuthorization(values)
		require.False(t, ok, name)
	}
}

func TestParseAuthorizeLinkAcceptsOnlyTheLiteralShape(t *testing.T) {
	valid := auth.CLIAuthorization{Port: 49152, Challenge: linkChallenge, State: linkState}
	query := valid.Link()[len("/authorize"):]
	for _, raw := range []string{
		valid.Link(),
		"/authorize?state=" + linkState + "&port=49152&challenge=" + linkChallenge,
	} {
		link, ok := auth.ParseAuthorizeLink(raw)
		require.True(t, ok, raw)
		require.Equal(t, valid, link)
		require.Equal(t, valid.Link(), link.Link(), "the link is rebuilt in one canonical form")
	}
	for _, raw := range []string{
		"//evil.example/authorize" + query,
		"https://evil.example/authorize" + query,
		"http:/authorize" + query,
		"/\\evil.example/authorize" + query,
		"/authorize/../admin" + query,
		"/authorize/" + query,
		"/Authorize" + query,
		"/%61uthorize" + query,
		"/authorize%0A" + query,
		"/authorize" + query + "%0A",
		"/authorize" + query + "#fragment",
		"/authorize" + query + "#",
		"/authorize" + query + "&extra=1",
		"/authorize" + query + ";x=1",
		"authorize" + query,
		"/admin/users",
		"",
		"/authorize?port=80&challenge=" + linkChallenge + "&state=" + linkState,
	} {
		_, ok := auth.ParseAuthorizeLink(raw)
		require.False(t, ok, raw)
	}
}

func TestCallbackURLIsBuiltFromParsedValues(t *testing.T) {
	link := auth.CLIAuthorization{Port: 1024, Challenge: linkChallenge, State: linkState}
	code := auth.Secret(strings.Repeat("c", 42) + "A")
	callback := link.CallbackURL(code)
	require.Equal(t, "http://127.0.0.1:1024/callback?code="+string(code)+"&state="+linkState, callback)
	parsed, err := url.Parse(callback)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:1024", parsed.Host)
	require.Equal(t, url.Values{"code": {string(code)}, "state": {linkState}}, parsed.Query())
	require.NotContains(t, callback, linkChallenge)
}

func TestVerifierMatchesComparesTheDigest(t *testing.T) {
	challenge, err := base64.RawURLEncoding.DecodeString(linkChallenge)
	require.NoError(t, err)
	require.True(t, auth.VerifierMatches(linkVerifier, challenge))
	require.False(t, auth.VerifierMatches(linkVerifier+"x", challenge))
	require.False(t, auth.VerifierMatches(auth.Secret(linkChallenge), challenge))
	require.False(t, auth.VerifierMatches(linkVerifier, challenge[:31]))
	require.False(t, auth.VerifierMatches(linkVerifier, nil))
}
