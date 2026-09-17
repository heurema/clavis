package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/web"
	"github.com/stretchr/testify/require"
)

// fakeCLIAuthorization records approvals and redemptions for the fixture
// service; it never stores anything.
type fakeCLIAuthorization struct {
	approveErr, exchangeErr     error
	approveCalls, exchangeCalls int
	lastLink                    auth.CLIAuthorization
	lastExchange                auth.TokenRequest
}

var fixtureCode = auth.Secret(strings.Repeat("C", 42) + "A")

func (f *fakeCLIAuthorization) ApproveCLI(_ context.Context, _ auth.Session, link auth.CLIAuthorization) (auth.Secret, error) {
	f.approveCalls++
	f.lastLink = link
	return fixtureCode, f.approveErr
}

func (f *fakeCLIAuthorization) ExchangeCLICode(_ context.Context, input auth.TokenRequest) (auth.LoginResponse, error) {
	f.exchangeCalls++
	f.lastExchange = input
	return auth.LoginResponse{Token: fixtureToken, Identity: fixtureIdentity}, f.exchangeErr
}

var fixtureVerifier = auth.Secret(strings.Repeat("V", 42) + "A")

func fixtureLink() auth.CLIAuthorization {
	digest := sha256.Sum256([]byte(fixtureVerifier))
	return auth.CLIAuthorization{Port: 51234, Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), State: strings.Repeat("S", 42) + "A"}
}

// linkForm is the body of an Approve post for the three raw parameters.
func linkForm(port, challenge, state string) string {
	return url.Values{"port": {port}, "challenge": {challenge}, "state": {state}}.Encode()
}

func browserHeaders() http.Header {
	return http.Header{
		"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"},
		"Cookie": {developmentCookie + "=" + string(fixtureToken)},
	}
}

// fixtureModel decodes the JSON the fixture views render into a model.
func fixtureModel(t *testing.T, body string, into any) {
	t.Helper()
	body = strings.TrimPrefix(body, "<!doctype html><html><body>")
	body = strings.TrimSuffix(body, "</body></html>")
	require.NoError(t, json.Unmarshal([]byte(body), into))
}

// requireDocumentHeaders asserts the headers every response on the authorize
// routes carries. The policy is pinned as a literal: "strict-origin" on every
// document, because "no-referrer" makes Safari and Firefox send `Origin: null`
// on a form POST from it, which the origin check refuses with 403 and which
// broke browser sign-in outright; "no-referrer" only on the Approve redirect,
// which governs the loopback GET that follows it and renders no form.
func requireDocumentHeaders(t *testing.T, response *httptest.ResponseRecorder, policy string) {
	t.Helper()
	require.Equal(t, "frame-ancestors 'none'", response.Header().Get("Content-Security-Policy"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Equal(t, policy, response.Header().Get("Referrer-Policy"))
}

// wantAction is the sign-in form action a document carries back for a link.
func wantAction(next string) string {
	if next == "" {
		return "/login"
	}
	return "/login?next=" + url.QueryEscape(next)
}

// Scenario: invalid link parameters, on the link and on Approve.
func TestInvalidAuthorizationLinkRendersSafeDocument(t *testing.T) {
	link := fixtureLink()
	for name, query := range map[string]string{
		"port below range":  linkForm("1023", link.Challenge, link.State),
		"port above range":  linkForm("65536", link.Challenge, link.State),
		"non-integer port":  linkForm("51234.5", link.Challenge, link.State),
		"word port":         linkForm("SENTINEL", link.Challenge, link.State),
		"short challenge":   linkForm("51234", link.Challenge[:42], link.State),
		"challenge symbols": linkForm("51234", strings.Repeat("*", 43), link.State),
		"long state":        linkForm("51234", link.Challenge, link.State+"A"),
		"missing state":     url.Values{"port": {"51234"}, "challenge": {link.Challenge}}.Encode(),
		"extra parameter":   linkForm("51234", link.Challenge, link.State) + "&SENTINEL=1",
		"malformed query":   linkForm("51234", link.Challenge, link.State) + "&%zz",
	} {
		t.Run(name, func(t *testing.T) {
			f := &backendFixture{}
			handler := authHandler(t, f, nil, "http://127.0.0.1")
			response := requestAuth(handler, "GET", "/authorize?"+query, "", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}})
			require.Equal(t, 400, response.Code)
			require.Contains(t, response.Body.String(), "AUTHORIZE_INVALID")
			require.NotContains(t, response.Body.String(), "SENTINEL")
			requireDocumentHeaders(t, response, "strict-origin")
			response = requestAuth(handler, "POST", "/authorize", query, browserHeaders())
			require.Equal(t, 400, response.Code)
			require.Contains(t, response.Body.String(), "AUTHORIZE_INVALID")
			require.Empty(t, response.Header().Get("Location"))
			require.Zero(t, f.authCalls+f.approveCalls)
		})
	}
}

// The link renders the approval document for any role's browser session and
// the sign-in document carrying the link without one.
func TestAuthorizePageRendersForSessionOrSignIn(t *testing.T) {
	link := fixtureLink()
	path := "/authorize?" + linkForm("51234", link.Challenge, link.State)
	for _, role := range []auth.Role{auth.Admin, auth.Member} {
		f := &backendFixture{role: role}
		handler := authHandler(t, f, nil, "http://127.0.0.1")
		response := requestAuth(handler, "GET", path, "", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}})
		require.Equal(t, 200, response.Code)
		requireDocumentHeaders(t, response, "strict-origin")
		var model web.AuthorizeModel
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, web.AuthorizeModel{Username: fixtureIdentity.User.Username, Link: link}, model)
		require.Equal(t, 1, f.authCalls)
		require.Zero(t, f.approveCalls)
		require.Empty(t, response.Header().Get("Set-Cookie"))
	}
	for name, tc := range map[string]struct {
		cookie string
		err    error
	}{
		"no cookie":          {"", nil},
		"malformed cookie":   {developmentCookie + "=malformed", nil},
		"expired session":    {developmentCookie + "=" + string(fixtureToken), &auth.Error{Code: auth.Unauthenticated}},
		"secure cookie only": {browserCookie + "=" + string(fixtureToken), nil},
	} {
		f := &backendFixture{errorAuth: tc.err}
		handler := authHandler(t, f, nil, "http://127.0.0.1")
		response := requestAuth(handler, "GET", path, "", http.Header{"Cookie": {tc.cookie}})
		require.Equal(t, 200, response.Code, name)
		requireDocumentHeaders(t, response, "strict-origin")
		var model web.LoginModel
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, web.LoginModel{Action: wantAction(link.Link())}, model, name)
	}
	for name, tc := range map[string]struct {
		headers http.Header
		err     error
		status  int
	}{
		"duplicate cookies":    {http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken) + "; " + developmentCookie + "=" + string(fixtureToken)}}, nil, 400},
		"authorization header": {http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}, nil, 400},
		"storage unavailable":  {http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, errors.New("SENTINEL_DRIVER"), 503},
	} {
		f := &backendFixture{errorAuth: tc.err}
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "GET", path, "", tc.headers)
		require.Equal(t, tc.status, response.Code, name)
		require.NotContains(t, response.Body.String(), "SENTINEL", name)
		require.NotContains(t, response.Body.String(), link.State, name)
		requireDocumentHeaders(t, response, "strict-origin")
	}
}

// Scenario: a member approves; the redirect carries only the parsed port, the
// fresh code and the validated state.
func TestApproveRedirectsToTheLoopbackCallback(t *testing.T) {
	link := fixtureLink()
	for _, port := range []int{auth.MinCallbackPort, 51234, auth.MaxCallbackPort} {
		f := &backendFixture{role: auth.Member}
		handler := authHandler(t, f, nil, "http://127.0.0.1")
		// Parameters in another order still produce the canonical redirect.
		body := "state=" + link.State + "&challenge=" + link.Challenge + "&port=" + strconv.Itoa(port)
		response := requestAuth(handler, "POST", "/authorize", body, browserHeaders())
		require.Equal(t, 303, response.Code)
		requireDocumentHeaders(t, response, "no-referrer")
		require.Equal(t, 1, f.approveCalls)
		require.Equal(t, auth.CLIAuthorization{Port: port, Challenge: link.Challenge, State: link.State}, f.lastLink)
		location, err := url.Parse(response.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "http", location.Scheme)
		require.Equal(t, "127.0.0.1:"+strconv.Itoa(port), location.Host)
		require.Equal(t, "/callback", location.Path)
		require.Empty(t, location.Fragment)
		require.Equal(t, url.Values{"code": {string(fixtureCode)}, "state": {link.State}}, location.Query())
		require.Equal(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/callback?code="+string(fixtureCode)+"&state="+link.State, response.Header().Get("Location"))
		require.Empty(t, response.Header().Get("Set-Cookie"))
		require.Empty(t, response.Body.String())
	}
}

// Scenario: cross-site approval. Every browser mutation rule applies before a
// session is read or an approval stored.
func TestCrossSiteApprovalStoresNothing(t *testing.T) {
	link := fixtureLink()
	body := linkForm("51234", link.Challenge, link.State)
	for name, mutate := range map[string]func(http.Header){
		"absent origin":        func(h http.Header) { h.Del("Origin") },
		"null origin":          func(h http.Header) { h.Set("Origin", "null") },
		"foreign origin":       func(h http.Header) { h.Set("Origin", "https://attacker.invalid") },
		"multiple origins":     func(h http.Header) { h.Add("Origin", "http://127.0.0.1") },
		"cross-site fetch":     func(h http.Header) { h.Set("Sec-Fetch-Site", "cross-site") },
		"same-site fetch":      func(h http.Header) { h.Set("Sec-Fetch-Site", "same-site") },
		"json content":         func(h http.Header) { h.Set("Content-Type", "application/json") },
		"multipart content":    func(h http.Header) { h.Set("Content-Type", "multipart/form-data; boundary=x") },
		"authorization header": func(h http.Header) { h.Set("Authorization", "Bearer "+string(fixtureToken)) },
		"duplicate cookies":    func(h http.Header) { h.Add("Cookie", developmentCookie+"="+string(fixtureToken)) },
	} {
		f := &backendFixture{}
		headers := browserHeaders()
		mutate(headers)
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/authorize", body, headers)
		require.Contains(t, []int{400, 403}, response.Code, name)
		require.Empty(t, response.Header().Get("Location"), name)
		require.Zero(t, f.authCalls+f.approveCalls, name)
		requireDocumentHeaders(t, response, "strict-origin")
	}
}

// Approve without a valid session issues nothing and returns to sign-in with
// the link as the return target.
func TestApproveWithoutSessionRedirectsToSignIn(t *testing.T) {
	link := fixtureLink()
	body := linkForm("51234", link.Challenge, link.State)
	want := wantAction(link.Link())
	for name, tc := range map[string]struct {
		cookie               string
		authErr, approveErr  error
		authCalls, approvals int
	}{
		"no cookie":           {"", nil, nil, 0, 0},
		"expired session":     {developmentCookie + "=" + string(fixtureToken), &auth.Error{Code: auth.Unauthenticated}, nil, 1, 0},
		"revoked at approval": {developmentCookie + "=" + string(fixtureToken), nil, &auth.Error{Code: auth.Unauthenticated}, 1, 1},
	} {
		f := &backendFixture{errorAuth: tc.authErr}
		f.approveErr = tc.approveErr
		headers := browserHeaders()
		headers.Set("Cookie", tc.cookie)
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/authorize", body, headers)
		require.Equal(t, 303, response.Code, name)
		require.Equal(t, want, response.Header().Get("Location"), name)
		require.Equal(t, tc.authCalls, f.authCalls, name)
		require.Equal(t, tc.approvals, f.approveCalls, name)
		requireDocumentHeaders(t, response, "no-referrer")
	}
	f := &backendFixture{}
	f.approveErr = errors.New("SENTINEL_DRIVER")
	response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", "/authorize", body, browserHeaders())
	require.Equal(t, 503, response.Code)
	require.Empty(t, response.Header().Get("Location"))
	require.NotContains(t, response.Body.String(), "SENTINEL")
	requireDocumentHeaders(t, response, "strict-origin")
}

// credentialForm is the whole body the sign-in form submits: the return target
// travels in the action URL, so nothing else belongs in it.
var credentialForm = url.Values{"username": {"personal-admin"}, "password": {"SENTINEL_PRIVATE_PASSWORD"}}.Encode()

func signInHeaders() http.Header {
	return http.Header{"Origin": {"http://127.0.0.1"}, "Content-Type": {"application/x-www-form-urlencoded"}}
}

// Scenarios: sign-in returns to a CLI authorization, and sign-in ignores any
// other return target. The target is read from the action the form posted to.
func TestLoginReturnTarget(t *testing.T) {
	link := fixtureLink()
	query := strings.TrimPrefix(link.Link(), "/authorize")
	signIn := func(next []string) *httptest.ResponseRecorder {
		f := &backendFixture{}
		target := "/login"
		if next != nil {
			target += "?" + url.Values{"next": next}.Encode()
		}
		return requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", target, credentialForm, signInHeaders())
	}
	for _, next := range []string{
		link.Link(),
		"/authorize?state=" + link.State + "&port=51234&challenge=" + link.Challenge,
	} {
		response := signIn([]string{next})
		require.Equal(t, 303, response.Code)
		require.Equal(t, link.Link(), response.Header().Get("Location"), "the target is rebuilt from parsed values")
		require.Len(t, response.Result().Cookies(), 1)
	}
	for name, next := range map[string][]string{
		"none":                 nil,
		"protocol relative":    {"//evil.example/authorize" + query},
		"absolute":             {"https://evil.example/authorize" + query},
		"dot segments":         {"/authorize/../admin" + query},
		"encoded newline path": {"/authorize%0A" + query},
		"newline in state":     {"/authorize?port=51234&challenge=" + link.Challenge + "&state=" + link.State[:42] + "%0A"},
		"raw newline":          {link.Link() + "\r\nSet-Cookie: SENTINEL=1"},
		"extra parameter":      {link.Link() + "&extra=1"},
		"invalid port":         {"/authorize?port=80&challenge=" + link.Challenge + "&state=" + link.State},
		"another path":         {"/admin/groups"},
		"empty":                {""},
		"two targets":          {link.Link(), link.Link()},
	} {
		response := signIn(next)
		require.Equal(t, 303, response.Code, name)
		require.Equal(t, "/admin/users", response.Header().Get("Location"), name)
	}
	// A failed sign-in keeps a valid return target for the retry, and only then.
	f := &backendFixture{loginErr: &auth.Error{Code: auth.InvalidCredentials}}
	handler := authHandler(t, f, nil, "http://127.0.0.1")
	for next, want := range map[string]string{link.Link(): link.Link(), "//evil.example/authorize" + query: ""} {
		target := "/login?" + url.Values{"next": {next}}.Encode()
		response := requestAuth(handler, "POST", target, credentialForm, signInHeaders())
		require.Equal(t, 401, response.Code)
		var model web.LoginModel
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, wantAction(want), model.Action)
		require.NotContains(t, response.Body.String(), "evil.example")
	}
	// The body carries exactly the two credential fields: a return target in it
	// is an unknown field now that the action carries it, and so is any other.
	for name, extra := range map[string]url.Values{"next": {"next": {link.Link()}}, "other": {"other": {"x"}}} {
		values := url.Values{"username": {"personal-admin"}, "password": {"SENTINEL_PRIVATE_PASSWORD"}}
		for key, value := range extra {
			values[key] = value
		}
		before := f.loginCalls
		target := "/login?" + url.Values{"next": {link.Link()}}.Encode()
		response := requestAuth(handler, "POST", target, values.Encode(), signInHeaders())
		require.Equal(t, 400, response.Code, name)
		require.Equal(t, before, f.loginCalls, name)
		var model web.LoginModel
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, wantAction(link.Link()), model.Action, name)
	}
}

// Scenario: a refused sign-in keeps the return target. Every refusal renders
// the sign-in document, and the action it renders carries the link back,
// including the refusals raised before the body is read and the timeout
// fallback, which cannot read the body at all.
func TestRefusedSignInKeepsTheReturnTarget(t *testing.T) {
	link := fixtureLink()
	target := "/login?" + url.Values{"next": {link.Link()}}.Encode()
	withHeader := func(key, value string) http.Header {
		headers := signInHeaders()
		headers.Set(key, value)
		return headers
	}
	for name, tc := range map[string]struct {
		body    string
		headers http.Header
		err     error
		status  int
		calls   int
	}{
		"foreign origin":       {credentialForm, withHeader("Origin", "https://attacker.invalid"), nil, 403, 0},
		"null origin":          {credentialForm, withHeader("Origin", "null"), nil, 403, 0},
		"absent origin":        {credentialForm, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, nil, 403, 0},
		"cross-site":           {credentialForm, withHeader("Sec-Fetch-Site", "cross-site"), nil, 403, 0},
		"authorization header": {credentialForm, withHeader("Authorization", "Bearer "+string(fixtureToken)), nil, 400, 0},
		"wrong media type":     {credentialForm, withHeader("Content-Type", "application/json"), nil, 400, 0},
		"duplicate sessions":   {credentialForm, withHeader("Cookie", developmentCookie+"="+string(fixtureToken)+"; "+developmentCookie+"="+string(fixtureToken)), nil, 400, 0},
		"invalid input":        {"username=A&password=x", signInHeaders(), nil, 400, 0},
		"oversized body":       {credentialForm + "&password=" + strings.Repeat("x", auth.MaxCredentialBody), signInHeaders(), nil, 400, 0},
		"wrong credentials":    {credentialForm, signInHeaders(), &auth.Error{Code: auth.InvalidCredentials}, 401, 1},
		"throttled":            {credentialForm, signInHeaders(), &auth.Error{Code: auth.RateLimited, RetryAfter: 3 * time.Second}, 429, 1},
		"unavailable storage":  {credentialForm, signInHeaders(), errors.New("SENTINEL_DRIVER"), 503, 1},
	} {
		f := &backendFixture{loginErr: tc.err}
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", target, tc.body, tc.headers)
		require.Equal(t, tc.status, response.Code, name)
		require.Equal(t, tc.calls, f.loginCalls, name)
		require.Empty(t, response.Header().Get("Set-Cookie"), name)
		require.NotContains(t, response.Body.String(), "SENTINEL", name)
		var model web.LoginModel
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, wantAction(link.Link()), model.Action, name)
	}
	// The timeout fallback answers after the handler consumed the body, and the
	// request URL still carries the target.
	f := &backendFixture{block: func(ctx context.Context) { <-ctx.Done() }}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	request := httptest.NewRequest("POST", target, strings.NewReader(credentialForm)).WithContext(ctx)
	request.Header = signInHeaders()
	response := httptest.NewRecorder()
	authHandler(t, f, nil, "http://127.0.0.1").ServeHTTP(response, request)
	cancel()
	require.Equal(t, 503, response.Code)
	var model web.LoginModel
	fixtureModel(t, response.Body.String(), &model)
	require.Equal(t, wantAction(link.Link()), model.Action)
	// A target that is not an authorization link renders the bare action, and a
	// refusal still refuses.
	for _, next := range []string{"//evil.example" + link.Link(), "/admin/users", link.Link() + "&extra=1", strings.Repeat("x", 8192)} {
		response := requestAuth(authHandler(t, &backendFixture{}, nil, "http://127.0.0.1"), "POST",
			"/login?"+url.Values{"next": {next}}.Encode(), credentialForm, withHeader("Origin", "https://attacker.invalid"))
		require.Equal(t, 403, response.Code)
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, "/login", model.Action)
		require.NotContains(t, response.Body.String(), "evil.example")
	}
}

// The sign-in document keeps a valid return target from its query without
// touching the database, which is how Approve without a session comes back.
func TestLoginDocumentReadsReturnTargetFromQuery(t *testing.T) {
	link := fixtureLink()
	f := &backendFixture{}
	handler := authHandler(t, f, nil, "http://127.0.0.1")
	for query, want := range map[string]string{
		"next=" + url.QueryEscape(link.Link()):                  link.Link(),
		"next=" + url.QueryEscape("//evil.example"+link.Link()): "",
		"next=" + url.QueryEscape(link.Link()) + "&next=/admin": "",
		"next=" + strings.Repeat("x", 8192):                     "",
		"":                                                      "",
	} {
		response := requestAuth(handler, "GET", "/login?"+query, "", nil)
		require.Equal(t, 200, response.Code)
		var model web.LoginModel
		fixtureModel(t, response.Body.String(), &model)
		require.Equal(t, wantAction(want), model.Action, query)
	}
	require.Zero(t, f.authCalls)
}

// Scenario: browser credentials on the token route, and the JSON transport
// rules; none of these reaches the service.
func TestTokenRouteTransport(t *testing.T) {
	valid := `{"code":"` + string(fixtureCode) + `","verifier":"` + string(fixtureVerifier) + `"}`
	for name, tc := range map[string]struct {
		body    string
		headers http.Header
		status  int
	}{
		"valid":            {valid, http.Header{"Content-Type": {"application/json"}}, 200},
		"cookie":           {valid, http.Header{"Content-Type": {"application/json"}, "Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 400},
		"authorization":    {valid, http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer " + string(fixtureToken)}}, 400},
		"form":             {"code=" + string(fixtureCode) + "&verifier=" + string(fixtureVerifier), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, 400},
		"foreign origin":   {valid, http.Header{"Content-Type": {"application/json"}, "Origin": {"https://attacker.invalid"}}, 403},
		"cross-site":       {valid, http.Header{"Content-Type": {"application/json"}, "Sec-Fetch-Site": {"cross-site"}}, 403},
		"unknown field":    {strings.TrimSuffix(valid, "}") + `,"SENTINEL":"x"}`, http.Header{"Content-Type": {"application/json"}}, 400},
		"trailing":         {valid + ` {}`, http.Header{"Content-Type": {"application/json"}}, 400},
		"duplicate":        {strings.TrimSuffix(valid, "}") + `,"code":"` + string(fixtureCode) + `"}`, http.Header{"Content-Type": {"application/json"}}, 400},
		"missing verifier": {`{"code":"` + string(fixtureCode) + `"}`, http.Header{"Content-Type": {"application/json"}}, 400},
		"short code":       {strings.Replace(valid, string(fixtureCode), string(fixtureCode[:42]), 1), http.Header{"Content-Type": {"application/json"}}, 400},
		"invalid verifier": {strings.Replace(valid, string(fixtureVerifier), strings.Repeat("*", 43), 1), http.Header{"Content-Type": {"application/json"}}, 400},
		"null":             {`{"code":null,"verifier":"` + string(fixtureVerifier) + `"}`, http.Header{"Content-Type": {"application/json"}}, 400},
		"oversized":        {valid + strings.Repeat(" ", auth.MaxCredentialBody), http.Header{"Content-Type": {"application/json"}}, 400},
	} {
		f := &backendFixture{}
		response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", auth.TokenPath, tc.body, tc.headers)
		require.Equal(t, tc.status, response.Code, name)
		require.Equal(t, "application/json", response.Header().Get("Content-Type"), name)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"), name)
		require.Empty(t, response.Header().Get("Set-Cookie"), name)
		require.Empty(t, response.Header().Get("Location"), name)
		require.NotContains(t, response.Body.String(), "SENTINEL", name)
		require.NotContains(t, response.Body.String(), string(fixtureCode), name)
		if tc.status == 200 {
			require.Equal(t, 1, f.exchangeCalls)
			require.Equal(t, auth.TokenRequest{Code: fixtureCode, Verifier: fixtureVerifier}, f.lastExchange)
			var issued auth.LoginResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &issued))
			require.Equal(t, auth.LoginResponse{Token: fixtureToken, Identity: fixtureIdentity}, issued)
			require.Contains(t, response.Body.String(), `"idleExpiresAt"`)
		} else {
			require.Zero(t, f.exchangeCalls+f.authCalls, name)
		}
	}
	f := &backendFixture{}
	f.exchangeErr = &auth.Error{Code: auth.InvalidCredentials}
	response := requestAuth(authHandler(t, f, nil, "http://127.0.0.1"), "POST", auth.TokenPath, valid, http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, 401, response.Code)
	require.Contains(t, response.Body.String(), auth.InvalidCredentials)
}

// The authorize routes answer an HTML document when their deadline passes.
func TestAuthorizeDeadlineReturnsTheSafeDocument(t *testing.T) {
	link := fixtureLink()
	for _, method := range []string{"GET", "POST"} {
		f := &backendFixture{block: func(ctx context.Context) { <-ctx.Done() }}
		handler := authHandler(t, f, nil, "http://127.0.0.1")
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		body := linkForm("51234", link.Challenge, link.State)
		target := "/authorize"
		if method == "GET" {
			target += "?" + body
			body = ""
		}
		request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(ctx)
		request.Header = browserHeaders()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		cancel()
		require.Equal(t, 503, response.Code, method)
		require.Contains(t, response.Body.String(), "<!doctype html>", method)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable, method)
		require.Empty(t, response.Header().Get("Location"), method)
		requireDocumentHeaders(t, response, "strict-origin")
	}
}
