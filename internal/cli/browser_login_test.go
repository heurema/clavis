package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// approveLink plays the browser: it opens the link, follows the approval's
// redirect to the loopback callback and checks the CLI's success page.
func approveLink(link string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(link)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Signed in.") {
		return fmt.Errorf("approval ended with status %d", response.StatusCode)
	}
	return nil
}

// approvingBrowser is an opener that approves every link it is given.
func approvingBrowser(t *testing.T) BrowserOpener {
	return func(_ context.Context, link string) error {
		assert.NoError(t, approveLink(link))
		return nil
	}
}

func refusePassword(t *testing.T) HiddenPasswordReader {
	return func(context.Context, io.Reader, io.Writer) ([]byte, error) {
		t.Error("login must never read a password")
		return nil, errors.New("unexpected password read")
	}
}

// loginInvoke runs login with a browser that approves its link and returns
// the exit code, the decoded result, stdout and stderr.
func loginInvoke(t *testing.T, args ...string) (int, Result, string, string) {
	t.Helper()
	var out, errout bytes.Buffer
	exit := RunWithIO(context.Background(), append([]string{"clavis", "login"}, args...), IO{
		Stdout: &out, Stderr: &errout, ReadPassword: refusePassword(t), OpenBrowser: approvingBrowser(t),
	})
	return exit, decode(t, out.String()), out.String(), errout.String()
}

func loginCLI(t *testing.T, server *httptest.Server) {
	t.Helper()
	exit, result, _, _ := loginInvoke(t, "--server", server.URL)
	require.Equal(t, 0, exit, "%+v", result.Error)
}

// serveApproval answers GET /authorize the way a signed-in person's Approve
// does, redirecting to the loopback callback with a fresh code.
func serveApproval(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != auth.AuthorizePath {
		return false
	}
	link, ok := auth.ParseCLIAuthorization(r.URL.Query())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return true
	}
	http.Redirect(w, r, link.CallbackURL(testToken()), http.StatusSeeOther)
	return true
}

// printedLink returns the link login printed after its notice.
func printedLink(t *testing.T, stderr string) string {
	t.Helper()
	notice, link, found := strings.Cut(stderr, "\n")
	require.True(t, found, "stderr: %q", stderr)
	require.Equal(t, "Open this link to sign in:", notice)
	return strings.TrimSuffix(link, "\n")
}

// callbackPort reads the loopback port out of a printed link.
func callbackPort(t *testing.T, link string) int {
	t.Helper()
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	authorization, ok := auth.ParseCLIAuthorization(parsed.Query())
	require.True(t, ok, link)
	return authorization.Port
}

// linkWriter is a stderr that hands the printed link to a waiting browser.
type linkWriter struct {
	mu    sync.Mutex
	text  strings.Builder
	links chan string
}

func (w *linkWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.text.Write(data)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "http") {
			w.links <- line
		}
	}
	return len(data), nil
}

func (w *linkWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.text.String()
}

func requireListenerClosed(t *testing.T, port int) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err == nil {
		_ = connection.Close()
	}
	require.Error(t, err, "the callback listener must be closed")
}

func cachedBytes(t *testing.T, origin string) []byte {
	t.Helper()
	data, err := os.ReadFile(cachePath(t, origin))
	require.NoError(t, err)
	return data
}

func TestBrowserLoginWaitsFiveMinutes(t *testing.T) {
	require.Equal(t, 5*time.Minute, browserLoginWait)
}

// Scenario: browser login from a terminal, and the successful login output.
func TestBrowserLoginStoresSessionAndKeepsSecretsOffStdout(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t)
	cliProfile(t, server.URL)
	var opened []string
	var out, errout bytes.Buffer
	exit := RunWithIO(context.Background(), []string{"clavis", "login"}, IO{
		Stdout: &out, Stderr: &errout, ReadPassword: refusePassword(t),
		OpenBrowser: func(ctx context.Context, link string) error {
			opened = append(opened, link)
			return approvingBrowser(t)(ctx, link)
		},
	})
	require.Equal(t, 0, exit, out.String())
	link := printedLink(t, errout.String())
	require.Equal(t, []string{link}, opened, "the opener receives exactly the printed link")
	require.True(t, strings.HasPrefix(link, server.URL+auth.AuthorizePath+"?"), link)
	require.Equal(t, "Open this link to sign in:\n"+link+"\n", errout.String())
	callbackPort(t, link)

	result := decode(t, out.String())
	require.True(t, result.OK)
	require.Equal(t, server.URL, *result.Server)
	require.Equal(t, "test", *result.Profile)
	data, _ := result.Data.(map[string]any)
	require.Contains(t, data, "expiresAt")
	require.Contains(t, data, "idleExpiresAt")
	require.NotContains(t, data, "token")

	fixture.mu.Lock()
	code, verifier := fixture.lastCode, fixture.lastVerifier
	require.Len(t, fixture.sessions, 1)
	var token auth.Secret
	for issued := range fixture.sessions {
		token = issued
	}
	fixture.mu.Unlock()
	require.True(t, auth.ValidToken(code))
	require.True(t, auth.ValidToken(verifier))
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	for _, secret := range []string{string(code), string(verifier), string(token), parsed.Query().Get("state"), parsed.Query().Get("challenge")} {
		require.NotContains(t, out.String(), secret)
	}
	for _, secret := range []string{string(code), string(verifier), string(token)} {
		require.NotContains(t, errout.String(), secret)
	}

	// Text output of login and whoami prints both expiries, and the link stays
	// on stderr.
	out.Reset()
	errout.Reset()
	exit = RunWithIO(context.Background(), []string{"clavis", "login", "--output=text"}, IO{
		Stdout: &out, Stderr: &errout, OpenBrowser: approvingBrowser(t),
	})
	require.Equal(t, 0, exit)
	text := serverText(t, out.String(), server.URL, "test")
	require.Regexp(t, `^User: cli-test \(`+testIdentity().User.ID+`\)\nRole: admin\nExpires: \S+Z\nIdle until: \S+Z\n$`, text)
	require.NotContains(t, text, "http")
	out.Reset()
	exit = RunWithIO(context.Background(), []string{"clavis", "whoami", "--output=text"}, IO{Stdout: &out})
	require.Equal(t, 0, exit)
	require.Regexp(t, `\nExpires: \S+Z\nIdle until: \S+Z\n`, out.String())
}

// Scenario: forged callback. A request with a missing or different state, to
// another path or with another method is refused, and the wait goes on.
func TestBrowserLoginRefusesForgedCallbacks(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t)
	forged := testToken()
	var out bytes.Buffer
	exit := RunWithIO(context.Background(), []string{"clavis", "login", "--server", server.URL}, IO{
		Stdout: &out,
		OpenBrowser: func(_ context.Context, link string) error {
			port := strconv.Itoa(callbackPort(t, link))
			base := "http://127.0.0.1:" + port
			// The listener is bound to 127.0.0.1 only, not every address.
			if connection, err := net.DialTimeout("tcp", "[::1]:"+port, time.Second); err == nil {
				_ = connection.Close()
				t.Error("the callback listener accepted a connection on ::1")
			}
			parsed, err := url.Parse(link)
			assert.NoError(t, err)
			state := parsed.Query().Get("state")
			for _, tc := range []struct {
				method, path string
				status       int
			}{
				{"GET", "/callback?" + url.Values{"code": {string(forged)}, "state": {string(testToken())}}.Encode(), 400},
				{"GET", "/callback?" + url.Values{"code": {string(forged)}}.Encode(), 400},
				{"GET", "/callback?" + url.Values{"code": {string(forged)}, "state": {state[:42]}}.Encode(), 400},
				{"GET", "/callback?" + url.Values{"code": {string(forged)[:42]}, "state": {state}}.Encode(), 400},
				{"GET", "/callback?" + url.Values{"code": {string(forged)}, "state": {state, state}}.Encode(), 400},
				{"POST", "/callback?" + url.Values{"code": {string(forged)}, "state": {state}}.Encode(), 400},
				{"GET", "/other?" + url.Values{"code": {string(forged)}, "state": {state}}.Encode(), 404},
				{"GET", "/", 404},
			} {
				request, err := http.NewRequest(tc.method, base+tc.path, nil)
				assert.NoError(t, err)
				response, err := http.DefaultClient.Do(request)
				if assert.NoError(t, err) {
					body, _ := io.ReadAll(response.Body)
					_ = response.Body.Close()
					assert.Equal(t, tc.status, response.StatusCode, tc.path)
					assert.NotContains(t, string(body), "Signed in", tc.path)
				}
			}
			return approvingBrowser(t)(context.Background(), link)
		},
	})
	require.Equal(t, 0, exit, out.String())
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, 1, fixture.login, "only the matching callback's code is redeemed")
	require.NotEqual(t, forged, fixture.lastCode)
}

// Scenario: nobody approves. The wait ends with TIMEOUT, the listener is
// closed and a working stored session is unchanged.
func TestBrowserLoginTimeoutKeepsStoredSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t)
	loginCLI(t, server)
	before := cachedBytes(t, server.URL)
	previous := browserLoginWait
	browserLoginWait = 200 * time.Millisecond
	t.Cleanup(func() { browserLoginWait = previous })
	port := 0
	var out bytes.Buffer
	start := time.Now()
	exit := RunWithIO(context.Background(), []string{"clavis", "login", "--server", server.URL}, IO{
		Stdout: &out,
		OpenBrowser: func(_ context.Context, link string) error {
			port = callbackPort(t, link)
			return nil
		},
	})
	require.Equal(t, 1, exit)
	require.Equal(t, "TIMEOUT", decode(t, out.String()).Error.Code)
	require.Less(t, time.Since(start), 3*time.Second)
	requireListenerClosed(t, port)
	require.Equal(t, before, cachedBytes(t, server.URL))
	exit, _, _ = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 0, exit)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, 1, fixture.login)
	require.Zero(t, fixture.logout)
}

// Scenario: an interruption exits without storing anything.
func TestBrowserLoginCancellationStoresNothing(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 0
	var out bytes.Buffer
	exit := RunWithIO(ctx, []string{"clavis", "login", "--server", server.URL}, IO{
		Stdout: &out,
		OpenBrowser: func(_ context.Context, link string) error {
			port = callbackPort(t, link)
			cancel()
			return nil
		},
	})
	require.Equal(t, 1, exit)
	require.Equal(t, "TIMEOUT", decode(t, out.String()).Error.Code)
	requireListenerClosed(t, port)
	_, err := os.Stat(cachePath(t, server.URL))
	require.True(t, os.IsNotExist(err))
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.login)
}

// Scenario: browser cannot be opened. The CLI keeps waiting with the link
// printed and completes when the person approves through it.
func TestBrowserLoginSurvivesAFailingOpener(t *testing.T) {
	cliHome(t)
	_, server := newCLIFixture(t)
	stderr := &linkWriter{links: make(chan string, 1)}
	approved := make(chan error, 1)
	go func() { approved <- approveLink(<-stderr.links) }()
	var out bytes.Buffer
	exit := RunWithIO(context.Background(), []string{"clavis", "login", "--server", server.URL}, IO{
		Stdout: &out, Stderr: stderr,
		OpenBrowser: func(context.Context, string) error { return errors.New("no browser here") },
	})
	require.Equal(t, 0, exit, out.String())
	require.NoError(t, <-approved)
	require.True(t, decode(t, out.String()).OK)
}

// Scenario: login without opening a browser.
func TestNoBrowserNeverCallsTheOpener(t *testing.T) {
	cliHome(t)
	_, server := newCLIFixture(t)
	stderr := &linkWriter{links: make(chan string, 1)}
	approved := make(chan error, 1)
	go func() { approved <- approveLink(<-stderr.links) }()
	var out bytes.Buffer
	exit := RunWithIO(context.Background(), []string{"clavis", "login", "--no-browser", "--server", server.URL}, IO{
		Stdout: &out, Stderr: stderr, ReadPassword: refusePassword(t),
		OpenBrowser: func(context.Context, string) error {
			t.Error("--no-browser must not run the opener")
			return nil
		},
	})
	require.Equal(t, 0, exit, out.String())
	require.NoError(t, <-approved)
	link := printedLink(t, stderr.String())
	require.True(t, strings.HasPrefix(link, server.URL+auth.AuthorizePath+"?"))
}

// Scenario: redemption refused. The command fails with the server's code and
// the stored session is neither replaced nor revoked.
func TestRefusedRedemptionKeepsStoredSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t)
	loginCLI(t, server)
	before := cachedBytes(t, server.URL)
	fixture.mu.Lock()
	fixture.refuseExchange = true
	fixture.mu.Unlock()
	exit, result, output, _ := loginInvoke(t, "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, auth.InvalidCredentials, result.Error.Code)
	require.Equal(t, "The sign-in was not accepted", result.Error.Message)
	fixture.mu.Lock()
	require.NotContains(t, output, string(fixture.lastCode))
	require.NotContains(t, output, string(fixture.lastVerifier))
	require.Equal(t, 2, fixture.login)
	require.Zero(t, fixture.logout)
	require.Len(t, fixture.sessions, 1)
	fixture.mu.Unlock()
	require.Equal(t, before, cachedBytes(t, server.URL))
	exit, _, _ = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 0, exit)
}

// Scenarios: password flags are refused, and a login that cannot resolve its
// server or use its storage neither prints a link nor runs the opener.
func TestLoginRefusedBeforeListening(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t)
	const password = "correct-horse-battery-staple"
	for _, args := range [][]string{
		{"login", "--username", "alice", "--server", server.URL},
		{"login", "--password-stdin", "--server", server.URL},
		{"login", "--username=cli-test", "--password-stdin", "--server", server.URL},
		{"login", "--server", server.URL, "--profile", "fce"},
		{"login", "--server", "http://example.com"},
		{"login"},
		{"login", "--server", server.URL, "--timeout=0"},
		{"login", "--server", server.URL, "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errout bytes.Buffer
			stdin := strings.NewReader(password)
			exit := RunWithIO(context.Background(), append([]string{"clavis", "--output=text"}, args...), IO{
				Stdin: stdin, Stdout: &out, Stderr: &errout, ReadPassword: refusePassword(t),
				OpenBrowser: func(context.Context, string) error {
					t.Error("a refused login must not run the opener")
					return nil
				},
			})
			require.Equal(t, 2, exit)
			require.Equal(t, "INVALID_ARGUMENT", decode(t, out.String()).Error.Code)
			require.Equal(t, len(password), stdin.Len(), "stdin must not be read")
			require.Empty(t, errout.String(), "no link may be printed")
		})
	}
	require.NoError(t, os.MkdirAll(cacheDirectory(t), 0o700))
	require.NoError(t, os.Chmod(cacheDirectory(t), 0o755))
	var out, errout bytes.Buffer
	exit := RunWithIO(context.Background(), []string{"clavis", "login", "--server", server.URL}, IO{
		Stdout: &out, Stderr: &errout,
		OpenBrowser: func(context.Context, string) error {
			t.Error("unsafe storage must fail before the opener runs")
			return nil
		},
	})
	require.Equal(t, 1, exit)
	require.Equal(t, "CREDENTIAL_STORAGE_FAILED", decode(t, out.String()).Error.Code)
	require.Empty(t, errout.String())
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.requests)
}

func cacheDirectory(t *testing.T) string {
	t.Helper()
	home, err := clavisHome()
	require.NoError(t, err)
	return home + "/sessions"
}

// The callback handler answers its page once; a replay of the same matching
// callback is refused.
func TestCallbackHandlerAcceptsOneCode(t *testing.T) {
	state := string(testToken())
	codes := make(chan auth.Secret, 1)
	handler := callbackHandler(state, codes)
	target := "/callback?" + url.Values{"code": {string(testToken())}, "state": {state}}.Encode()
	for index, want := range []int{200, 400} {
		response := &recorder{header: http.Header{}}
		request, err := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)
		handler.ServeHTTP(response, request)
		require.Equal(t, want, response.status, index)
		require.Equal(t, "no-store", response.header.Get("Cache-Control"))
		require.Equal(t, "no-referrer", response.header.Get("Referrer-Policy"))
	}
	require.Len(t, codes, 1)
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(data)
}
func (r *recorder) WriteHeader(status int) { r.status = status }
