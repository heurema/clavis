package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestVictoriaMetricsParseTarget(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  map[string]string
		want map[string]string
	}{
		{
			name: "no authentication",
			raw:  map[string]string{keyURL: "http://vm.example.com:8428", keyAuth: authNone},
			want: map[string]string{keyURL: "http://vm.example.com:8428", keyAuth: authNone},
		},
		{
			name: "basic with a username and a trimmed trailing slash",
			raw:  map[string]string{keyURL: "https://vm.example.com/", keyAuth: authBasic, keyUser: "reader"},
			want: map[string]string{keyURL: "https://vm.example.com", keyAuth: authBasic, keyUser: "reader"},
		},
		{
			name: "bearer keeps a path prefix",
			raw:  map[string]string{keyURL: "https://vm.example.com/select/0/prometheus/", keyAuth: authBearer},
			want: map[string]string{keyURL: "https://vm.example.com/select/0/prometheus", keyAuth: authBearer},
		},
		{
			name: "custom header",
			raw:  map[string]string{keyURL: "http://127.0.0.1:8428", keyAuth: authHeader, keyHeader: "X-Scope-OrgID"},
			want: map[string]string{keyURL: "http://127.0.0.1:8428", keyAuth: authHeader, keyHeader: "X-Scope-OrgID"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target, err := victoriaMetrics{}.ParseTarget(testCase.raw)
			require.NoError(t, err)
			require.Equal(t, testCase.want, target)
		})
	}
}

func TestVictoriaMetricsParseTargetRejections(t *testing.T) {
	base := "https://vm.example.com:8428"
	for _, testCase := range []struct {
		name string
		raw  map[string]string
	}{
		{"no settings", map[string]string{}},
		{"missing url", map[string]string{keyAuth: authNone}},
		{"missing auth", map[string]string{keyURL: base}},
		{"unknown key", map[string]string{keyURL: base, keyAuth: authNone, sentinel: sentinel}},
		{"credentials in url", map[string]string{keyURL: "https://reader:" + sentinel + "@vm.example.com", keyAuth: authNone}},
		{"userinfo in url", map[string]string{keyURL: "https://" + sentinel + "@vm.example.com", keyAuth: authNone}},
		{"query string", map[string]string{keyURL: base + "/?token=" + sentinel, keyAuth: authNone}},
		{"empty query", map[string]string{keyURL: base + "?", keyAuth: authNone}},
		{"fragment", map[string]string{keyURL: base + "#" + sentinel, keyAuth: authNone}},
		{"unknown scheme", map[string]string{keyURL: "ftp://vm.example.com", keyAuth: authNone}},
		{"uppercase scheme", map[string]string{keyURL: "HTTPS://vm.example.com", keyAuth: authNone}},
		{"leading whitespace", map[string]string{keyURL: " " + base, keyAuth: authNone}},
		{"embedded whitespace", map[string]string{keyURL: "https://vm.example.com/ " + sentinel, keyAuth: authNone}},
		{"two hosts", map[string]string{keyURL: "https://vm1," + sentinel, keyAuth: authNone}},
		{"zero port", map[string]string{keyURL: "https://vm.example.com:0", keyAuth: authNone}},
		{"unknown auth method", map[string]string{keyURL: base, keyAuth: sentinel}},
		{"uppercase auth method", map[string]string{keyURL: base, keyAuth: "BASIC", keyUser: "reader"}},
		{"padded auth method", map[string]string{keyURL: base, keyAuth: " basic", keyUser: "reader"}},
		{"basic without a user", map[string]string{keyURL: base, keyAuth: authBasic}},
		{"basic with an empty user", map[string]string{keyURL: base, keyAuth: authBasic, keyUser: ""}},
		{"user with a colon", map[string]string{keyURL: base, keyAuth: authBasic, keyUser: "reader:" + sentinel}},
		{"user with whitespace", map[string]string{keyURL: base, keyAuth: authBasic, keyUser: "read er"}},
		{"user with bearer", map[string]string{keyURL: base, keyAuth: authBearer, keyUser: sentinel}},
		{"user with none", map[string]string{keyURL: base, keyAuth: authNone, keyUser: sentinel}},
		{"user with header auth", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "X-Token", keyUser: sentinel}},
		{"header auth without a header", map[string]string{keyURL: base, keyAuth: authHeader}},
		{"header with bearer", map[string]string{keyURL: base, keyAuth: authBearer, keyHeader: "X-Token"}},
		{"header with none", map[string]string{keyURL: base, keyAuth: authNone, keyHeader: "X-Token"}},
		{"reserved authorization header", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "Authorization"}},
		{"reserved lowercase authorization header", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "authorization"}},
		{"reserved uppercase host header", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "HOST"}},
		{"reserved content-length header", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "Content-Length"}},
		{"header with a space", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "X Scope " + sentinel}},
		{"header with a colon", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "X-Scope:" + sentinel}},
		{"header with a newline", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: "X-Scope\n" + sentinel}},
		{"empty header", map[string]string{keyURL: base, keyAuth: authHeader, keyHeader: ""}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target, err := victoriaMetrics{}.ParseTarget(testCase.raw)
			require.Nil(t, target)
			requireRejected(t, err)
		})
	}
}

func TestVictoriaMetricsValidateSecret(t *testing.T) {
	none := map[string]string{keyAuth: authNone}
	require.NoError(t, victoriaMetrics{}.ValidateSecret(none, ""))
	requireRejected(t, victoriaMetrics{}.ValidateSecret(none, auth.Secret(sentinel)))
	for _, method := range []string{authBasic, authBearer, authHeader} {
		target := map[string]string{keyAuth: method}
		require.NoError(t, victoriaMetrics{}.ValidateSecret(target, auth.Secret(sentinel)))
		requireRejected(t, victoriaMetrics{}.ValidateSecret(target, ""))
		requireRejected(t, victoriaMetrics{}.ValidateSecret(target, auth.Secret(sentinel+"\r\n")))
		requireRejected(t, victoriaMetrics{}.ValidateSecret(target, auth.Secret(strings.Repeat("x", auth.MaxSecretBytes+1))))
	}
}

const probeSecret = sentinel + "-secret"

// requests records what a probe actually sent, so every assertion runs on the
// test goroutine rather than inside a handler.
type requests struct {
	mutex   sync.Mutex
	methods []string
	paths   []string
	headers []http.Header
}

func (r *requests) record(request *http.Request) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.methods = append(r.methods, request.Method)
	r.paths = append(r.paths, request.URL.Path)
	r.headers = append(r.headers, request.Header.Clone())
}

func (r *requests) count() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return len(r.headers)
}

// only asserts that exactly one GET reached /health and returns its headers.
func (r *requests) only(t *testing.T) http.Header {
	t.Helper()
	r.mutex.Lock()
	defer r.mutex.Unlock()
	require.Len(t, r.headers, 1)
	require.Equal(t, []string{http.MethodGet}, r.methods)
	require.Equal(t, []string{healthPath}, r.paths)
	return r.headers[0]
}

// healthServer answers with the supplied status and a body larger than the
// probe is allowed to read.
func healthServer(t *testing.T, status int) (string, *requests) {
	t.Helper()
	seen := &requests{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			_, _ = w.Write([]byte("probe body " + strings.Repeat("x", 4096)))
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, seen
}

func probeContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	return ctx
}

func TestVictoriaMetricsProbeAuthMethods(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		raw    func(url string) map[string]string
		secret auth.Secret
		check  func(t *testing.T, headers http.Header)
	}{
		{
			name: authNone,
			raw:  func(url string) map[string]string { return map[string]string{keyURL: url, keyAuth: authNone} },
			check: func(t *testing.T, headers http.Header) {
				require.Empty(t, headers.Values("Authorization"))
			},
		},
		{
			name: authBasic,
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authBasic, keyUser: "reader"}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				encoded := base64.StdEncoding.EncodeToString([]byte("reader:" + probeSecret))
				require.Equal(t, "Basic "+encoded, headers.Get("Authorization"))
			},
		},
		{
			name:   authBearer,
			raw:    func(url string) map[string]string { return map[string]string{keyURL: url, keyAuth: authBearer} },
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				require.Equal(t, "Bearer "+probeSecret, headers.Get("Authorization"))
			},
		},
		{
			name: authHeader,
			raw: func(url string) map[string]string {
				return map[string]string{keyURL: url, keyAuth: authHeader, keyHeader: "X-Scope-OrgID"}
			},
			secret: probeSecret,
			check: func(t *testing.T, headers http.Header) {
				require.Equal(t, probeSecret, headers.Get("X-Scope-OrgID"))
				require.Empty(t, headers.Values("Authorization"))
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			url, seen := healthServer(t, http.StatusOK)
			target, err := victoriaMetrics{}.ParseTarget(testCase.raw(url))
			require.NoError(t, err)
			require.NoError(t, victoriaMetrics{}.ValidateSecret(target, testCase.secret))
			outcome := victoriaMetrics{}.Probe(probeContext(t, 5*time.Second), target, testCase.secret)
			require.Equal(t, auth.CheckReachable, outcome)
			testCase.check(t, seen.only(t))
			requireNoSentinel(t, outcome, target)
		})
	}
}

func TestVictoriaMetricsProbeStatuses(t *testing.T) {
	for _, testCase := range []struct {
		status int
		want   auth.CheckOutcome
	}{
		{http.StatusOK, auth.CheckReachable},
		{http.StatusUnauthorized, auth.CheckAuthRejected},
		{http.StatusForbidden, auth.CheckAuthRejected},
		{http.StatusNotFound, auth.CheckUnreachable},
		{http.StatusInternalServerError, auth.CheckUnreachable},
		{http.StatusServiceUnavailable, auth.CheckUnreachable},
		{http.StatusNoContent, auth.CheckUnreachable},
	} {
		t.Run(fmt.Sprint(testCase.status), func(t *testing.T) {
			url, seen := healthServer(t, testCase.status)
			target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: url, keyAuth: authBearer})
			require.NoError(t, err)
			outcome := victoriaMetrics{}.Probe(probeContext(t, 5*time.Second), target, auth.Secret(probeSecret))
			require.Equal(t, testCase.want, outcome)
			require.Equal(t, 1, seen.count())
			requireNoSentinel(t, outcome)
		})
	}
}

func TestVictoriaMetricsProbeDoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+healthPath, http.StatusFound)
	}))
	t.Cleanup(source.Close)
	target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: source.URL, keyAuth: authBearer})
	require.NoError(t, err)
	outcome := victoriaMetrics{}.Probe(probeContext(t, 5*time.Second), target, auth.Secret(probeSecret))
	require.Equal(t, auth.CheckUnreachable, outcome)
	require.Zero(t, destinationCalls.Load())
}

func TestVictoriaMetricsProbeHonoursDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: server.URL, keyAuth: authNone})
	require.NoError(t, err)
	started := time.Now()
	outcome := victoriaMetrics{}.Probe(probeContext(t, 200*time.Millisecond), target, "")
	elapsed := time.Since(started)
	require.Equal(t, auth.CheckUnreachable, outcome)
	require.GreaterOrEqual(t, elapsed, 150*time.Millisecond)
	require.Less(t, elapsed, 2*time.Second)
}

func TestVictoriaMetricsProbeExpiredContext(t *testing.T) {
	url, seen := healthServer(t, http.StatusOK)
	target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: url, keyAuth: authNone})
	require.NoError(t, err)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	require.Equal(t, auth.CheckUnreachable, victoriaMetrics{}.Probe(ctx, target, ""))
	require.Zero(t, seen.count())
}

// An untrusted certificate must read as unreachable, not as a panic and not as
// a silent success: the probe never disables verification.
func TestVictoriaMetricsProbeRejectsUntrustedTLS(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: server.URL, keyAuth: authBearer})
	require.NoError(t, err)
	outcome := victoriaMetrics{}.Probe(probeContext(t, 5*time.Second), target, auth.Secret(probeSecret))
	require.Equal(t, auth.CheckUnreachable, outcome)
	require.Zero(t, calls.Load())
	requireNoSentinel(t, outcome)
}

func TestVictoriaMetricsProbeIsConcurrencySafe(t *testing.T) {
	url, seen := healthServer(t, http.StatusOK)
	target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: url, keyAuth: authBearer})
	require.NoError(t, err)
	ctx := probeContext(t, 5*time.Second)
	outcomes := make(chan auth.CheckOutcome, 8)
	for range cap(outcomes) {
		go func() { outcomes <- victoriaMetrics{}.Probe(ctx, target, auth.Secret(probeSecret)) }()
	}
	for range cap(outcomes) {
		require.Equal(t, auth.CheckReachable, <-outcomes)
	}
	require.Equal(t, cap(outcomes), seen.count())
}

func TestVictoriaMetricsRejectsEmptyPortAndControlBytes(t *testing.T) {
	provider, ok := Lookup(auth.ProviderVictoriaMetrics)
	require.True(t, ok)
	_, err := provider.ParseTarget(map[string]string{"url": "http://metrics:/", "auth": "none"})
	require.Error(t, err, "a trailing colon is an empty port, which cannot be dialed")
	for name, target := range map[string]map[string]string{
		"bearer": {"url": "http://metrics", "auth": "bearer"},
		"header": {"url": "http://metrics", "auth": "header", "header": "X-Api-Key"},
	} {
		for _, secret := range []string{"tok\ten", "tok\x01en", "tok\x7fen"} {
			require.Error(t, provider.ValidateSecret(target, auth.Secret(secret)), name)
		}
		require.NoError(t, provider.ValidateSecret(target, auth.Secret("printable-token-value")), name)
	}
	require.NoError(t, provider.ValidateSecret(map[string]string{"url": "http://metrics", "auth": "basic", "user": "u"}, auth.Secret("pass\tword")), "basic secrets are base64-encoded, so a tab is fine")
}
