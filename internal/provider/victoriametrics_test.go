package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// The expression a test submits. It is the caller's own text: it may reach the
// source unchanged and may never appear in an error the platform produces.
const metricsExpression = `sum(rate(http_requests_total{job="SENTINEL_JOB"}[5m])) by (job)`

const metricsVector = `{"status":"success","data":{"resultType":"vector","result":[` +
	`{"metric":{"job":"api","__name__":"up"},"value":[1435781451.781,"1"]},` +
	`{"metric":{"job":"web","__name__":"up"},"value":[1435781451.781,"0"]}]},` +
	`"stats":{"seriesFetched":"2","executionTimeMsec":1}}`

const metricsMatrix = `{"status":"success","data":{"resultType":"matrix","result":[` +
	`{"metric":{"job":"api"},"values":[[1435781430,"1"],[1435781445,"2"]]}]}}`

// metricsExchange is one request as the fake source saw it.
type metricsExchange struct {
	method   string
	path     string
	rawQuery string
	rawBody  string
	headers  http.Header
}

// values parses whichever of the query string and the body carried the
// parameters, so a test compares what the source would have parsed.
func (e metricsExchange) values(t *testing.T) url.Values {
	t.Helper()
	raw := e.rawQuery
	if e.method == http.MethodPost {
		raw = e.rawBody
	}
	values, err := url.ParseQuery(raw)
	require.NoError(t, err)
	return values
}

type metricsCapture struct {
	mu        sync.Mutex
	exchanges []metricsExchange
}

func (c *metricsCapture) record(t *testing.T, r *http.Request) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exchanges = append(c.exchanges, metricsExchange{
		method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
		rawBody: string(body), headers: r.Header.Clone(),
	})
}

func (c *metricsCapture) only(t *testing.T) metricsExchange {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Len(t, c.exchanges, 1)
	return c.exchanges[0]
}

func (c *metricsCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.exchanges)
}

// metricsSource answers every request with one canned response.
func metricsSource(t *testing.T, status int, contentType, body string) (string, *metricsCapture) {
	t.Helper()
	seen := &metricsCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(t, r)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server.URL, seen
}

func metricsJSON(t *testing.T, body string) (string, *metricsCapture) {
	t.Helper()
	return metricsSource(t, http.StatusOK, "application/json", body)
}

func metricsTarget(t *testing.T, address string) map[string]string {
	t.Helper()
	target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: address, keyAuth: authNone})
	require.NoError(t, err)
	return target
}

// metricsExecute runs one execution against a fake source under a deadline generous
// enough that only the provider's own bounds can end it.
func metricsExecute(t *testing.T, address string, request ExecuteRequest) (ExecuteResult, error) {
	t.Helper()
	return victoriaMetrics{}.Execute(probeContext(t, 20*time.Second), metricsTarget(t, address), "", request)
}

// Every endpoint receives exactly the strings that were submitted: no time is
// reformatted, no step is normalised, no selector is rewritten, and a field
// that was not given is not sent at all.
func TestVictoriaMetricsExecuteEndpoints(t *testing.T) {
	selector := `{job="api",__name__=~"up|down"}`
	other := `{instance="host-1"}`
	for _, testCase := range []struct {
		name    string
		request ExecuteRequest
		method  string
		path    string
		values  url.Values
		absent  []string
	}{
		{
			name:    "instant query",
			request: ExecuteRequest{PromQL: metricsExpression, Timeout: 30 * time.Second},
			method:  http.MethodPost, path: metricsQueryPath,
			values: url.Values{"query": {metricsExpression}, "timeout": {"30s"}},
			absent: []string{"time", "start", "end", "step", "limit", "match[]"},
		},
		{
			name:    "instant query pinned to a time",
			request: ExecuteRequest{PromQL: metricsExpression, At: "2026-09-13T10:00:00Z", Timeout: time.Second},
			method:  http.MethodPost, path: metricsQueryPath,
			values: url.Values{"query": {metricsExpression}, "time": {"2026-09-13T10:00:00Z"}, "timeout": {"1s"}},
			absent: []string{"start", "end", "step"},
		},
		{
			name: "range query",
			request: ExecuteRequest{
				PromQL: metricsExpression, Start: "-1h", End: "now", Step: "1m", Timeout: 45 * time.Second,
			},
			method: http.MethodPost, path: metricsQueryRangePath,
			values: url.Values{
				"query": {metricsExpression}, "start": {"-1h"}, "end": {"now"},
				"step": {"1m"}, "timeout": {"45s"},
			},
			absent: []string{"time", "limit"},
		},
		{
			name:    "range query without an end or a step",
			request: ExecuteRequest{PromQL: metricsExpression, Start: "1435781430.781", Timeout: 30 * time.Second},
			method:  http.MethodPost, path: metricsQueryRangePath,
			values: url.Values{"query": {metricsExpression}, "start": {"1435781430.781"}, "timeout": {"30s"}},
			absent: []string{"end", "step", "time"},
		},
		{
			name:    "labels",
			request: ExecuteRequest{Labels: true, Match: selector, Start: "-1h", MaxRows: 5, Timeout: 30 * time.Second},
			method:  http.MethodGet, path: metricsLabelsPath,
			values: url.Values{
				"match[]": {selector}, "start": {"-1h"}, "limit": {"6"}, "timeout": {"30s"},
			},
			absent: []string{"end", "query", "step", "time"},
		},
		{
			name:    "label values",
			request: ExecuteRequest{LabelValues: "__name__", MaxRows: 1000, Timeout: 30 * time.Second},
			method:  http.MethodGet, path: "/api/v1/label/__name__/values",
			values: url.Values{"limit": {"1001"}, "timeout": {"30s"}},
			absent: []string{"match[]", "start", "end"},
		},
		{
			name: "series with its own selector and a narrowing match",
			request: ExecuteRequest{
				Series: selector, Match: other, Start: "-1h", End: "now", MaxRows: 2, Timeout: 30 * time.Second,
			},
			method: http.MethodGet, path: metricsSeriesPath,
			// The selector comes first and the match after it: the source is
			// given both, in the order the caller named them.
			values: url.Values{
				"match[]": {selector, other}, "start": {"-1h"}, "end": {"now"},
				"limit": {"3"}, "timeout": {"30s"},
			},
			absent: []string{"query", "step"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			body := metricsVector
			if testCase.method == http.MethodGet {
				body = `{"status":"success","data":["up"]}`
			}
			address, seen := metricsJSON(t, body)
			_, err := metricsExecute(t, address, testCase.request)
			require.NoError(t, err)
			exchange := seen.only(t)
			require.Equal(t, testCase.method, exchange.method)
			require.Equal(t, testCase.path, exchange.path)
			require.Equal(t, testCase.values, exchange.values(t))
			require.Equal(t, "application/json", exchange.headers.Get("Accept"))
			raw := exchange.rawQuery
			if testCase.method == http.MethodPost {
				require.Equal(t, metricsFormType, exchange.headers.Get("Content-Type"))
				require.Empty(t, exchange.rawQuery, "a query endpoint takes a form body, not a query string")
				raw = exchange.rawBody
			} else {
				require.Empty(t, exchange.rawBody)
			}
			// A parameter that was not given is absent from the wire, not
			// present and empty: the source applies its own default.
			for _, key := range testCase.absent {
				require.NotContains(t, raw, url.QueryEscape(key)+"=", key)
			}
		})
	}
}

// The timeout the connection carries is the source's own bound, so the source
// aborts its evaluation rather than the platform cutting the exchange.
func TestVictoriaMetricsExecuteTimeoutParameter(t *testing.T) {
	for _, testCase := range []struct {
		timeout time.Duration
		want    string
	}{
		{30 * time.Second, "30s"},
		{time.Second, "1s"},
		{1500 * time.Millisecond, "1.5s"},
		{120 * time.Second, "120s"},
		// A missing bound is the documented default rather than no bound.
		{0, "30s"},
	} {
		t.Run(testCase.want, func(t *testing.T) {
			address, seen := metricsJSON(t, metricsVector)
			_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, Timeout: testCase.timeout})
			require.NoError(t, err)
			require.Equal(t, []string{testCase.want}, seen.only(t).values(t)["timeout"])
		})
	}
}

// Every result shape reaches the caller as the source rendered it: the
// platform reorders nothing, converts nothing and names the type only for the
// discovery endpoints, which have none of their own.
func TestVictoriaMetricsExecuteResultsPassThrough(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		request    ExecuteRequest
		body       string
		resultType string
		result     string
		rows       int64
	}{
		{
			name: "vector", request: ExecuteRequest{PromQL: metricsExpression}, body: metricsVector,
			resultType: "vector",
			result: `[{"metric":{"job":"api","__name__":"up"},"value":[1435781451.781,"1"]},` +
				`{"metric":{"job":"web","__name__":"up"},"value":[1435781451.781,"0"]}]`,
			rows: 2,
		},
		{
			name: "matrix", request: ExecuteRequest{PromQL: metricsExpression, Start: "-1h", Step: "15s"},
			body: metricsMatrix, resultType: "matrix",
			result: `[{"metric":{"job":"api"},"values":[[1435781430,"1"],[1435781445,"2"]]}]`,
			rows:   2,
		},
		{
			name: "scalar", request: ExecuteRequest{PromQL: "2+2"},
			body:       `{"status":"success","data":{"resultType":"scalar","result":[1435781451.781,"4"]}}`,
			resultType: "scalar", result: `[1435781451.781,"4"]`, rows: 1,
		},
		{
			name: "string", request: ExecuteRequest{PromQL: `"text"`},
			body:       `{"status":"success","data":{"resultType":"string","result":[1435781451.781,"some text"]}}`,
			resultType: "string", result: `[1435781451.781,"some text"]`, rows: 1,
		},
		{
			name: "empty vector", request: ExecuteRequest{PromQL: metricsExpression},
			body:       `{"status":"success","data":{"resultType":"vector","result":[]}}`,
			resultType: "vector", result: `[]`, rows: 0,
		},
		{
			name: "labels", request: ExecuteRequest{Labels: true},
			body:       `{"status":"success","data":["__name__","instance","job"]}`,
			resultType: resultTypeLabels, result: `["__name__","instance","job"]`, rows: 3,
		},
		{
			name: "label values", request: ExecuteRequest{LabelValues: "job"},
			body:       `{"status":"success","data":["api","web"]}`,
			resultType: resultTypeLabelValues, result: `["api","web"]`, rows: 2,
		},
		{
			name: "series", request: ExecuteRequest{Series: `{__name__="up"}`},
			body:       `{"status":"success","data":[{"job":"api","__name__":"up"},{"job":"web","__name__":"up"}]}`,
			resultType: resultTypeSeries,
			result:     `[{"job":"api","__name__":"up"},{"job":"web","__name__":"up"}]`, rows: 2,
		},
		{
			name: "empty discovery list", request: ExecuteRequest{Labels: true},
			body:       `{"status":"success","data":[]}`,
			resultType: resultTypeLabels, result: `[]`, rows: 0,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := metricsJSON(t, testCase.body)
			result, err := metricsExecute(t, address, testCase.request)
			require.NoError(t, err)
			require.Equal(t, testCase.resultType, result.ResultType)
			require.JSONEq(t, testCase.result, string(result.Result))
			// The source's own order survives, labels included: the decoder
			// never puts a series through a map.
			require.Equal(t, testCase.result, string(result.Result))
			require.False(t, result.Truncated)
			require.Equal(t, testCase.rows, result.Rows)
			require.Equal(t, int64(1), result.Statements)
			require.Empty(t, result.Results)
			require.Nil(t, result.Warnings)
			require.Nil(t, result.Infos)
			require.False(t, result.IsPartial)
		})
	}
}

// An instant query may answer a matrix: the type is read from the document,
// never inferred from the request mode.
func TestVictoriaMetricsExecuteInstantQueryReturningMatrix(t *testing.T) {
	address, seen := metricsJSON(t, metricsMatrix)
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: "up[5m]"})
	require.NoError(t, err)
	require.Equal(t, metricsQueryPath, seen.only(t).path)
	require.Equal(t, "matrix", result.ResultType)
	require.Equal(t, `[{"metric":{"job":"api"},"values":[[1435781430,"1"],[1435781445,"2"]]}]`, string(result.Result))
}

// The source's own words about its answer travel beside the data, and a
// partial answer stays the source's word rather than becoming truncation.
func TestVictoriaMetricsExecuteSurfacesWarnings(t *testing.T) {
	body := `{"status":"success","warnings":["the query was rewritten","cardinality limit"],` +
		`"infos":["an info line"],"isPartial":true,` +
		`"data":{"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}]}}`
	address, _ := metricsJSON(t, body)
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
	require.NoError(t, err)
	require.Equal(t, []string{"the query was rewritten", "cardinality limit"}, result.Warnings)
	require.Equal(t, []string{"an info line"}, result.Infos)
	require.True(t, result.IsPartial)
	require.False(t, result.Truncated)
}

// A key the platform does not document is the source's own and is skipped
// rather than refused, wherever it sits.
func TestVictoriaMetricsExecuteSkipsUnknownKeys(t *testing.T) {
	body := `{"stats":{"seriesFetched":"2","nested":{"deep":[1,2,{"x":null}]}},` +
		`"data":{"stats":{"a":1},"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}],"extra":[]},` +
		`"status":"success","trailingExtra":true}`
	address, _ := metricsJSON(t, body)
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
	require.NoError(t, err)
	require.Equal(t, "vector", result.ResultType)
	require.Equal(t, `[{"metric":{},"value":[1,"1"]}]`, string(result.Result))
}

// The sample cap cuts each series where it was reached, keeps the samples
// already read, marks every series it cut and leaves the source's own envelope
// to be read to the end, wherever the status sits.
func TestVictoriaMetricsExecuteSampleCap(t *testing.T) {
	body := `{"data":{"resultType":"matrix","result":[` +
		`{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"],[3,"3"]]},` +
		`{"metric":{"job":"b"},"values":[[1,"1"],[2,"2"],[3,"3"]]},` +
		`{"metric":{"job":"c"},"values":[[1,"1"],[2,"2"],[3,"3"]]}]},` +
		`"warnings":["after the data"],"status":"success"}`
	address, _ := metricsJSON(t, body)
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, MaxRows: 4})
	require.NoError(t, err)
	require.Equal(t, `[{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"],[3,"3"]]},`+
		`{"metric":{"job":"b"},"values":[[1,"1"]],"truncated":true},`+
		`{"metric":{"job":"c"},"values":[],"truncated":true}]`, string(result.Result))
	require.True(t, result.Truncated)
	require.Equal(t, int64(4), result.Rows)
	// The envelope after the data was honoured, which is what proves the
	// decoder kept reading rather than stopping at the cap.
	require.Equal(t, []string{"after the data"}, result.Warnings)
	require.Equal(t, "matrix", result.ResultType)
	// Labels and the kept sample values are what the byte cap counts.
	require.Equal(t, int64(3*len("joba")+4), result.Bytes)
}

// A vector sample is the whole entry, so an entry beyond the cap is dropped
// rather than emitted without the value that made it one.
func TestVictoriaMetricsExecuteSampleCapOnAVector(t *testing.T) {
	address, _ := metricsJSON(t, metricsVector)
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, MaxRows: 1})
	require.NoError(t, err)
	require.Equal(t, `[{"metric":{"job":"api","__name__":"up"},"value":[1435781451.781,"1"]}]`, string(result.Result))
	require.True(t, result.Truncated)
	require.Equal(t, int64(1), result.Rows)
}

// A discovery item is what the caller asked for, so it is kept whole or not
// at all.
func TestVictoriaMetricsExecuteSampleCapOnDiscovery(t *testing.T) {
	address, _ := metricsJSON(t, `{"status":"success","data":["api","web","batch"]}`)
	result, err := metricsExecute(t, address, ExecuteRequest{LabelValues: "job", MaxRows: 2})
	require.NoError(t, err)
	require.Equal(t, `["api","web"]`, string(result.Result))
	require.True(t, result.Truncated)
	require.Equal(t, int64(2), result.Rows)
	require.Equal(t, int64(len("apiweb")), result.Bytes)
}

// The byte cap counts the label and sample text that was kept, so a series of
// long values is cut even when the sample cap is far away.
func TestVictoriaMetricsExecuteByteCap(t *testing.T) {
	address, _ := metricsJSON(t, `{"status":"success","data":{"resultType":"matrix","result":[`+
		`{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"],[3,"3"],[4,"4"]]}]}}`)
	// The labels cost four bytes, so the third sample is the one that passes
	// a cap of five and the fourth is dropped.
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, MaxRows: 1000, MaxBytes: 5})
	require.NoError(t, err)
	require.Equal(t, `[{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"]],"truncated":true}]`, string(result.Result))
	require.True(t, result.Truncated)
	require.Equal(t, int64(2), result.Rows)
}

// Once the byte cap is spent, later series are dropped whole, labels
// included, so a high-cardinality answer cannot grow past the cap by its label
// sets alone; the sample cap alone keeps every series with its labels.
func TestVictoriaMetricsExecuteByteCapDropsLaterSeries(t *testing.T) {
	wide := strings.Repeat("l", 64)
	address, _ := metricsJSON(t, `{"status":"success","data":{"resultType":"matrix","result":[`+
		`{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"]]},`+
		`{"metric":{"job":"`+wide+`"},"values":[[1,"1"]]},`+
		`{"metric":{"job":"`+wide+`"},"values":[[1,"1"]]}]}}`)
	result, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, MaxRows: 1000, MaxBytes: 8})
	require.NoError(t, err)
	// The second series crosses the cap with its labels and keeps them with no
	// samples; the third is dropped whole.
	require.Equal(t, `[{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"]]},`+
		`{"metric":{"job":"`+wide+`"},"values":[],"truncated":true}]`, string(result.Result))
	require.True(t, result.Truncated)
	require.LessOrEqual(t, result.Bytes, int64(8+len(wide)+3), "kept bytes are the cap plus the series that crossed it")

	// The sample cap by itself keeps every later series, labels and all.
	result, err = metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, MaxRows: 2, MaxBytes: 1 << 20})
	require.NoError(t, err)
	require.Equal(t, `[{"metric":{"job":"a"},"values":[[1,"1"],[2,"2"]]},`+
		`{"metric":{"job":"`+wide+`"},"values":[],"truncated":true},`+
		`{"metric":{"job":"`+wide+`"},"values":[],"truncated":true}]`, string(result.Result))
	require.True(t, result.Truncated)
}

// The source's own error wins over a null data member, and a deadline reached
// while an error body is still arriving is the timeout, not a rejection.
func TestVictoriaMetricsExecuteErrorEnvelopeWithNullData(t *testing.T) {
	address, _ := metricsJSON(t, `{"status":"error","errorType":"422","error":"bad query","data":null}`)
	_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "422", rejected.Failure.ErrorType)
	require.Equal(t, "bad query", rejected.Failure.Message)
}

// A body beyond the ceiling is not data: it fails the request rather than
// arriving as an answer the platform never read to the end.
func TestVictoriaMetricsExecuteBodyCeiling(t *testing.T) {
	// The ceiling is four times the byte cap plus one MiB, so a cap of one
	// KiB makes a body of a little over one MiB too large.
	filler := strings.Repeat("x", 1<<20+8<<10)
	address, _ := metricsJSON(t, `{"status":"success","data":{"resultType":"vector","result":[`+
		`{"metric":{"job":"`+filler+`"},"value":[1,"1"]}]}}`)
	_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, MaxBytes: 1 << 10})
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, ResponseTooLarge, rejected.Failure.ErrorType)
	require.NotEmpty(t, rejected.Failure.Message)
	require.Nil(t, rejected.Failure.Statement)
	require.Empty(t, rejected.Failure.SQLState)
	requireNoSentinel(t, rejected.Error(), rejected.Failure.Message)
}

// An answer that is not the source's envelope is a failure of its own: the
// platform never presents half a document as data.
func TestVictoriaMetricsExecuteMalformedBody(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		contentType string
		body        string
	}{
		{"not JSON at all", "text/html", "<html>not a source</html>"},
		{"truncated JSON", "application/json", `{"status":"success","data":{"resultType":"vector","result":[`},
		{"no status", "application/json", `{"data":{"resultType":"vector","result":[]}}`},
		{"unknown status", "application/json", `{"status":"partial","data":{"resultType":"vector","result":[]}}`},
		{"status is not a string", "application/json", `{"status":1,"data":{"resultType":"vector","result":[]}}`},
		{"no data", "application/json", `{"status":"success"}`},
		{"no result type", "application/json", `{"status":"success","data":{"result":[]}}`},
		{"data is a list for a query", "application/json", `{"status":"success","data":["up"]}`},
		{"a second document", "application/json", `{"status":"success","data":{"resultType":"vector","result":[]}}{}`},
		{"a series that is not an object", "application/json",
			`{"status":"success","data":{"resultType":"vector","result":[[1,"1"],[2,"2"]]}}`},
		{"a label value that is not a string", "application/json",
			`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"job":1},"value":[1,"1"]}]}}`},
		{"empty body", "application/json", ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := metricsSource(t, http.StatusOK, testCase.contentType, testCase.body)
			_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
			var rejected *SourceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, MalformedResponse, rejected.Failure.ErrorType)
			require.NotEmpty(t, rejected.Failure.Message)
			requireNoSentinel(t, rejected.Error(), rejected.Failure.Message)
		})
	}
	// A discovery endpoint answering an expression's shape is the same
	// failure: the platform judges the answer against what it asked for.
	address, _ := metricsJSON(t, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	_, err := metricsExecute(t, address, ExecuteRequest{Labels: true})
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, MalformedResponse, rejected.Failure.ErrorType)
}

// The source's own rejection reaches the caller with the source's words, and
// an evaluation the source aborted is the timeout the caller was promised.
func TestVictoriaMetricsExecuteErrorEnvelope(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status int
		body   string
	}{
		{"bad request", http.StatusBadRequest, `{"status":"error","errorType":"bad_data",` +
			`"error":"unsupported operation for ranges"}`},
		{"unprocessable", http.StatusUnprocessableEntity, `{"status":"error","errorType":"bad_data",` +
			`"error":"unsupported operation for ranges"}`},
		// A source that answers 200 and then says it failed is still a failure.
		{"error under a success status", http.StatusOK, `{"status":"error","errorType":"bad_data",` +
			`"error":"unsupported operation for ranges"}`},
		// The status may follow the data the source already streamed.
		{"error after the data", http.StatusOK, `{"data":{"resultType":"vector","result":[]},` +
			`"status":"error","errorType":"bad_data","error":"unsupported operation for ranges"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := metricsSource(t, testCase.status, "application/json", testCase.body)
			_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
			var rejected *SourceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, "bad_data", rejected.Failure.ErrorType)
			require.Equal(t, "unsupported operation for ranges", rejected.Failure.Message)
			require.Nil(t, rejected.Failure.Statement)
			require.Empty(t, rejected.Failure.SQLState)
			requireNoSentinel(t, rejected.Error())
		})
	}
	// The source's own timeout is the platform's timeout, not a rejection to
	// show the caller: the bound it names is the connection's.
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		address, _ := metricsSource(t, status, "application/json",
			`{"status":"error","errorType":"timeout","error":"query timed out after 5s"}`)
		_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression, Timeout: 5 * time.Second})
		require.ErrorIs(t, err, ErrTimeout)
	}
}

// A status without the source's envelope is the status itself: a proxy or a
// gateway in front of the source is not the source.
func TestVictoriaMetricsExecuteNonJSONStatus(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			address, _ := metricsSource(t, status, "text/html", "  upstream connect error  ")
			_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
			var rejected *SourceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, "http_"+fmt.Sprint(status), rejected.Failure.ErrorType)
			require.Equal(t, "upstream connect error", rejected.Failure.Message)
			require.Nil(t, rejected.Failure.Statement)
		})
	}
	// The body text is bounded: a gateway that answers a page cannot fill the
	// caller's response with it.
	address, _ := metricsSource(t, http.StatusInternalServerError, "text/html", strings.Repeat("e", 64<<10))
	_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
	var rejected *SourceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "http_500", rejected.Failure.ErrorType)
	require.Len(t, rejected.Failure.Message, maxMetricsErrorText)
}

// The transport failures keep the categories the probe reports, so a caller
// can tell a refused credential from a source that is not there.
func TestVictoriaMetricsExecuteTransportFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		address, _ := metricsSource(t, status, "application/json", `{"status":"error","errorType":"unauthorized"}`)
		_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
		require.ErrorIs(t, err, ErrAuthRejected, status)
		requireNoSentinel(t, err.Error())
	}

	// A redirect is refused rather than followed: following one would send the
	// secret to a host no administrator configured.
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+metricsQueryPath, http.StatusFound)
	}))
	t.Cleanup(source.Close)
	_, err := metricsExecute(t, source.URL, ExecuteRequest{PromQL: metricsExpression})
	require.ErrorIs(t, err, ErrUnreachable)
	require.Zero(t, destinationCalls.Load())

	// A source that is not listening is unreachable, with no driver or
	// transport text in the failure.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := closed.URL
	closed.Close()
	_, err = metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
	require.ErrorIs(t, err, ErrUnreachable)
	requireNoSentinel(t, err.Error())
}

// stall is a source that never answers. It gives up on its own after the
// supplied time: a server whose handler waits only on the request context
// would hold the test's cleanup open, because a Go server notices a client
// that went away only once it reads from the connection.
func stall(limit time.Duration) http.HandlerFunc {
	return func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(limit):
		case <-r.Context().Done():
		}
	}
}

// A source that stops answering is cut by the request deadline, which is the
// service's backstop, with the same code its own timeout produces.
func TestVictoriaMetricsExecuteRequestDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(stall(2 * time.Second)))
	t.Cleanup(server.Close)
	started := time.Now()
	_, err := victoriaMetrics{}.Execute(probeContext(t, 300*time.Millisecond), metricsTarget(t, server.URL), "",
		ExecuteRequest{PromQL: metricsExpression, Timeout: 30 * time.Second})
	require.ErrorIs(t, err, ErrTimeout)
	require.Less(t, time.Since(started), 3*time.Second)
}

// Without a caller deadline the client's own bound ends it: the connection's
// timeout plus the documented grace, and not a moment of it longer.
func TestVictoriaMetricsExecuteClientDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(stall(auth.MetricsGrace + 2*time.Second)))
	t.Cleanup(server.Close)
	started := time.Now()
	_, err := victoriaMetrics{}.Execute(t.Context(), metricsTarget(t, server.URL), "",
		ExecuteRequest{PromQL: metricsExpression, Timeout: 10 * time.Millisecond})
	elapsed := time.Since(started)
	require.ErrorIs(t, err, ErrTimeout)
	require.GreaterOrEqual(t, elapsed, auth.MetricsGrace)
	require.Less(t, elapsed, auth.MetricsGrace+3*time.Second)
}

// The four authentication methods reach the source exactly as the probe sends
// them, and the secret never appears anywhere else.
func TestVictoriaMetricsExecuteAuthMethods(t *testing.T) {
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
			address, seen := metricsJSON(t, metricsVector)
			target, err := victoriaMetrics{}.ParseTarget(testCase.raw(address))
			require.NoError(t, err)
			require.NoError(t, victoriaMetrics{}.ValidateSecret(target, testCase.secret))
			result, err := victoriaMetrics{}.Execute(probeContext(t, 10*time.Second), target, testCase.secret,
				ExecuteRequest{PromQL: metricsExpression, Timeout: 30 * time.Second})
			require.NoError(t, err)
			require.Equal(t, "vector", result.ResultType)
			testCase.check(t, seen.only(t).headers)
		})
	}
}

// One execution is one request, and the source sees no connection kept open
// on the caller's behalf.
func TestVictoriaMetricsExecuteSendsOneRequest(t *testing.T) {
	address, seen := metricsJSON(t, metricsVector)
	_, err := metricsExecute(t, address, ExecuteRequest{PromQL: metricsExpression})
	require.NoError(t, err)
	require.Equal(t, 1, seen.count())
	require.Equal(t, "close", strings.ToLower(seen.only(t).headers.Get("Connection")))
}

// Neither the secret nor the caller's expression may appear in a failure the
// platform produces: the source's block is the only text that travels, and it
// is the source's own.
func TestVictoriaMetricsExecuteFailuresCarryNoInput(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"source rejection", http.StatusBadRequest, "application/json",
			`{"status":"error","errorType":"bad_data","error":"invalid expression"}`},
		{"gateway text", http.StatusBadGateway, "text/html", "upstream unavailable"},
		{"malformed", http.StatusOK, "application/json", "{"},
		{"refused credentials", http.StatusUnauthorized, "application/json", "{}"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, _ := metricsSource(t, testCase.status, testCase.contentType, testCase.body)
			target, err := victoriaMetrics{}.ParseTarget(map[string]string{keyURL: address, keyAuth: authBearer})
			require.NoError(t, err)
			_, err = victoriaMetrics{}.Execute(probeContext(t, 10*time.Second), target, auth.Secret(sentinel),
				ExecuteRequest{PromQL: metricsExpression, Timeout: 30 * time.Second})
			require.Error(t, err)
			requireNoSentinel(t, err.Error())
			var rejected *SourceError
			if errors.As(err, &rejected) {
				requireNoSentinel(t, rejected.Failure.Message, rejected.Failure.ErrorType)
			}
		})
	}
}

// An input this provider does not take is refused before anything is dialled.
// The service refuses it first, with a hint naming the right input; this is
// the backstop that keeps a missed rule from reaching a source.
func TestVictoriaMetricsExecuteRefusesUnsupportedInput(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		request ExecuteRequest
	}{
		{"sql", ExecuteRequest{SQL: "select 1"}},
		{"sql beside an expression", ExecuteRequest{SQL: "select 1", PromQL: metricsExpression}},
		{"no input at all", ExecuteRequest{}},
		{"only a time", ExecuteRequest{Start: "-1h"}},
		{"two discovery inputs", ExecuteRequest{Labels: true, Series: "up"}},
		{"an expression and a discovery input", ExecuteRequest{PromQL: metricsExpression, Labels: true}},
		{"an instant and a range", ExecuteRequest{PromQL: metricsExpression, At: "now", Start: "-1h"}},
		{"a step without a start", ExecuteRequest{PromQL: metricsExpression, Step: "1m"}},
		{"an end without a start", ExecuteRequest{PromQL: metricsExpression, End: "now"}},
		{"a match on an expression", ExecuteRequest{PromQL: metricsExpression, Match: `{job="api"}`}},
		{"an instant on a discovery input", ExecuteRequest{Labels: true, At: "now"}},
		{"a step on a discovery input", ExecuteRequest{Series: "up", Step: "1m"}},
		{"a label name that is not one", ExecuteRequest{LabelValues: "../secret"}},
		{"a label name with a path separator", ExecuteRequest{LabelValues: "job/values"}},
		{"an empty label name is no input", ExecuteRequest{LabelValues: ""}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, seen := metricsJSON(t, metricsVector)
			_, err := metricsExecute(t, address, testCase.request)
			require.ErrorIs(t, err, ErrUnsupportedInput)
			require.Zero(t, seen.count(), "no source may be contacted for an input the provider does not take")
		})
	}
}

// The decoder is exercised without a server where that is the clearer test:
// the caps, the marks and the counters are decided here.
func TestVictoriaMetricsDecoderBounds(t *testing.T) {
	call := metricsCall{}
	for _, testCase := range []struct {
		name      string
		body      string
		request   ExecuteRequest
		result    string
		rows      int64
		bytes     int64
		truncated bool
	}{
		{
			name: "a series keeps its labels when every sample was cut",
			body: `{"status":"success","data":{"resultType":"matrix","result":[` +
				`{"metric":{"job":"a"},"values":[[1,"1"]]},{"metric":{"job":"b"},"values":[[1,"1"]]}]}}`,
			request:   ExecuteRequest{MaxRows: 1, MaxBytes: 1 << 20},
			result:    `[{"metric":{"job":"a"},"values":[[1,"1"]]},{"metric":{"job":"b"},"values":[],"truncated":true}]`,
			rows:      1,
			bytes:     2*int64(len("joba")) + 1,
			truncated: true,
		},
		{
			name: "a member the platform does not know travels as it is",
			body: `{"status":"success","data":{"resultType":"matrix","result":[` +
				`{"metric":{"job":"a"},"values":[[1,"1"]],"extra":{"b":[1,2]}}]}}`,
			request: ExecuteRequest{MaxRows: 10, MaxBytes: 1 << 20},
			result:  `[{"metric":{"job":"a"},"values":[[1,"1"]],"extra":{"b":[1,2]}}]`,
			rows:    1,
			bytes:   int64(len("joba")) + 1 + int64(len(`{"b":[1,2]}`)),
		},
		{
			name: "a null value list is an empty one",
			body: `{"status":"success","data":{"resultType":"matrix","result":[` +
				`{"metric":null,"values":null}]}}`,
			request: ExecuteRequest{MaxRows: 10, MaxBytes: 1 << 20},
			result:  `[{"metric":{},"values":[]}]`,
		},
		{
			name:    "a null result is an empty one",
			body:    `{"status":"success","data":{"resultType":"vector","result":null}}`,
			request: ExecuteRequest{MaxRows: 10, MaxBytes: 1 << 20},
			result:  `[]`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := metricsBody(strings.NewReader(testCase.body), call, testCase.request)
			require.NoError(t, err)
			require.Equal(t, testCase.result, string(result.Result))
			require.Equal(t, testCase.rows, result.Rows)
			require.Equal(t, testCase.truncated, result.Truncated)
			if testCase.bytes != 0 {
				require.Equal(t, testCase.bytes, result.Bytes)
			}
		})
	}
}

// The ceiling is enforced on the stream rather than after it, so a source that
// never stops writing cannot be read into memory first.
func TestVictoriaMetricsDecoderCeilingIsStreamed(t *testing.T) {
	endless := io.MultiReader(strings.NewReader(`{"status":"success","data":{"resultType":"vector","result":[`),
		&endlessReader{})
	_, err := metricsBody(endless, metricsCall{}, ExecuteRequest{MaxRows: 10, MaxBytes: 1 << 10})
	require.ErrorIs(t, err, errBodyTooLarge)
	require.Equal(t, ResponseTooLarge, metricsBodyError(err).(*SourceError).Failure.ErrorType)
}

// endlessReader stands in for a source that keeps writing well-formed samples.
// It fills whatever it is given, continuing where the last read stopped, so a
// short read never breaks the document in two.
type endlessReader struct{ offset int }

const endlessSample = `{"metric":{},"value":[1,"1"]},`

func (e *endlessReader) Read(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		copied := copy(p[written:], endlessSample[e.offset:])
		written += copied
		e.offset = (e.offset + copied) % len(endlessSample)
	}
	return written, nil
}

// A document nested past the platform's bound is refused rather than driving
// the decoder's recursion.
func TestVictoriaMetricsDecoderRefusesDeepNesting(t *testing.T) {
	depth := 200
	body := `{"status":"success","stats":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) +
		`,"data":{"resultType":"vector","result":[]}}`
	_, err := metricsBody(strings.NewReader(body), metricsCall{}, ExecuteRequest{MaxRows: 10, MaxBytes: 1 << 20})
	require.ErrorIs(t, err, errMalformed)
}
