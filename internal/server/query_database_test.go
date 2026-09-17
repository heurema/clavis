package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/auth"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
)

// The query route end to end against PostgreSQL through the real store: the
// bodies are the DTOs the CLI marshals, and the smoke database is also the
// external source, exactly as the connection round trip does it.
func TestRealHTTPQueryRouteRoundTrip(t *testing.T) {
	pool, path, password := serverDatabase(t)
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	local, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionIdleTimeout, auth.DefaultSessionMaxLifetime)
	require.NoError(t, err)
	service := local.WithKeyring(serverTestKeyring(t))
	_, isExecutor := any(service).(auth.QueryExecutor)
	require.True(t, isExecutor, "the store value must satisfy the executor contract")
	handler, err := HandlerWithAuth(time.Second, checker, service, service, service, service, service, service, service,
		"http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	body := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		require.NoError(t, err)
		return string(data)
	}
	login := func(username string, secret auth.Secret) http.Header {
		t.Helper()
		response := requestAuth(handler, "POST", auth.LoginPath, body(auth.LoginRequest{Username: username, Password: secret}),
			http.Header{"Content-Type": {"application/json"}})
		require.Equal(t, 200, response.Code)
		var issued auth.LoginResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &issued))
		return http.Header{"Authorization": {"Bearer " + string(issued.Token)}, "Accept": {"application/json"}}
	}
	send := func(headers http.Header, method, route, payload string) *httptest.ResponseRecorder {
		t.Helper()
		request := headers.Clone()
		if payload != "" {
			request.Set("Content-Type", "application/json")
		}
		result := requestAuth(handler, method, route, payload, request)
		require.Equal(t, "no-store", result.Header().Get("Cache-Control"))
		return result
	}
	rows := func(table string) int {
		t.Helper()
		var count int
		require.NoError(t, pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count))
		return count
	}
	admin := login("personal-admin", password)
	memberPassword := auth.Secret("member-password-fixture-1")
	response := send(admin, "POST", auth.UsersPath, body(auth.CreateUserRequest{Username: "alice", Password: memberPassword}))
	require.Equal(t, 201, response.Code)
	target, secret := probeTarget(t)
	response = send(admin, "POST", auth.ConnectionsPath, body(auth.CreateConnectionRequest{
		Name: "ledger-primary", Provider: auth.ProviderPostgreSQL, Target: target, Labels: map[string]string{}, Secret: secret,
		MaxRows: 50,
	}))
	require.Equal(t, 201, response.Code)
	// The metrics half of the round trip: a fake source, reached over the wire
	// under the connection's own bounds exactly as a real one would be.
	source := newFakeMetrics(t)
	response = send(admin, "POST", auth.ConnectionsPath, body(auth.CreateConnectionRequest{
		Name: "metrics-eu", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": source.url, "auth": "none"}, Labels: map[string]string{}, MaxRows: 2,
	}))
	require.Equal(t, 201, response.Code)
	// A second metrics connection nobody grants the member, so an ungranted
	// connection stays indistinguishable from an absent one.
	response = send(admin, "POST", auth.ConnectionsPath, body(auth.CreateConnectionRequest{
		Name: "metrics-us", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": source.url, "auth": "none"}, Labels: map[string]string{},
	}))
	require.Equal(t, 201, response.Code)
	response = send(admin, "POST", auth.GrantsPath, body(auth.GrantRequest{User: "alice", Connection: "metrics-eu"}))
	require.Equal(t, 201, response.Code)
	response = send(admin, "POST", auth.GrantsPath, body(auth.GrantRequest{User: "alice", Connection: "ledger-primary"}))
	require.Equal(t, 201, response.Code)
	member := login("alice", memberPassword)
	before := []int{rows("users"), rows("sessions"), rows("connections"), rows("grants")}

	// A script runs as one implicit transaction and answers a list.
	query := func(headers http.Header, request auth.QueryRequest) *httptest.ResponseRecorder {
		t.Helper()
		return send(headers, "POST", auth.QueryPath, body(request))
	}
	response = query(member, auth.QueryRequest{Connection: "ledger-primary",
		SQL: "create temp table script as select generate_series(1, 3) as n; select n, null::text as missing from script order by n;"})
	require.Equal(t, 200, response.Code, response.Body.String())
	var result auth.QueryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.Len(t, result.Results, 2)
	require.Equal(t, "SELECT", result.Results[0].Command)
	require.Empty(t, result.Results[0].Rows)
	require.Equal(t, []auth.QueryColumn{{Name: "n", Type: "int4"}, {Name: "missing", Type: "text"}}, result.Results[1].Columns)
	require.Len(t, result.Results[1].Rows, 3)
	require.Equal(t, "2", *result.Results[1].Rows[1][0])
	require.Nil(t, result.Results[1].Rows[1][1])
	require.False(t, result.Truncated)
	require.Contains(t, response.Body.String(), `"rows":[]`, "statements without rows keep an empty list")

	// The row cap is the connection's, lowered per request, and drains.
	response = query(admin, auth.QueryRequest{Connection: "ledger-primary", SQL: "select generate_series(1, 200)", MaxRows: 5})
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.Len(t, result.Results[0].Rows, 5)
	require.True(t, result.Results[0].Truncated)
	require.True(t, result.Truncated)
	response = query(admin, auth.QueryRequest{Connection: "ledger-primary", SQL: "select 1", MaxRows: 51})
	require.Equal(t, 400, response.Code)
	require.Contains(t, response.Body.String(), "INVALID_ARGUMENT")
	require.Contains(t, response.Body.String(), "50")

	// Failures are distinguishable and carry the source's own text.
	response = query(member, auth.QueryRequest{Connection: "ledger-primary", SQL: "select 1; select nothing from missing_relation_sentinel;"})
	require.Equal(t, 422, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, auth.SourceError, failure.Error.Code)
	require.NotNil(t, failure.Source)
	require.Equal(t, "42P01", failure.Source.SQLState)
	require.NotNil(t, failure.Source.Statement)
	require.Equal(t, 1, *failure.Source.Statement)
	require.Contains(t, failure.Source.Message, "missing_relation_sentinel")
	response = query(member, auth.QueryRequest{Connection: "ledger-primary", SQL: "selec 1"})
	require.Equal(t, 422, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, "42601", failure.Source.SQLState)
	require.NotNil(t, failure.Source.Statement)
	require.Equal(t, 0, *failure.Source.Statement)
	require.Positive(t, failure.Source.Position)

	// Authorization and provider refusals never reach a source.
	response = query(member, auth.QueryRequest{Connection: "metrics-us", PromQL: "up"})
	require.Equal(t, 404, response.Code)
	require.Contains(t, response.Body.String(), auth.ConnectionNotFound)
	response = query(admin, auth.QueryRequest{Connection: "metrics-eu", SQL: "select 1"})
	require.Equal(t, 400, response.Code)
	require.Contains(t, response.Body.String(), auth.InvalidArgument)
	require.Contains(t, response.Body.String(), "victoriametrics")
	response = query(admin, auth.QueryRequest{Connection: "ledger-primary", PromQL: "up"})
	require.Equal(t, 400, response.Code)
	require.Contains(t, response.Body.String(), auth.InvalidArgument)
	require.Contains(t, response.Body.String(), "postgresql")

	// A granted member's range query reaches the fake source as submitted and
	// comes back as the source's own matrix, cut at the connection's cap.
	source.reply(`{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"job":"api"},"values":[[1,"1"],[2,"2"],[3,"3"]]}]}}`)
	response = query(member, auth.QueryRequest{Connection: "metrics-eu", PromQL: "up", Start: "-1h", End: "now", Step: "1m"})
	require.Equal(t, 200, response.Code, response.Body.String())
	// A fresh value each time: a document decoded over another would inherit
	// the members the new one leaves out, which is the very thing under test.
	var metrics auth.QueryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metrics))
	require.Equal(t, auth.ProviderVictoriaMetrics, metrics.Provider)
	require.Equal(t, "matrix", metrics.ResultType)
	require.JSONEq(t, `[{"metric":{"job":"api"},"values":[[1,"1"],[2,"2"]],"truncated":true}]`, string(metrics.Result))
	require.True(t, metrics.Truncated)
	require.Empty(t, metrics.Results)
	call := source.last(t)
	require.Equal(t, "/api/v1/query_range", call.path)
	require.Equal(t, []string{"up"}, call.values["query"])
	require.Equal(t, []string{"-1h"}, call.values["start"])
	require.Equal(t, []string{"now"}, call.values["end"])
	require.Equal(t, []string{"1m"}, call.values["step"])

	// Discovery is the same request with a different endpoint, and the source's
	// own rejection keeps its own classification with no statement index.
	source.reply(`{"status":"success","data":["up","go_info"]}`)
	response = query(member, auth.QueryRequest{Connection: "metrics-eu", LabelValues: "__name__", Match: `{job="api"}`})
	require.Equal(t, 200, response.Code, response.Body.String())
	metrics = auth.QueryResponse{}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metrics))
	require.Equal(t, "labelValues", metrics.ResultType)
	require.JSONEq(t, `["up","go_info"]`, string(metrics.Result))
	require.Equal(t, "/api/v1/label/__name__/values", source.last(t).path)
	source.reply(`{"status":"error","errorType":"bad_data","error":"unparsed data in metrics_sentinel"}`)
	response = query(member, auth.QueryRequest{Connection: "metrics-eu", PromQL: "metrics_sentinel ~~"})
	require.Equal(t, 422, response.Code)
	var rejected auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &rejected))
	require.Equal(t, auth.SourceError, rejected.Error.Code)
	require.Equal(t, "bad_data", rejected.Source.ErrorType)
	require.Contains(t, rejected.Source.Message, "metrics_sentinel")
	require.Nil(t, rejected.Source.Statement, "a metrics source has no statements")
	require.Empty(t, rejected.Source.SQLState)
	response = send(admin, "POST", strings.Replace(auth.ConnectionDisablePath, "{connectionID}", "ledger-primary", 1), "")
	require.Equal(t, 200, response.Code)
	response = query(member, auth.QueryRequest{Connection: "ledger-primary", SQL: "select 1"})
	require.Equal(t, 409, response.Code)
	require.Contains(t, response.Body.String(), auth.ConnectionDisabled)
	response = send(admin, "POST", strings.Replace(auth.ConnectionEnablePath, "{connectionID}", "ledger-primary", 1), "")
	require.Equal(t, 200, response.Code)
	response = send(admin, "POST", auth.GrantRevokePath, body(auth.GrantRequest{User: "alice", Connection: "ledger-primary"}))
	require.Equal(t, 200, response.Code)
	response = query(member, auth.QueryRequest{Connection: "ledger-primary", SQL: "select 1"})
	require.Equal(t, 404, response.Code, "revocation takes effect on the next request")

	// The statement timeout is PostgreSQL's own and outlives the five-second
	// operation deadline of the other routes.
	response = send(admin, "POST", strings.Replace(auth.ConnectionUpdatePath, "{connectionID}", "ledger-primary", 1),
		body(auth.UpdateConnectionRequest{StatementTimeoutMS: intPointer(1000)}))
	require.Equal(t, 200, response.Code, response.Body.String())
	started := time.Now()
	response = query(admin, auth.QueryRequest{Connection: "ledger-primary", SQL: "select pg_sleep(2)"})
	require.Equal(t, 504, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), auth.SourceTimeout)
	require.Less(t, time.Since(started), 10*time.Second)
	response = send(admin, "POST", strings.Replace(auth.ConnectionUpdatePath, "{connectionID}", "ledger-primary", 1),
		body(auth.UpdateConnectionRequest{StatementTimeoutMS: intPointer(7000)}))
	require.Equal(t, 200, response.Code, response.Body.String())
	started = time.Now()
	response = query(admin, auth.QueryRequest{Connection: "ledger-primary", SQL: "select pg_sleep(6)"})
	require.Equal(t, 200, response.Code, "a statement longer than the operation deadline still completes")
	// pg_sleep's granularity can undershoot by a few tens of milliseconds;
	// what matters is that the wait outlived the shared five-second bound.
	require.Greater(t, time.Since(started), auth.OperationTimeout)

	// Nothing in the platform database changed because of any execution; the
	// grant revocation above is the only administrative change since.
	before[3]--
	require.Equal(t, before, []int{rows("users"), rows("sessions"), rows("connections"), rows("grants")})
	require.NotContains(t, response.Body.String(), string(secret))
}

func intPointer(value int) *int { return &value }

// fakeMetrics is an external metrics source for the round trip: it records
// every request as it arrived and answers whatever the test set, so the whole
// path from the route through the service and the provider is exercised
// without a container.
type fakeMetrics struct {
	url   string
	mu    sync.Mutex
	calls []metricsCall
	body  string
}

type metricsCall struct {
	path   string
	values url.Values
}

func newFakeMetrics(t *testing.T) *fakeMetrics {
	t.Helper()
	source := &fakeMetrics{body: `{"status":"success","data":{"resultType":"vector","result":[]}}`}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		source.mu.Lock()
		source.calls = append(source.calls, metricsCall{r.URL.Path, r.Form})
		body := source.body
		source.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	source.url = server.URL
	return source
}

func (f *fakeMetrics) reply(body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = body
}

func (f *fakeMetrics) last(t *testing.T) metricsCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.calls)
	return f.calls[len(f.calls)-1]
}
