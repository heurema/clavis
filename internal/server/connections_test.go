package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/secrets"
	"github.com/stretchr/testify/require"
)

// fakeConnections records exactly what each route handed the service, so a
// rejected request can be proven never to have reached it. It is embedded in
// backendFixture, which supplies the session and the event recorder.
type fakeConnections struct {
	connectionList     auth.ConnectionList
	connectionRecord   auth.Connection
	connectionMutation auth.ConnectionMutation
	connectionDeletion auth.ConnectionDeletion
	connectionCheck    auth.ConnectionCheck
	connectionErr      error
	connectionCalls    []connectionCall
	connectionBlock    func(context.Context)
}

type connectionCall struct {
	operation, target string
	create            auth.CreateConnectionRequest
	update            auth.UpdateConnectionRequest
	secret            auth.Secret
	enabled, dryRun   bool
	terms             []auth.SelectorTerm
	limit             int
}

func (f *fakeConnections) connectionCall(ctx context.Context, call connectionCall) {
	f.connectionCalls = append(f.connectionCalls, call)
	if f.connectionBlock != nil {
		f.connectionBlock(ctx)
	}
}

func (f *fakeConnections) ListConnections(ctx context.Context, _ auth.Session, terms []auth.SelectorTerm, limit int) (auth.ConnectionList, error) {
	f.connectionCall(ctx, connectionCall{operation: "list", terms: terms, limit: limit})
	return f.connectionList, f.connectionErr
}

func (f *fakeConnections) GetConnection(ctx context.Context, _ auth.Session, ref string) (auth.Connection, error) {
	f.connectionCall(ctx, connectionCall{operation: "get", target: ref})
	return f.connectionRecord, f.connectionErr
}

func (f *fakeConnections) CreateConnection(ctx context.Context, _ auth.Session, request auth.CreateConnectionRequest, dryRun bool) (auth.ConnectionMutation, error) {
	f.connectionCall(ctx, connectionCall{operation: "create", create: request, dryRun: dryRun})
	return f.connectionMutation, f.connectionErr
}

func (f *fakeConnections) UpdateConnection(ctx context.Context, _ auth.Session, ref string, request auth.UpdateConnectionRequest, dryRun bool) (auth.ConnectionMutation, error) {
	f.connectionCall(ctx, connectionCall{operation: "update", target: ref, update: request, dryRun: dryRun})
	return f.connectionMutation, f.connectionErr
}

func (f *fakeConnections) SetConnectionCredentials(ctx context.Context, _ auth.Session, ref string, secret auth.Secret, dryRun bool) (auth.ConnectionMutation, error) {
	f.connectionCall(ctx, connectionCall{operation: "credentials", target: ref, secret: secret, dryRun: dryRun})
	return f.connectionMutation, f.connectionErr
}

func (f *fakeConnections) SetConnectionEnabled(ctx context.Context, _ auth.Session, ref string, enabled, dryRun bool) (auth.ConnectionMutation, error) {
	f.connectionCall(ctx, connectionCall{operation: "enabled", target: ref, enabled: enabled, dryRun: dryRun})
	return f.connectionMutation, f.connectionErr
}

func (f *fakeConnections) DeleteConnection(ctx context.Context, _ auth.Session, ref string, dryRun bool) (auth.ConnectionDeletion, error) {
	f.connectionCall(ctx, connectionCall{operation: "delete", target: ref, dryRun: dryRun})
	return f.connectionDeletion, f.connectionErr
}

func (f *fakeConnections) CheckConnection(ctx context.Context, _ auth.Session, ref string) (auth.ConnectionCheck, error) {
	f.connectionCall(ctx, connectionCall{operation: "check", target: ref})
	return f.connectionCheck, f.connectionErr
}

const (
	connectionTargetID   = "abcdefab-1234-4234-8234-1234567890c1"
	connectionTargetName = "warehouse-primary"
	connectionSecret     = "SENTINEL_PRIVATE_SECRET"
)

var (
	connectionTime   = time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	connectionRecord = auth.Connection{
		ID: connectionTargetID, Name: connectionTargetName, Title: "Warehouse",
		Description: "primary ledger", Scope: "read only", Provider: auth.ProviderPostgreSQL,
		Target: map[string]string{"url": "postgres://reader@db.invalid:5432/ledger"},
		Labels: map[string]string{"env": "prod"}, Enabled: true,
		StatementTimeoutMS: 30000, MaxRows: 1000, MaxBytes: 1 << 20,
		CreatedAt: connectionTime, UpdatedAt: connectionTime,
	}
	connectionMutation = auth.ConnectionMutation{Connection: connectionRecord}
	connectionDeletion = auth.ConnectionDeletion{ID: connectionTargetID, Name: connectionTargetName, Deleted: true}
	connectionChecked  = auth.ConnectionCheck{Connection: connectionRecord,
		Check: auth.CheckResult{Outcome: auth.CheckReachable, CheckedAt: connectionTime}}
	connectionListing = auth.ConnectionList{Connections: []auth.Connection{connectionRecord}, Truncated: true}
)

// The create body is the exact projection the CLI marshals: every member of
// the request DTO, including the zero bounds and the secret.
const (
	validConnectionBody = `{"name":"warehouse-primary","title":"Warehouse","description":"primary ledger",` +
		`"scope":"read only","provider":"postgresql","target":{"url":"postgres://reader@db.invalid:5432/ledger"},` +
		`"labels":{"env":"prod"},"statementTimeoutMs":30000,"maxRows":1000,"maxBytes":1048576,` +
		`"secret":"` + connectionSecret + `"}`
	validUpdateBody      = `{"title":"Warehouse","maxRows":500}`
	validCredentialsBody = `{"secret":"` + connectionSecret + `"}`
)

func connectionPath(pattern string) string {
	return strings.Replace(pattern, "{connectionID}", connectionTargetName, 1)
}

// connectionRoute is the design's route table expressed once: every test below
// walks all nine routes rather than a representative subset.
type connectionRoute struct {
	name, method, path, body, operation string
	success                             int
	action                              auth.EventAction
	expected                            any
	dryRunnable                         bool
}

func connectionRoutes() []connectionRoute {
	return []connectionRoute{
		{"list", "GET", auth.ConnectionsPath, "", "list", 200, auth.EventConnectionsList, connectionListing, false},
		{"create", "POST", auth.ConnectionsPath, validConnectionBody, "create", 201, auth.EventConnectionCreate, connectionRecord, true},
		{"get", "GET", connectionPath(auth.ConnectionPath), "", "get", 200, auth.EventConnectionGet, connectionRecord, false},
		{"update", "POST", connectionPath(auth.ConnectionUpdatePath), validUpdateBody, "update", 200, auth.EventConnectionUpdate, connectionMutation, true},
		{"credentials", "POST", connectionPath(auth.ConnectionCredentialsPath), validCredentialsBody, "credentials", 200, auth.EventConnectionSecrets, connectionMutation, true},
		{"enable", "POST", connectionPath(auth.ConnectionEnablePath), "", "enabled", 200, auth.EventConnectionEnable, connectionMutation, true},
		{"disable", "POST", connectionPath(auth.ConnectionDisablePath), "", "enabled", 200, auth.EventConnectionDisable, connectionMutation, true},
		{"delete", "POST", connectionPath(auth.ConnectionDeletePath), "", "delete", 200, auth.EventConnectionDelete, connectionDeletion, true},
		{"check", "POST", connectionPath(auth.ConnectionCheckPath), "", "check", 200, auth.EventConnectionCheck, connectionChecked, false},
	}
}

func (route connectionRoute) headers() http.Header {
	headers := bearerHeaders()
	if route.body != "" {
		headers.Set("Content-Type", "application/json")
	}
	return headers
}

func connectionFixture(t *testing.T) (*backendFixture, http.Handler) {
	t.Helper()
	f := &backendFixture{}
	f.connectionList, f.connectionRecord = connectionListing, connectionRecord
	f.connectionMutation, f.connectionDeletion, f.connectionCheck = connectionMutation, connectionDeletion, connectionChecked
	return f, authHandler(t, f, nil, "http://127.0.0.1")
}

func TestConnectionRoutesReturnDocumentedSuccessBodies(t *testing.T) {
	for _, route := range connectionRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := connectionFixture(t)
			// Browser negotiation headers must never turn a JSON route into a
			// document or a redirect.
			headers := route.headers()
			headers.Set("Accept", "text/html")
			headers.Set("Hx-Request", "true")
			response := requestAuth(handler, route.method, route.path, route.body, headers)
			require.Equal(t, route.success, response.Code)
			require.Equal(t, "application/json", response.Header().Get("Content-Type"))
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.Empty(t, response.Header().Get("Location"))
			require.Empty(t, response.Header().Get("Set-Cookie"))
			expected, err := json.Marshal(route.expected)
			require.NoError(t, err)
			require.JSONEq(t, string(expected), response.Body.String())
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Len(t, f.connectionCalls, 1)
			require.Equal(t, route.operation, f.connectionCalls[0].operation)
			require.False(t, f.connectionCalls[0].dryRun)
			require.Empty(t, f.events, "a service-owned outcome must not be recorded again by the adapter")
		})
	}
}

func TestConnectionRoutesHandTheServiceExactlyWhatWasAsked(t *testing.T) {
	f, handler := connectionFixture(t)
	for _, tc := range []struct {
		method, path, body string
	}{
		{"GET", auth.ConnectionsPath + "?selector=env%3Dprod%2Cteam%2Cservice%21%3Dlegacy&limit=7", ""},
		{"POST", auth.ConnectionsPath, validConnectionBody},
		{"GET", connectionPath(auth.ConnectionPath), ""},
		{"POST", connectionPath(auth.ConnectionUpdatePath), validUpdateBody},
		{"POST", connectionPath(auth.ConnectionCredentialsPath), validCredentialsBody},
		{"POST", connectionPath(auth.ConnectionEnablePath), ""},
		{"POST", connectionPath(auth.ConnectionDisablePath), ""},
	} {
		headers := bearerHeaders()
		if tc.body != "" {
			headers.Set("Content-Type", "application/json")
		}
		require.Less(t, requestAuth(handler, tc.method, tc.path, tc.body, headers).Code, 300, tc.path)
	}
	title, rows := "Warehouse", 500
	require.Equal(t, []connectionCall{
		{operation: "list", limit: 7, terms: []auth.SelectorTerm{
			{Key: "env", Op: auth.SelectorEquals, Value: "prod"},
			{Key: "team", Op: auth.SelectorExists},
			{Key: "service", Op: auth.SelectorNotEquals, Value: "legacy"},
		}},
		{operation: "create", create: auth.CreateConnectionRequest{
			Name: connectionTargetName, Title: "Warehouse", Description: "primary ledger", Scope: "read only",
			Provider: auth.ProviderPostgreSQL, Target: map[string]string{"url": "postgres://reader@db.invalid:5432/ledger"},
			Labels: map[string]string{"env": "prod"}, StatementTimeoutMS: 30000, MaxRows: 1000, MaxBytes: 1 << 20,
			Secret: connectionSecret,
		}},
		{operation: "get", target: connectionTargetName},
		{operation: "update", target: connectionTargetName, update: auth.UpdateConnectionRequest{Title: &title, MaxRows: &rows}},
		{operation: "credentials", target: connectionTargetName, secret: connectionSecret},
		{operation: "enabled", target: connectionTargetName, enabled: true},
		{operation: "enabled", target: connectionTargetName, enabled: false},
	}, f.connectionCalls)
	// A missing limit asks for the documented bound, not for nothing.
	f, handler = connectionFixture(t)
	require.Equal(t, 200, requestAuth(handler, "GET", auth.ConnectionsPath, "", bearerHeaders()).Code)
	require.Equal(t, auth.MaxConnectionListing, f.connectionCalls[0].limit)
	require.Nil(t, f.connectionCalls[0].terms)
	// A UUID reference reaches the service unchanged.
	f, handler = connectionFixture(t)
	path := strings.Replace(auth.ConnectionCheckPath, "{connectionID}", connectionTargetID, 1)
	require.Equal(t, 200, requestAuth(handler, "POST", path, "", bearerHeaders()).Code)
	require.Equal(t, connectionTargetID, f.connectionCalls[0].target)
}

func TestConnectionDryRunIsRequestedExplicitlyAndMarksTheResult(t *testing.T) {
	for _, route := range connectionRoutes() {
		if !route.dryRunnable {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			f, handler := connectionFixture(t)
			f.connectionMutation.DryRun, f.connectionDeletion.DryRun = true, true
			response := requestAuth(handler, route.method, route.path+"?dryRun=true", route.body, route.headers())
			// A dry-run creation answers 200 with the mutation it would have
			// made rather than 201 with a record that does not exist.
			require.Equal(t, 200, response.Code)
			require.Len(t, f.connectionCalls, 1)
			require.True(t, f.connectionCalls[0].dryRun)
			require.Contains(t, response.Body.String(), `"dryRun":true`)
			require.Empty(t, f.events)
			var expected any = f.connectionMutation
			if route.name == "delete" {
				expected = f.connectionDeletion
			}
			encoded, err := json.Marshal(expected)
			require.NoError(t, err)
			require.JSONEq(t, string(encoded), response.Body.String())
		})
	}
}

// A probe that answers "no" is a result, not a failure: the route returns 200
// with the stored outcome exactly as the service reported it.
func TestConnectionCheckReportsAFailedProbeAsASuccessfulRequest(t *testing.T) {
	for _, outcome := range []auth.CheckOutcome{auth.CheckReachable, auth.CheckAuthRejected, auth.CheckUnreachable} {
		f, handler := connectionFixture(t)
		f.connectionCheck = auth.ConnectionCheck{Connection: connectionRecord,
			Check: auth.CheckResult{Outcome: outcome, CheckedAt: connectionTime}}
		response := requestAuth(handler, "POST", connectionPath(auth.ConnectionCheckPath), "", bearerHeaders())
		require.Equal(t, 200, response.Code)
		var decoded auth.ConnectionCheck
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
		require.Equal(t, outcome, decoded.Check.Outcome)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Empty(t, f.events)
	}
}

// The routes field is the design's per-route error column: a nil list means
// every route, and a named list keeps undocumented pairings out of the
// asserted contract. The hint is the service's, passed through unchanged.
func TestConnectionServiceFailuresUseDocumentedStatusesAndHints(t *testing.T) {
	const existsHint = "A connection named like that exists; use `clavis connections update` to change it or choose another name."
	for _, tc := range []struct {
		err    error
		status int
		code   string
		hint   string
		routes []string
	}{
		{&auth.Error{Code: auth.Unauthenticated}, 401, auth.Unauthenticated, "", nil},
		{&auth.Error{Code: auth.Forbidden}, 403, auth.Forbidden, "", nil},
		{&auth.Error{Code: auth.InvalidArgument, Hint: "The title is 1 to 128 characters."}, 400,
			auth.InvalidArgument, "The title is 1 to 128 characters.", []string{"create", "update", "credentials"}},
		{&auth.Error{Code: auth.ConnectionNotFound, Hint: "Use `clavis connections list` to find the connection."}, 404,
			auth.ConnectionNotFound, "Use `clavis connections list` to find the connection.",
			[]string{"get", "update", "credentials", "enable", "disable", "delete", "check"}},
		{&auth.Error{Code: auth.ConnectionExists, Hint: existsHint}, 409, auth.ConnectionExists, existsHint,
			[]string{"create", "update"}},
		{&auth.Error{Code: auth.ConnectionInUse, Hint: "Disable the connection first."}, 409, auth.ConnectionInUse,
			"Disable the connection first.", []string{"delete"}},
		{&auth.Error{Code: auth.CredentialsUnavailable, Hint: "Replace the connection's credentials."}, 409,
			auth.CredentialsUnavailable, "Replace the connection's credentials.", []string{"check"}},
		{&auth.Error{Code: platform.CodeSetupRequired}, 503, platform.CodeSetupRequired, "", nil},
		{errors.New("SENTINEL_PRIVATE_DRIVER"), 503, auth.ServiceUnavailable, "", nil},
	} {
		for _, route := range connectionRoutes() {
			if len(tc.routes) != 0 && !slices.Contains(tc.routes, route.name) {
				continue
			}
			t.Run(tc.code+"/"+route.name, func(t *testing.T) {
				f, handler := connectionFixture(t)
				f.connectionErr = tc.err
				response := requestAuth(handler, route.method, route.path, route.body, route.headers())
				require.Equal(t, tc.status, response.Code)
				var failure auth.ErrorResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
				require.Equal(t, tc.code, failure.Error.Code)
				require.Equal(t, tc.hint, failure.Error.Hint)
				require.NotContains(t, response.Body.String(), "SENTINEL")
				require.NotContains(t, response.Body.String(), connectionTargetName)
				require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				require.Len(t, f.connectionCalls, 1)
				require.Empty(t, f.events, "a service-owned denial is never recorded twice")
			})
		}
	}
}

func TestConnectionRoutesRequireBearerCredentials(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		status  int
		outcome auth.EventOutcome
	}{
		{"cookie only", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 401, auth.OutcomeUnauthenticated},
		{"no credentials", http.Header{}, 401, auth.OutcomeUnauthenticated},
		{"bearer and cookie", http.Header{"Authorization": {"Bearer " + string(fixtureToken)},
			"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 400, auth.OutcomeInvalidArgument},
		{"foreign origin", http.Header{"Authorization": {"Bearer " + string(fixtureToken)},
			"Origin": {"https://attacker.invalid"}}, 403, auth.OutcomeForbidden},
	} {
		for _, route := range connectionRoutes() {
			t.Run(tc.name+"/"+route.name, func(t *testing.T) {
				f, handler := connectionFixture(t)
				headers := tc.headers.Clone()
				headers.Set("Accept", "text/html")
				if route.body != "" {
					headers.Set("Content-Type", "application/json")
				}
				response := requestAuth(handler, route.method, route.path, route.body, headers)
				require.Equal(t, tc.status, response.Code)
				require.Equal(t, "application/json", response.Header().Get("Content-Type"))
				require.Empty(t, response.Header().Get("Location"))
				require.Empty(t, response.Header().Get("Set-Cookie"))
				require.NotContains(t, response.Body.String(), "SENTINEL")
				require.Empty(t, f.connectionCalls, "no operation may reach the service")
				require.Equal(t, []auth.Event{{Action: route.action, Outcome: tc.outcome}}, f.events)
			})
		}
	}
}

func TestConnectionBodiesAreStrictAndUnreflected(t *testing.T) {
	trim := func(body string) string { return strings.TrimSuffix(body, "}") }
	bodies := map[string][]string{
		"create": {
			trim(validConnectionBody) + `,"extra":"x"}`,
			validConnectionBody + ` {}`,
			trim(validConnectionBody) + `,"name":"other"}`,
			strings.Replace(validConnectionBody, `"name"`, `"Name"`, 1),
			strings.Replace(validConnectionBody, `"secret":"`+connectionSecret+`"`, `"secret":null`, 1),
			strings.Replace(validConnectionBody, `"target":{"url":"postgres://reader@db.invalid:5432/ledger"}`, `"target":[]`, 1),
			strings.Replace(validConnectionBody, `"labels":{"env":"prod"}`, `"labels":{"env":1}`, 1),
			strings.Replace(validConnectionBody, `"labels":{"env":"prod"}`, `"labels":{"env":"a","env":"b"}`, 1),
			strings.Replace(validConnectionBody, `"maxRows":1000`, `"maxRows":"1000"`, 1),
			strings.Replace(validConnectionBody, `"maxRows":1000`, `"maxRows":10.5`, 1),
			strings.Replace(validConnectionBody, `"secret":"`+connectionSecret+`"`,
				`"secret":"`+strings.Repeat("s", auth.MaxSecretBytes+1)+`"`, 1),
			`[]`,
			`{}` + strings.Repeat(" ", auth.MaxCredentialBody),
		},
		"update": {
			`{}`,
			trim(validUpdateBody) + `,"extra":"x"}`,
			validUpdateBody + ` {}`,
			`{"title":"a","title":"b"}`,
			`{"provider":"postgresql"}`,
			`{"secret":"` + connectionSecret + `"}`,
			`{"target":[]}`,
			`{"maxRows":"5"}`,
			`{"title":null}`,
		},
		"credentials": {
			`{}`,
			trim(validCredentialsBody) + `,"extra":"x"}`,
			validCredentialsBody + ` {}`,
			`{"secret":"a","secret":"b"}`,
			`{"Secret":"` + connectionSecret + `"}`,
			`{"secret":null}`,
			`{"secret":"` + strings.Repeat("s", auth.MaxSecretBytes+1) + `"}`,
		},
	}
	for _, route := range connectionRoutes() {
		for index, body := range bodies[route.name] {
			t.Run(route.name+"/"+strconv.Itoa(index), func(t *testing.T) {
				f, handler := connectionFixture(t)
				response := requestAuth(handler, route.method, route.path, body, bearerHeaders("Content-Type", "application/json"))
				require.Equal(t, 400, response.Code)
				require.Contains(t, response.Body.String(), auth.InvalidArgument)
				require.NotContains(t, response.Body.String(), "SENTINEL")
				require.NotContains(t, response.Body.String(), connectionTargetName)
				require.Empty(t, f.connectionCalls, "an invalid body must never reach the service")
				require.Equal(t, []auth.Event{{Action: route.action, Outcome: auth.OutcomeInvalidArgument}}, f.events)
			})
		}
	}
	// The one hint this adapter owns: an update that asks for nothing.
	f, handler := connectionFixture(t)
	response := requestAuth(handler, "POST", connectionPath(auth.ConnectionUpdatePath), `{}`,
		bearerHeaders("Content-Type", "application/json"))
	require.Equal(t, 400, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, hintEmptyUpdate, failure.Error.Hint)
	require.Empty(t, f.connectionCalls)

	// Wrong or absent content types, and bodies on the routes that take none.
	for _, tc := range []struct {
		name, method, path, body, contentType string
		action                                auth.EventAction
	}{
		{"form create", "POST", auth.ConnectionsPath, "name=warehouse-primary&secret=" + connectionSecret,
			"application/x-www-form-urlencoded", auth.EventConnectionCreate},
		{"typeless create", "POST", auth.ConnectionsPath, validConnectionBody, "", auth.EventConnectionCreate},
		{"form credentials", "POST", connectionPath(auth.ConnectionCredentialsPath), "secret=" + connectionSecret,
			"application/x-www-form-urlencoded", auth.EventConnectionSecrets},
		{"listing body", "GET", auth.ConnectionsPath, `{"connections":[]}`, "application/json", auth.EventConnectionsList},
		{"record body", "GET", connectionPath(auth.ConnectionPath), `{}`, "application/json", auth.EventConnectionGet},
		{"enable body", "POST", connectionPath(auth.ConnectionEnablePath), `{}`, "application/json", auth.EventConnectionEnable},
		{"disable body", "POST", connectionPath(auth.ConnectionDisablePath), `{}`, "application/json", auth.EventConnectionDisable},
		{"delete body", "POST", connectionPath(auth.ConnectionDeletePath), `{}`, "application/json", auth.EventConnectionDelete},
		{"check body", "POST", connectionPath(auth.ConnectionCheckPath), `{}`, "application/json", auth.EventConnectionCheck},
		{"oversized create", "POST", auth.ConnectionsPath,
			trim(validConnectionBody) + `,"description":"` + strings.Repeat("d", auth.MaxCredentialBody) + `"}`,
			"application/json", auth.EventConnectionCreate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := connectionFixture(t)
			headers := bearerHeaders()
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			response := requestAuth(handler, tc.method, tc.path, tc.body, headers)
			require.Equal(t, 400, response.Code)
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Empty(t, f.connectionCalls)
			require.Equal(t, []auth.Event{{Action: tc.action, Outcome: auth.OutcomeInvalidArgument}}, f.events)
		})
	}
}

func TestConnectionQueryParametersAreStrict(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		action                   auth.EventAction
	}{
		{"selector", "GET", auth.ConnectionsPath + "?selector=env%3DPROD", "", auth.EventConnectionsList},
		{"selector terms", "GET", auth.ConnectionsPath + "?selector=a%3D1%2Cb%3D2%2Cc%3D3%2Cd%3D4%2Ce%3D5%2Cf%3D6%2Cg%3D7%2Ch%3D8%2Ci%3D9", "", auth.EventConnectionsList},
		{"limit zero", "GET", auth.ConnectionsPath + "?limit=0", "", auth.EventConnectionsList},
		{"limit negative", "GET", auth.ConnectionsPath + "?limit=-1", "", auth.EventConnectionsList},
		{"limit above bound", "GET", auth.ConnectionsPath + "?limit=1001", "", auth.EventConnectionsList},
		{"limit text", "GET", auth.ConnectionsPath + "?limit=abc", "", auth.EventConnectionsList},
		{"limit empty", "GET", auth.ConnectionsPath + "?limit=", "", auth.EventConnectionsList},
		{"limit repeated", "GET", auth.ConnectionsPath + "?limit=1&limit=2", "", auth.EventConnectionsList},
		{"listing unknown", "GET", auth.ConnectionsPath + "?dryRun=true", "", auth.EventConnectionsList},
		{"malformed", "GET", auth.ConnectionsPath + "?limit=%zz", "", auth.EventConnectionsList},
		{"create dry run value", "POST", auth.ConnectionsPath + "?dryRun=yes", validConnectionBody, auth.EventConnectionCreate},
		{"create dry run bare", "POST", auth.ConnectionsPath + "?dryRun", validConnectionBody, auth.EventConnectionCreate},
		{"create dry run case", "POST", auth.ConnectionsPath + "?dryRun=TRUE", validConnectionBody, auth.EventConnectionCreate},
		{"create dry run false", "POST", auth.ConnectionsPath + "?dryRun=false", validConnectionBody, auth.EventConnectionCreate},
		{"create unknown", "POST", auth.ConnectionsPath + "?selector=env%3Dprod", validConnectionBody, auth.EventConnectionCreate},
		{"create extra", "POST", auth.ConnectionsPath + "?dryRun=true&force=1", validConnectionBody, auth.EventConnectionCreate},
		{"update dry run value", "POST", connectionPath(auth.ConnectionUpdatePath) + "?dryRun=1", validUpdateBody, auth.EventConnectionUpdate},
		{"credentials unknown", "POST", connectionPath(auth.ConnectionCredentialsPath) + "?limit=1", validCredentialsBody, auth.EventConnectionSecrets},
		{"enable dry run value", "POST", connectionPath(auth.ConnectionEnablePath) + "?dryRun=on", "", auth.EventConnectionEnable},
		{"disable unknown", "POST", connectionPath(auth.ConnectionDisablePath) + "?x=1", "", auth.EventConnectionDisable},
		{"delete dry run value", "POST", connectionPath(auth.ConnectionDeletePath) + "?dryRun=yes", "", auth.EventConnectionDelete},
		{"check dry run", "POST", connectionPath(auth.ConnectionCheckPath) + "?dryRun=true", "", auth.EventConnectionCheck},
		{"check unknown", "POST", connectionPath(auth.ConnectionCheckPath) + "?force=1", "", auth.EventConnectionCheck},
		{"record dry run", "GET", connectionPath(auth.ConnectionPath) + "?dryRun=true", "", auth.EventConnectionGet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := connectionFixture(t)
			headers := bearerHeaders()
			if tc.body != "" {
				headers.Set("Content-Type", "application/json")
			}
			response := requestAuth(handler, tc.method, tc.path, tc.body, headers)
			require.Equal(t, 400, response.Code)
			require.Contains(t, response.Body.String(), auth.InvalidArgument)
			require.Empty(t, f.connectionCalls)
			require.Equal(t, []auth.Event{{Action: tc.action, Outcome: auth.OutcomeInvalidArgument}}, f.events)
		})
	}
}

func TestConnectionRoutesRejectUnusableReferencesAfterIdentifyingTheActor(t *testing.T) {
	const sessionID = "12345678-1234-4234-8234-123456789aaa"
	patterns := map[string]auth.EventAction{
		auth.ConnectionPath:            auth.EventConnectionGet,
		auth.ConnectionUpdatePath:      auth.EventConnectionUpdate,
		auth.ConnectionCredentialsPath: auth.EventConnectionSecrets,
		auth.ConnectionEnablePath:      auth.EventConnectionEnable,
		auth.ConnectionDisablePath:     auth.EventConnectionDisable,
		auth.ConnectionDeletePath:      auth.EventConnectionDelete,
		auth.ConnectionCheckPath:       auth.EventConnectionCheck,
	}
	// An empty segment (doubled slash) still matches every suffixed route and
	// must be rejected here rather than resolved by the service.
	for _, reference := range []string{"", "ab", "WAREHOUSE", "1warehouse", "wh!primary", "12345678-1234-4234-8234-123456789ab"} {
		for pattern, action := range patterns {
			if reference == "" && pattern == auth.ConnectionPath {
				continue // a bare trailing slash matches no route at all
			}
			f, handler := connectionFixture(t)
			path := strings.Replace(pattern, "{connectionID}", reference, 1)
			method, body := "POST", ""
			if pattern == auth.ConnectionPath {
				method = "GET"
			}
			if pattern == auth.ConnectionUpdatePath {
				body = validUpdateBody
			}
			if pattern == auth.ConnectionCredentialsPath {
				body = validCredentialsBody
			}
			headers := bearerHeaders()
			if body != "" {
				headers.Set("Content-Type", "application/json")
			}
			response := requestAuth(handler, method, path, body, headers)
			require.Equal(t, 400, response.Code, path)
			require.Contains(t, response.Body.String(), auth.InvalidArgument)
			require.Empty(t, f.connectionCalls)
			require.Len(t, f.events, 1)
			require.Equal(t, action, f.events[0].Action)
			require.Equal(t, auth.OutcomeInvalidArgument, f.events[0].Outcome)
			require.Equal(t, fixtureIdentity.User.ID, f.events[0].ActorID)
			require.Equal(t, sessionID, f.events[0].SessionID)
			require.Empty(t, f.events[0].TargetID, "an unverified target never enters an event")
		}
	}
	// The record route without a reference is no route: the router answers,
	// the adapter records nothing and the service is never reached.
	f, handler := connectionFixture(t)
	response := requestAuth(handler, "GET", auth.ConnectionsPath+"/", "", bearerHeaders())
	require.Equal(t, 404, response.Code)
	require.Empty(t, f.connectionCalls)
	require.Empty(t, f.events)
}

func TestConnectionRejectionAuditFailureReturnsUnavailability(t *testing.T) {
	for _, route := range connectionRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := connectionFixture(t)
			f.recordErr = errors.New("SENTINEL_PRIVATE_DRIVER")
			response := requestAuth(handler, route.method, route.path, route.body, http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, 503, response.Code)
			require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Empty(t, f.connectionCalls)
		})
	}
}

func TestConnectionRoutesHonorTheOperationDeadline(t *testing.T) {
	for _, route := range connectionRoutes() {
		f, handler := connectionFixture(t)
		f.connectionBlock = func(ctx context.Context) { <-ctx.Done() }
		start := time.Now()
		response := requestAuth(handler, route.method, route.path, route.body, route.headers())
		require.Equal(t, 503, response.Code, route.name)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
		require.Less(t, time.Since(start), 7*time.Second)
	}
}

// maximalConnection is the largest record the contract allows: a full-length
// name, title, description and scope, sixteen maximal labels and a full set of
// target settings. A thousand of them are far larger than the listing body.
func maximalConnection() auth.Connection {
	labels := map[string]string{}
	for index := 0; index < auth.MaxLabels; index++ {
		labels[fmt.Sprintf("k%02d", index)+strings.Repeat("x", 60)] = strings.Repeat("y", 63)
	}
	target := map[string]string{}
	for index := 0; index < 8; index++ {
		target[fmt.Sprintf("s%d", index)] = strings.Repeat("t", 200)
	}
	return auth.Connection{
		ID: connectionTargetID, Name: "c" + strings.Repeat("n", 63), Title: strings.Repeat("T", auth.MaxTitleLength),
		Description: strings.Repeat("D", auth.MaxDescriptionLength), Scope: strings.Repeat("S", auth.MaxDescriptionLength),
		Provider: auth.ProviderPostgreSQL, Target: target, Labels: labels, Enabled: true,
		StatementTimeoutMS: 120000, MaxRows: auth.MaxMaxRows, MaxBytes: auth.MaxMaxBytes,
		LastCheck: &auth.CheckResult{Outcome: auth.CheckReachable, CheckedAt: connectionTime},
		CreatedAt: connectionTime, UpdatedAt: connectionTime,
	}
}

func TestBoundedListingDropsTrailingRecordsToFitTheBudget(t *testing.T) {
	records := make([]auth.Connection, 0, auth.MaxConnectionListing)
	for index := 0; index < auth.MaxConnectionListing; index++ {
		records = append(records, maximalConnection())
	}
	kept, truncated, err := boundedListing("connections", records, false)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Greater(t, len(kept), 0)
	require.Less(t, len(kept), auth.MaxConnectionListing)
	encoded, err := json.Marshal(auth.ConnectionList{Connections: kept, Truncated: truncated})
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded)+1, auth.MaxListingBody, "the encoder's newline is part of the body")
	// One more record would have exceeded the budget.
	over, err := json.Marshal(auth.ConnectionList{Connections: records[:len(kept)+1], Truncated: true})
	require.NoError(t, err)
	require.Greater(t, len(over)+1, auth.MaxListingBody)
	// A listing that already fits is passed through untouched, flag included.
	small := []auth.Connection{connectionRecord}
	kept, truncated, err = boundedListing("connections", small, true)
	require.NoError(t, err)
	require.Equal(t, small, kept)
	require.True(t, truncated)
	empty, truncated, err := boundedListing("connections", []auth.Connection{}, false)
	require.NoError(t, err)
	require.Equal(t, []auth.Connection{}, empty)
	require.False(t, truncated)
	// The grant listing shares the budget under its own, shorter envelope.
	grants := make([]auth.Grant, 0, auth.MaxGrantListing)
	for index := 0; index < auth.MaxGrantListing; index++ {
		grants = append(grants, maximalGrant())
	}
	keptGrants, truncated, err := boundedListing("grants", grants, false)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Less(t, len(keptGrants), auth.MaxGrantListing)
	encoded, err = json.Marshal(auth.GrantList{Grants: keptGrants, Truncated: truncated})
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded)+1, auth.MaxListingBody)
	overGrants, err := json.Marshal(auth.GrantList{Grants: grants[:len(keptGrants)+1], Truncated: true})
	require.NoError(t, err)
	require.Greater(t, len(overGrants)+1, auth.MaxListingBody)
}

func TestConnectionListingResponseStaysWithinTheDocumentedBodyLimit(t *testing.T) {
	f, handler := connectionFixture(t)
	records := make([]auth.Connection, 0, auth.MaxConnectionListing)
	for index := 0; index < auth.MaxConnectionListing; index++ {
		records = append(records, maximalConnection())
	}
	f.connectionList = auth.ConnectionList{Connections: records}
	response := requestAuth(handler, "GET", auth.ConnectionsPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.LessOrEqual(t, response.Body.Len(), auth.MaxListingBody)
	var decoded auth.ConnectionList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
	require.True(t, decoded.Truncated)
	require.Greater(t, len(decoded.Connections), 0)
	require.Less(t, len(decoded.Connections), auth.MaxConnectionListing)
	require.Equal(t, auth.MaxConnectionListing, f.connectionCalls[0].limit)
}

func serverTestKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	var key [secrets.KeyBytes]byte
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	keyring, err := secrets.NewKeyring(key[:])
	require.NoError(t, err)
	return keyring
}

// probeTarget is the test database as a connection target: the same URL
// without its password, which travels in the request's secret instead.
func probeTarget(t *testing.T) (map[string]string, auth.Secret) {
	t.Helper()
	parsed, err := url.Parse(os.Getenv("CLAVIS_BACKEND_TEST_DATABASE_URL"))
	require.NoError(t, err)
	password, _ := parsed.User.Password()
	if password == "" {
		t.Skip("the test database URL carries no password to probe with")
	}
	query := url.Values{}
	if mode := parsed.Query().Get("sslmode"); mode != "" {
		query.Set("sslmode", mode)
	}
	safe := url.URL{Scheme: parsed.Scheme, User: url.User(parsed.User.Username()),
		Host: parsed.Host, Path: parsed.Path, RawQuery: query.Encode()}
	return map[string]string{"url": safe.String()}, auth.Secret(password)
}

// The request bodies here are marshaled from the same DTOs the CLI marshals,
// so the shapes exercised are literally the ones the CLI sends, including the
// zero bounds a bare `connections create` carries.
func TestRealHTTPConnectionRoutesRoundTrip(t *testing.T) {
	pool, path, password := serverDatabase(t)
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	local, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	service := local.WithKeyring(serverTestKeyring(t))
	handler, err := HandlerWithAuth(time.Second, checker, service, service, service, service, service, service,
		"http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	encoded, err := json.Marshal(auth.LoginRequest{Username: "personal-admin", Password: password})
	require.NoError(t, err)
	response := requestAuth(handler, "POST", auth.LoginPath, string(encoded), http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, 200, response.Code)
	var issued auth.LoginResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &issued))
	headers := http.Header{"Authorization": {"Bearer " + string(issued.Token)}, "Accept": {"application/json"}}
	send := func(method, route, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := headers.Clone()
		if body != "" {
			request.Set("Content-Type", "application/json")
		}
		result := requestAuth(handler, method, route, body, request)
		require.Equal(t, "no-store", result.Header().Get("Cache-Control"))
		require.Empty(t, result.Header().Get("Location"))
		return result
	}
	body := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		require.NoError(t, err)
		return string(data)
	}

	target, secret := probeTarget(t)
	create := auth.CreateConnectionRequest{
		Name: "ledger-primary", Title: "Ledger", Description: "primary ledger", Scope: "read only",
		Provider: auth.ProviderPostgreSQL, Target: target,
		Labels: map[string]string{"env": "prod", "team": "data"}, Secret: secret,
	}
	// A dry run answers with the record it would have made and leaves nothing.
	response = send("POST", auth.ConnectionsPath+"?dryRun=true", body(create))
	require.Equal(t, 200, response.Code)
	var mutation auth.ConnectionMutation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.True(t, mutation.DryRun)
	var rows int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM connections`).Scan(&rows))
	require.Zero(t, rows)

	response = send("POST", auth.ConnectionsPath, body(create))
	require.Equal(t, 201, response.Code)
	var record auth.Connection
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &record))
	require.Equal(t, "ledger-primary", record.Name)
	require.True(t, record.Enabled)
	require.Nil(t, record.LastCheck)
	require.Equal(t, 30000, record.StatementTimeoutMS, "an omitted bound takes its default")
	require.NotContains(t, response.Body.String(), string(secret))

	// A VictoriaMetrics connection with auth none is the one request that
	// carries an empty secret; the CLI sends it exactly like this.
	metrics := auth.CreateConnectionRequest{
		Name: "metrics-eu", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": "http://127.0.0.1:8428", "auth": "none"},
		Labels: map[string]string{}, Secret: "", StatementTimeoutMS: 0, MaxRows: 0, MaxBytes: 0,
	}
	response = send("POST", auth.ConnectionsPath, body(metrics))
	require.Equal(t, 201, response.Code)

	response = send("GET", auth.ConnectionsPath+"?"+url.Values{"selector": {"env=prod,team"}, "limit": {"10"}}.Encode(), "")
	require.Equal(t, 200, response.Code)
	var list auth.ConnectionList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &list))
	require.Len(t, list.Connections, 1)
	require.False(t, list.Truncated)
	require.Equal(t, record.ID, list.Connections[0].ID)

	for _, reference := range []string{record.Name, record.ID} {
		response = send("GET", strings.Replace(auth.ConnectionPath, "{connectionID}", reference, 1), "")
		require.Equal(t, 200, response.Code)
		var fetched auth.Connection
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &fetched))
		require.Equal(t, record.ID, fetched.ID)
	}
	response = send("GET", strings.Replace(auth.ConnectionPath, "{connectionID}", "no-such-connection", 1), "")
	require.Equal(t, 404, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, auth.ConnectionNotFound, failure.Error.Code)
	require.NotEmpty(t, failure.Error.Hint)

	scope := "read only, ledger schema"
	response = send("POST", strings.Replace(auth.ConnectionUpdatePath, "{connectionID}", record.ID, 1),
		body(auth.UpdateConnectionRequest{Scope: &scope}))
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.Equal(t, scope, mutation.Connection.Scope)
	require.False(t, mutation.DryRun)

	response = send("POST", strings.Replace(auth.ConnectionCheckPath, "{connectionID}", record.Name, 1), "")
	require.Equal(t, 200, response.Code)
	var checked auth.ConnectionCheck
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &checked))
	require.Equal(t, auth.CheckReachable, checked.Check.Outcome)

	response = send("POST", strings.Replace(auth.ConnectionCredentialsPath, "{connectionID}", record.Name, 1),
		body(auth.SetConnectionCredentialsRequest{Secret: secret + "-wrong"}))
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.Nil(t, mutation.Connection.LastCheck, "replacing credentials clears the last check")
	response = send("POST", strings.Replace(auth.ConnectionCheckPath, "{connectionID}", record.Name, 1), "")
	require.Equal(t, 200, response.Code, "a rejected credential is a result, not an error")
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &checked))
	require.Equal(t, auth.CheckAuthRejected, checked.Check.Outcome)

	// Delete is guarded until the connection is disabled.
	response = send("POST", strings.Replace(auth.ConnectionDeletePath, "{connectionID}", record.Name, 1), "")
	require.Equal(t, 409, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, auth.ConnectionInUse, failure.Error.Code)
	require.NotEmpty(t, failure.Error.Hint)

	response = send("POST", strings.Replace(auth.ConnectionDisablePath, "{connectionID}", record.Name, 1), "")
	require.Equal(t, 200, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
	require.False(t, mutation.Connection.Enabled)
	response = send("POST", strings.Replace(auth.ConnectionDeletePath, "{connectionID}", record.Name, 1), "")
	require.Equal(t, 200, response.Code)
	var deletion auth.ConnectionDeletion
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &deletion))
	require.Equal(t, auth.ConnectionDeletion{ID: record.ID, Name: record.Name, Deleted: true}, deletion)

	// One pre-service rejection records exactly one event with the mapped
	// action, which the migrated check constraint must accept.
	var before int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events`).Scan(&before))
	response = send("POST", auth.ConnectionsPath, `{"SENTINEL_PRIVATE_BODY":"x"}`)
	require.Equal(t, 400, response.Code)
	var total, rejected int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events`).Scan(&total))
	require.Equal(t, before+1, total)
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth_events WHERE action='connection.create' AND outcome='invalid_argument'`).Scan(&rejected))
	require.Equal(t, 1, rejected)
	var row string
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT row_to_json(auth_events)::text FROM auth_events WHERE outcome='invalid_argument'`).Scan(&row))
	require.NotContains(t, row, "SENTINEL")

	for action, count := range map[string]int{
		"connection.create": 2, "connection.update": 1, "connection.set_credentials": 1,
		"connection.disable": 1, "connection.delete": 1, "connection.check": 2,
		"connection.get": 0, "connections.list": 0, "connection.enable": 0,
	} {
		var events int
		require.NoError(t, pool.QueryRow(t.Context(),
			`SELECT count(*) FROM auth_events WHERE action=$1 AND outcome IN ('success','check_failed')`, action).Scan(&events))
		require.Equal(t, count, events, action)
	}
	var stored int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM connections`).Scan(&stored))
	require.Equal(t, 1, stored, "only the metrics connection remains")
}
