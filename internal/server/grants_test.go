package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

// fakeGrants records exactly what each route handed the grant service and the
// member half of the connection reads, so a rejected request can be proven
// never to have reached either. It is embedded in backendFixture, which
// supplies the session.
type fakeGrants struct {
	grantList       auth.GrantList
	grantMutation   auth.GrantMutation
	grantRevocation auth.GrantRevocation
	grantErr        error
	grantCalls      []grantCall
	grantBlock      func(context.Context)
	summaryList     auth.ConnectionSummaryList
	summaryRecord   auth.ConnectionSummary
	grantedNames    []string
	namesTruncated  bool
	memberErr       error
}

type grantCall struct {
	operation string
	filter    auth.GrantFilter
	request   auth.GrantRequest
	dryRun    bool
	target    string
	terms     []auth.SelectorTerm
	limit     int
	role      auth.Role
}

func (f *fakeGrants) grantCall(ctx context.Context, session auth.Session, call grantCall) {
	call.role = session.User.Role
	f.grantCalls = append(f.grantCalls, call)
	if f.grantBlock != nil {
		f.grantBlock(ctx)
	}
}

func (f *fakeGrants) ListGrants(ctx context.Context, session auth.Session, filter auth.GrantFilter) (auth.GrantList, error) {
	f.grantCall(ctx, session, grantCall{operation: "list", filter: filter})
	return f.grantList, f.grantErr
}

func (f *fakeGrants) CreateGrant(ctx context.Context, session auth.Session, request auth.GrantRequest, dryRun bool) (auth.GrantMutation, error) {
	f.grantCall(ctx, session, grantCall{operation: "create", request: request, dryRun: dryRun})
	return f.grantMutation, f.grantErr
}

func (f *fakeGrants) RevokeGrant(ctx context.Context, session auth.Session, request auth.GrantRequest, dryRun bool) (auth.GrantRevocation, error) {
	f.grantCall(ctx, session, grantCall{operation: "revoke", request: request, dryRun: dryRun})
	return f.grantRevocation, f.grantErr
}

func (f *fakeGrants) AuthorizeConnection(ctx context.Context, session auth.Session, ref string) (auth.Connection, error) {
	f.grantCall(ctx, session, grantCall{operation: "authorize", target: ref})
	return auth.Connection{}, f.grantErr
}

func (f *fakeGrants) ListGrantedConnections(ctx context.Context, session auth.Session, terms []auth.SelectorTerm, limit int) (auth.ConnectionSummaryList, error) {
	f.grantCall(ctx, session, grantCall{operation: "member-list", terms: terms, limit: limit})
	return f.summaryList, f.memberErr
}

func (f *fakeGrants) GetGrantedConnection(ctx context.Context, session auth.Session, ref string) (auth.ConnectionSummary, error) {
	f.grantCall(ctx, session, grantCall{operation: "member-get", target: ref})
	return f.summaryRecord, f.memberErr
}

func (f *fakeGrants) ListGrantedConnectionNames(ctx context.Context, session auth.Session, limit int) ([]string, bool, error) {
	f.grantCall(ctx, session, grantCall{operation: "member-names", limit: limit})
	return f.grantedNames, f.namesTruncated, f.memberErr
}

const (
	grantUserID       = "abcdefab-1234-4234-8234-1234567890a7"
	grantAdminID      = "abcdefab-1234-4234-8234-1234567890a8"
	grantUsername     = "alice"
	grantConnection   = "payments-prod-reporting"
	validGrantBody    = `{"user":"alice","connection":"payments-prod-reporting"}`
	grantMemberSecret = "SENTINEL_PRIVATE_TARGET"
)

var (
	grantTime   = time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	grantRecord = auth.Grant{
		User:       auth.GrantParty{ID: grantUserID, Name: grantUsername},
		Connection: auth.GrantParty{ID: connectionTargetID, Name: grantConnection},
		CreatedAt:  grantTime,
		CreatedBy:  auth.GrantParty{ID: grantAdminID, Name: "personal-admin"},
	}
	grantCreated  = auth.GrantMutation{Grant: grantRecord, Created: true}
	grantRevoked  = auth.GrantRevocation{User: grantRecord.User, Connection: grantRecord.Connection, Revoked: true}
	grantListing  = auth.GrantList{Grants: []auth.Grant{grantRecord}, Truncated: true}
	grantedRecord = auth.ConnectionSummary{
		ID: connectionTargetID, Name: connectionTargetName, Title: "Warehouse",
		Description: "primary ledger", Scope: "read only", Provider: auth.ProviderPostgreSQL,
		Labels: map[string]string{"env": "prod"}, Enabled: true,
	}
)

// grantRoute is the design's grant route table expressed once: every test
// below walks all three routes rather than a representative subset.
type grantRoute struct {
	name, method, path, body, operation string
	success                             int
	expected                            any
	dryRunnable                         bool
}

func grantRoutes() []grantRoute {
	return []grantRoute{
		{"list", "GET", auth.GrantsPath, "", "list", 200, grantListing, false},
		{"create", "POST", auth.GrantsPath, validGrantBody, "create", 201, grantCreated, true},
		{"revoke", "POST", auth.GrantRevokePath, validGrantBody, "revoke", 200, grantRevoked, true},
	}
}

func (route grantRoute) headers() http.Header {
	headers := bearerHeaders()
	if route.body != "" {
		headers.Set("Content-Type", "application/json")
	}
	return headers
}

func grantFixture(t *testing.T) (*backendFixture, http.Handler) {
	t.Helper()
	f := &backendFixture{}
	f.grantList, f.grantMutation, f.grantRevocation = grantListing, grantCreated, grantRevoked
	f.summaryList = auth.ConnectionSummaryList{Connections: []auth.ConnectionSummary{grantedRecord}, Truncated: true}
	f.summaryRecord = grantedRecord
	return f, authHandler(t, f, nil, "http://127.0.0.1")
}

func TestGrantRoutesReturnDocumentedSuccessBodies(t *testing.T) {
	for _, route := range grantRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := grantFixture(t)
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
			require.Len(t, f.grantCalls, 1)
			require.Equal(t, route.operation, f.grantCalls[0].operation)
			require.False(t, f.grantCalls[0].dryRun)
		})
	}
}

// Creation is idempotent, so its status carries the only fact a retrying agent
// needs: 201 when the grant was written, 200 when it was already in place.
func TestGrantCreationAnswers200WhenTheGrantAlreadyExisted(t *testing.T) {
	f, handler := grantFixture(t)
	f.grantMutation = auth.GrantMutation{Grant: grantRecord}
	response := requestAuth(handler, "POST", auth.GrantsPath, validGrantBody,
		bearerHeaders("Content-Type", "application/json"))
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), `"created":false`)
}

func TestGrantRoutesHandTheServiceExactlyWhatWasAsked(t *testing.T) {
	f, handler := grantFixture(t)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", auth.GrantsPath + "?user=alice&connection=" + grantConnection + "&limit=7", ""},
		{"GET", auth.GrantsPath, ""},
		{"GET", auth.GrantsPath + "?user=" + grantUserID, ""},
		{"POST", auth.GrantsPath, validGrantBody},
		{"POST", auth.GrantRevokePath, `{"user":"` + grantUserID + `","connection":"` + connectionTargetID + `"}`},
	} {
		headers := bearerHeaders()
		if tc.body != "" {
			headers.Set("Content-Type", "application/json")
		}
		require.Less(t, requestAuth(handler, tc.method, tc.path, tc.body, headers).Code, 300, tc.path)
	}
	require.Equal(t, []grantCall{
		{operation: "list", role: auth.Admin, filter: auth.GrantFilter{User: grantUsername, Connection: grantConnection, Limit: 7}},
		// A missing limit asks for the documented bound, not for nothing.
		{operation: "list", role: auth.Admin, filter: auth.GrantFilter{Limit: auth.MaxGrantListing}},
		{operation: "list", role: auth.Admin, filter: auth.GrantFilter{User: grantUserID, Limit: auth.MaxGrantListing}},
		{operation: "create", role: auth.Admin, request: auth.GrantRequest{User: grantUsername, Connection: grantConnection}},
		{operation: "revoke", role: auth.Admin, request: auth.GrantRequest{User: grantUserID, Connection: connectionTargetID}},
	}, f.grantCalls)
}

func TestGrantDryRunIsRequestedExplicitlyAndMarksTheResult(t *testing.T) {
	for _, route := range grantRoutes() {
		if !route.dryRunnable {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			f, handler := grantFixture(t)
			f.grantMutation.DryRun, f.grantRevocation.DryRun = true, true
			response := requestAuth(handler, route.method, route.path+"?dryRun=true", route.body, route.headers())
			// A rehearsed creation answers 200 with the mutation it would have
			// made rather than 201 with a grant that does not exist.
			require.Equal(t, 200, response.Code)
			require.Len(t, f.grantCalls, 1)
			require.True(t, f.grantCalls[0].dryRun)
			require.Contains(t, response.Body.String(), `"dryRun":true`)
		})
	}
}

// The routes field is the design's per-route error column: a nil list means
// every route, and a named list keeps undocumented pairings out of the
// asserted contract. The hint is the service's, passed through unchanged.
func TestGrantServiceFailuresUseDocumentedStatusesAndHints(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		hint   string
		routes []string
	}{
		{&auth.Error{Code: auth.Unauthenticated}, 401, auth.Unauthenticated, "", nil},
		{&auth.Error{Code: auth.Forbidden}, 403, auth.Forbidden, "", nil},
		{&auth.Error{Code: auth.UserNotFound, Hint: "List users to find the username."}, 404, auth.UserNotFound,
			"List users to find the username.", []string{"create", "revoke"}},
		{&auth.Error{Code: auth.ConnectionNotFound, Hint: "List connections to find the name."}, 404,
			auth.ConnectionNotFound, "List connections to find the name.", []string{"create", "revoke"}},
		{&auth.Error{Code: auth.InvalidArgument, Hint: "Provide a user and a connection."}, 400,
			auth.InvalidArgument, "Provide a user and a connection.", nil},
		{errors.New("SENTINEL_PRIVATE_DRIVER"), 503, auth.ServiceUnavailable, "", nil},
	} {
		for _, route := range grantRoutes() {
			if len(tc.routes) != 0 && !slices.Contains(tc.routes, route.name) {
				continue
			}
			t.Run(tc.code+"/"+route.name, func(t *testing.T) {
				f, handler := grantFixture(t)
				f.grantErr = tc.err
				response := requestAuth(handler, route.method, route.path, route.body, route.headers())
				require.Equal(t, tc.status, response.Code)
				var failure auth.ErrorResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
				require.Equal(t, tc.code, failure.Error.Code)
				require.Equal(t, tc.hint, failure.Error.Hint)
				require.NotContains(t, response.Body.String(), "SENTINEL")
			})
		}
	}
}

func TestGrantBodiesAndQueriesAreStrict(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, contentType string
	}{
		{"unknown field", "POST", auth.GrantsPath, `{"user":"alice","connection":"c-name","role":"admin"}`, "application/json"},
		{"duplicate field", "POST", auth.GrantsPath, `{"user":"alice","user":"bob","connection":"c-name"}`, "application/json"},
		{"case alias", "POST", auth.GrantsPath, `{"User":"alice","connection":"c-name"}`, "application/json"},
		{"null user", "POST", auth.GrantsPath, `{"user":null,"connection":"c-name"}`, "application/json"},
		{"numeric user", "POST", auth.GrantsPath, `{"user":7,"connection":"c-name"}`, "application/json"},
		{"trailing document", "POST", auth.GrantsPath, validGrantBody + `{}`, "application/json"},
		{"empty body", "POST", auth.GrantsPath, `{}`, "application/json"},
		{"missing connection", "POST", auth.GrantsPath, `{"user":"alice"}`, "application/json"},
		{"uppercase user", "POST", auth.GrantsPath, `{"user":"ALICE","connection":"c-name"}`, "application/json"},
		{"short user", "POST", auth.GrantsPath, `{"user":"ab","connection":"c-name"}`, "application/json"},
		{"bad connection", "POST", auth.GrantsPath, `{"user":"alice","connection":"C NAME"}`, "application/json"},
		{"form create", "POST", auth.GrantsPath, "user=alice&connection=c-name", "application/x-www-form-urlencoded"},
		{"typeless create", "POST", auth.GrantsPath, validGrantBody, ""},
		{"oversized", "POST", auth.GrantsPath, `{"user":"alice","connection":"` + strings.Repeat("c", auth.MaxCredentialBody) + `"}`,
			"application/json"},
		{"revoke unknown field", "POST", auth.GrantRevokePath, `{"user":"alice","connection":"c-name","x":1}`, "application/json"},
		{"revoke bad user", "POST", auth.GrantRevokePath, `{"user":"1alice","connection":"c-name"}`, "application/json"},
		{"listing body", "GET", auth.GrantsPath, `{"grants":[]}`, "application/json"},
		{"listing user", "GET", auth.GrantsPath + "?user=ALICE", "", ""},
		{"listing connection", "GET", auth.GrantsPath + "?connection=C%20NAME", "", ""},
		{"listing limit zero", "GET", auth.GrantsPath + "?limit=0", "", ""},
		{"listing limit above bound", "GET", auth.GrantsPath + "?limit=1001", "", ""},
		{"listing limit text", "GET", auth.GrantsPath + "?limit=abc", "", ""},
		{"listing limit repeated", "GET", auth.GrantsPath + "?limit=1&limit=2", "", ""},
		{"listing unknown parameter", "GET", auth.GrantsPath + "?dryRun=true", "", ""},
		{"listing malformed", "GET", auth.GrantsPath + "?limit=%zz", "", ""},
		{"create dry run value", "POST", auth.GrantsPath + "?dryRun=yes", validGrantBody, "application/json"},
		{"create dry run case", "POST", auth.GrantsPath + "?dryRun=TRUE", validGrantBody, "application/json"},
		{"create unknown parameter", "POST", auth.GrantsPath + "?limit=1", validGrantBody, "application/json"},
		{"revoke dry run bare", "POST", auth.GrantRevokePath + "?dryRun", validGrantBody, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := grantFixture(t)
			headers := bearerHeaders()
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			response := requestAuth(handler, tc.method, tc.path, tc.body, headers)
			require.Equal(t, 400, response.Code)
			require.Contains(t, response.Body.String(), auth.InvalidArgument)
			require.NotContains(t, response.Body.String(), "alice")
			require.Empty(t, f.grantCalls, "an invalid request must never reach the service")
		})
	}
}

// A cookie is not a CLI credential: the grant routes are bearer-only exactly
// like the connection routes, and an ambiguous credential never reaches them.
func TestGrantRoutesAreBearerOnly(t *testing.T) {
	for _, route := range grantRoutes() {
		for _, tc := range []struct {
			name    string
			headers http.Header
			status  int
		}{
			{"cookie only", http.Header{"Cookie": {developmentCookie + "=" + string(fixtureToken)}}, 401},
			{"no credential", http.Header{}, 401},
			{"bearer and cookie", http.Header{
				"Authorization": {"Bearer " + string(fixtureToken)},
				"Cookie":        {developmentCookie + "=" + string(fixtureToken)},
			}, 400},
			{"cross origin", bearerHeaders("Origin", "http://evil.invalid"), 403},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				f, handler := grantFixture(t)
				headers := tc.headers.Clone()
				if route.body != "" {
					headers.Set("Content-Type", "application/json")
				}
				response := requestAuth(handler, route.method, route.path, route.body, headers)
				require.Equal(t, tc.status, response.Code)
				require.Empty(t, response.Header().Get("Set-Cookie"))
				require.Empty(t, f.grantCalls)
			})
		}
	}
}

// Members are not refused here: the service scopes a listing to the caller's
// own grants and denies the mutations itself, so the adapter must hand it the
// session rather than deciding on the role itself.
func TestGrantRoutesPassMemberSessionsToTheService(t *testing.T) {
	for _, route := range grantRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := grantFixture(t)
			f.role = auth.Member
			response := requestAuth(handler, route.method, route.path, route.body, route.headers())
			require.Equal(t, route.success, response.Code)
			require.Len(t, f.grantCalls, 1)
			require.Equal(t, auth.Member, f.grantCalls[0].role)
		})
	}
}

func TestGrantRoutesFailClosedWithoutAService(t *testing.T) {
	for _, route := range grantRoutes() {
		f := &backendFixture{}
		adapter, err := newAuthHTTP("http://127.0.0.1", f, fixtureViews())
		require.NoError(t, err)
		adapter.admin, adapter.connections = f, f
		ready := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
		handler := handler(time.Second, ready, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
		response := requestAuth(handler, route.method, route.path, route.body, route.headers())
		require.Equal(t, 503, response.Code, route.name)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
		require.Empty(t, f.grantCalls)
	}
}

func TestGrantRoutesHonorTheOperationDeadline(t *testing.T) {
	for _, route := range grantRoutes() {
		f, handler := grantFixture(t)
		f.grantBlock = func(ctx context.Context) { <-ctx.Done() }
		start := time.Now()
		response := requestAuth(handler, route.method, route.path, route.body, route.headers())
		require.Equal(t, 503, response.Code, route.name)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
		require.Less(t, time.Since(start), 7*time.Second)
	}
}

// maximalGrant is the largest grant the contract allows: full-length username,
// connection name and granting administrator. A thousand of them are larger
// than the listing body, so the byte budget, not the row bound, truncates.
func maximalGrant() auth.Grant {
	name := "u" + strings.Repeat("z", 63)
	return auth.Grant{
		User:       auth.GrantParty{ID: grantUserID, Name: name},
		Connection: auth.GrantParty{ID: connectionTargetID, Name: "c" + strings.Repeat("n", 63)},
		CreatedAt:  grantTime,
		CreatedBy:  auth.GrantParty{ID: grantAdminID, Name: name},
	}
}

func TestGrantListingResponseStaysWithinTheDocumentedBodyLimit(t *testing.T) {
	f, handler := grantFixture(t)
	grants := make([]auth.Grant, 0, auth.MaxGrantListing)
	for index := 0; index < auth.MaxGrantListing; index++ {
		grants = append(grants, maximalGrant())
	}
	f.grantList = auth.GrantList{Grants: grants}
	response := requestAuth(handler, "GET", auth.GrantsPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.LessOrEqual(t, response.Body.Len(), auth.MaxListingBody)
	var decoded auth.GrantList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
	require.True(t, decoded.Truncated)
	require.Greater(t, len(decoded.Grants), 0)
	require.Less(t, len(decoded.Grants), auth.MaxGrantListing)
	require.Equal(t, auth.MaxGrantListing, f.grantCalls[0].filter.Limit)
}

// The two connection GET routes are the only ones a member may call, and the
// projection follows the role: no target, bound or timestamp reaches a member.
func TestConnectionReadsUseTheMemberProjectionForMembers(t *testing.T) {
	summary := grantedRecord
	summary.Description = "primary ledger"
	for _, tc := range []struct {
		name, method, path string
		operation          string
		expected           any
	}{
		{"list", "GET", auth.ConnectionsPath + "?selector=env%3Dprod&limit=5", "member-list",
			auth.ConnectionSummaryList{Connections: []auth.ConnectionSummary{summary}, Truncated: true}},
		{"get", "GET", strings.Replace(auth.ConnectionPath, "{connectionID}", connectionTargetName, 1), "member-get", summary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := grantFixture(t)
			f.role = auth.Member
			// The administrator projection is loaded too: if the route read it
			// for a member, the target below would appear in the response.
			f.connectionList, f.connectionRecord = connectionListing, connectionRecord
			f.connectionRecord.Target = map[string]string{"url": grantMemberSecret}
			response := requestAuth(handler, tc.method, tc.path, "", bearerHeaders())
			require.Equal(t, 200, response.Code)
			expected, err := json.Marshal(tc.expected)
			require.NoError(t, err)
			require.JSONEq(t, string(expected), response.Body.String())
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.NotContains(t, response.Body.String(), `"target"`)
			require.NotContains(t, response.Body.String(), `"maxRows"`)
			require.Empty(t, f.connectionCalls, "a member read never reaches the administrator projection")
			require.Len(t, f.grantCalls, 1)
			require.Equal(t, tc.operation, f.grantCalls[0].operation)
		})
	}
	// Selectors and bounds behave for a member exactly as for an administrator.
	f, handler := grantFixture(t)
	f.role = auth.Member
	require.Equal(t, 200, requestAuth(handler, "GET", auth.ConnectionsPath+"?selector=env%3Dprod&limit=5", "", bearerHeaders()).Code)
	require.Equal(t, []auth.SelectorTerm{{Key: "env", Op: auth.SelectorEquals, Value: "prod"}}, f.grantCalls[0].terms)
	require.Equal(t, 5, f.grantCalls[0].limit)
	// An administrator keeps the full record and never touches the member half.
	f, handler = grantFixture(t)
	f.connectionRecord = connectionRecord
	response := requestAuth(handler, "GET", strings.Replace(auth.ConnectionPath, "{connectionID}", connectionTargetName, 1), "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), `"target"`)
	require.Empty(t, f.grantCalls)
}

// A member's denied get is the service's answer, passed through with its hint,
// so an ungranted connection is indistinguishable from one that does not
// exist.
func TestMemberConnectionDenialsPassThroughUnchanged(t *testing.T) {
	f, handler := grantFixture(t)
	f.role = auth.Member
	f.memberErr = &auth.Error{Code: auth.ConnectionNotFound, Hint: "List connections to see what you may use."}
	response := requestAuth(handler, "GET", strings.Replace(auth.ConnectionPath, "{connectionID}", connectionTargetName, 1), "", bearerHeaders())
	require.Equal(t, 404, response.Code)
	var failure auth.ErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Equal(t, auth.ConnectionNotFound, failure.Error.Code)
	require.Equal(t, "List connections to see what you may use.", failure.Error.Hint)
}

// whoami answers what the caller may use, so the first call an agent makes
// already names its connections. An administrator needs no grant, so the list
// stays empty rather than enumerating everything.
func TestIdentityReportsGrantedConnectionNamesForMembersOnly(t *testing.T) {
	f, handler := grantFixture(t)
	f.role = auth.Member
	f.grantedNames, f.namesTruncated = []string{"payments-prod-reporting", "warehouse-primary"}, true
	response := requestAuth(handler, "GET", auth.WhoAmIPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	var identity auth.Identity
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &identity))
	require.Equal(t, []string{"payments-prod-reporting", "warehouse-primary"}, identity.Connections)
	require.True(t, identity.ConnectionsTruncated)
	require.Len(t, f.grantCalls, 1)
	require.Equal(t, "member-names", f.grantCalls[0].operation)
	require.Equal(t, auth.MaxConnectionListing, f.grantCalls[0].limit)

	f, handler = grantFixture(t)
	f.grantedNames, f.namesTruncated = []string{"payments-prod-reporting"}, true
	response = requestAuth(handler, "GET", auth.WhoAmIPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	var administrator auth.Identity
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &administrator))
	require.Empty(t, administrator.Connections)
	require.False(t, administrator.ConnectionsTruncated)
	require.Empty(t, f.grantCalls, "an administrator needs no grant lookup")
	require.NotContains(t, response.Body.String(), "connections")

	// A member whose names cannot be loaded gets no identity at all rather than
	// one that understates what they may use.
	f, handler = grantFixture(t)
	f.role, f.memberErr = auth.Member, errors.New("SENTINEL_PRIVATE_DRIVER")
	response = requestAuth(handler, "GET", auth.WhoAmIPath, "", bearerHeaders())
	require.Equal(t, 503, response.Code)
	require.NotContains(t, response.Body.String(), "SENTINEL")
}

// Every user route takes a reference: a UUID or a username, sent unchanged for
// the service to resolve. Only a shape that can be neither is refused here.
func TestUserRoutesAcceptReferencesAndRefuseUnusableOnes(t *testing.T) {
	patterns := []string{
		auth.UserBlockPath, auth.UserUnblockPath, auth.UserPasswordPath,
		auth.UserRolePath, auth.RevokePath,
	}
	bodies := map[string]string{
		auth.UserPasswordPath: validPasswordBody,
		auth.UserRolePath:     validRoleBody,
	}
	for _, pattern := range patterns {
		for _, reference := range []string{grantUsername, adminTargetID} {
			f, handler := adminFixture(t)
			headers := bearerHeaders()
			if bodies[pattern] != "" {
				headers.Set("Content-Type", "application/json")
			}
			path := strings.Replace(pattern, "{userID}", reference, 1)
			response := requestAuth(handler, "POST", path, bodies[pattern], headers)
			require.Equal(t, 200, response.Code, path)
			if pattern == auth.RevokePath {
				require.Equal(t, 1, f.revokeCalls, path)
				continue
			}
			// The reference travels unchanged: the service, not the adapter,
			// decides whether it is a UUID or a username.
			require.Equal(t, reference, f.adminCalls[len(f.adminCalls)-1].target, path)
		}
		for _, reference := range []string{"", "ab", "ALICE", "1alice", "a!ice"} {
			f, handler := adminFixture(t)
			headers := bearerHeaders()
			if bodies[pattern] != "" {
				headers.Set("Content-Type", "application/json")
			}
			path := strings.Replace(pattern, "{userID}", reference, 1)
			response := requestAuth(handler, "POST", path, bodies[pattern], headers)
			require.Equal(t, 400, response.Code, path)
			require.Empty(t, f.adminCalls, path)
			require.Zero(t, f.revokeCalls, path)
		}
	}
}

// A UUID-shaped username is refused before the service with the rule spelled
// out, so an agent learns why rather than retrying the same name.
func TestUserCreationRefusesUUIDShapedUsernamesWithAHint(t *testing.T) {
	for _, tc := range []struct {
		name, body, hint string
	}{
		{"uuid-shaped", fmt.Sprintf(`{"username":%q,"password":"valid test password"}`, adminTargetID), auth.UsernameHint},
		{"uppercase", `{"username":"Alice","password":"valid test password"}`, auth.UsernameHint},
		{"short password", `{"username":"alice","password":"short"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := adminFixture(t)
			response := requestAuth(handler, "POST", auth.UsersPath, tc.body, bearerHeaders("Content-Type", "application/json"))
			require.Equal(t, 400, response.Code)
			var failure auth.ErrorResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
			require.Equal(t, auth.InvalidArgument, failure.Error.Code)
			require.Equal(t, tc.hint, failure.Error.Hint)
			require.Empty(t, f.adminCalls, "an invalid body must never reach the service")
		})
	}
}

// A member holding the maximum number of long-named grants still receives a
// whoami body the CLI can read under the general response limit; names past
// the byte budget are dropped in order and reported as truncation.
func TestIdentityNamesStayWithinTheResponseLimit(t *testing.T) {
	f, handler := grantFixture(t)
	f.role = auth.Member
	names := make([]string, auth.MaxConnectionListing)
	for index := range names {
		names[index] = fmt.Sprintf("c%03d-%s", index, strings.Repeat("x", 59))
	}
	f.grantedNames = names
	response := requestAuth(handler, "GET", auth.WhoAmIPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.LessOrEqual(t, response.Body.Len(), auth.MaxResponseBody)
	var identity auth.Identity
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &identity))
	require.True(t, identity.ConnectionsTruncated)
	require.NotEmpty(t, identity.Connections)
	require.Less(t, len(identity.Connections), len(names))
	require.Equal(t, names[:len(identity.Connections)], identity.Connections, "names are dropped from the end only")

	kept, truncated := boundedNames([]string{"a", "b"}, false)
	require.Equal(t, []string{"a", "b"}, kept)
	require.False(t, truncated)
	kept, truncated = boundedNames(nil, true)
	require.Empty(t, kept)
	require.True(t, truncated)
}
