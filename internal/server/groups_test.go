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

// fakeGroups records exactly what each group route handed the service, so a
// rejected request can be proven never to have reached it. It is embedded in
// backendFixture, which supplies the session.
type fakeGroups struct {
	groupList     auth.GroupList
	groupRecord   auth.Group
	groupMutation auth.GroupMutation
	groupDeletion auth.GroupDeletion
	memberList    auth.MemberList
	membership    auth.MembershipMutation
	removal       auth.MembershipRemoval
	groupErr      error
	groupCalls    []groupCall
	groupBlock    func(context.Context)
}

type groupCall struct {
	operation string
	target    string
	user      string
	request   auth.GroupRequest
	update    auth.GroupUpdate
	dryRun    bool
	limit     int
	role      auth.Role
}

func (f *fakeGroups) groupCall(ctx context.Context, session auth.Session, call groupCall) {
	call.role = session.User.Role
	f.groupCalls = append(f.groupCalls, call)
	if f.groupBlock != nil {
		f.groupBlock(ctx)
	}
}

func (f *fakeGroups) ListGroups(ctx context.Context, session auth.Session, limit int) (auth.GroupList, error) {
	f.groupCall(ctx, session, groupCall{operation: "list", limit: limit})
	return f.groupList, f.groupErr
}

func (f *fakeGroups) GetGroup(ctx context.Context, session auth.Session, ref string) (auth.Group, error) {
	f.groupCall(ctx, session, groupCall{operation: "get", target: ref})
	return f.groupRecord, f.groupErr
}

func (f *fakeGroups) CreateGroup(ctx context.Context, session auth.Session,
	request auth.GroupRequest, dryRun bool) (auth.GroupMutation, error) {
	f.groupCall(ctx, session, groupCall{operation: "create", request: request, dryRun: dryRun})
	return f.groupMutation, f.groupErr
}

func (f *fakeGroups) UpdateGroup(ctx context.Context, session auth.Session, ref string,
	update auth.GroupUpdate, dryRun bool) (auth.GroupMutation, error) {
	f.groupCall(ctx, session, groupCall{operation: "update", target: ref, update: update, dryRun: dryRun})
	return f.groupMutation, f.groupErr
}

func (f *fakeGroups) DeleteGroup(ctx context.Context, session auth.Session, ref string,
	dryRun bool) (auth.GroupDeletion, error) {
	f.groupCall(ctx, session, groupCall{operation: "delete", target: ref, dryRun: dryRun})
	return f.groupDeletion, f.groupErr
}

func (f *fakeGroups) ListMembers(ctx context.Context, session auth.Session, ref string, limit int) (auth.MemberList, error) {
	f.groupCall(ctx, session, groupCall{operation: "members", target: ref, limit: limit})
	return f.memberList, f.groupErr
}

func (f *fakeGroups) AddMember(ctx context.Context, session auth.Session, groupRef, userRef string,
	dryRun bool) (auth.MembershipMutation, error) {
	f.groupCall(ctx, session, groupCall{operation: "add", target: groupRef, user: userRef, dryRun: dryRun})
	return f.membership, f.groupErr
}

func (f *fakeGroups) RemoveMember(ctx context.Context, session auth.Session, groupRef, userRef string,
	dryRun bool) (auth.MembershipRemoval, error) {
	f.groupCall(ctx, session, groupCall{operation: "remove", target: groupRef, user: userRef, dryRun: dryRun})
	return f.removal, f.groupErr
}

const (
	groupID        = "abcdefab-1234-4234-8234-1234567890b1"
	groupName      = "finance-managers"
	validGroupBody = `{"name":"finance-managers","description":"Finance managers"}`
	validMemberAdd = `{"user":"alice"}`
)

var (
	groupTime   = time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)
	groupRecord = auth.Group{
		ID: groupID, Name: groupName, Description: "Finance managers",
		CreatedAt: groupTime, UpdatedAt: groupTime, Members: 3, Grants: 2,
	}
	groupParty     = auth.GrantParty{ID: groupID, Name: groupName}
	groupCreated   = auth.GroupMutation{Group: groupRecord}
	groupRemoved   = auth.GroupDeletion{Group: groupParty}
	groupListing   = auth.GroupList{Groups: []auth.Group{groupRecord}, Truncated: true}
	memberRecord   = auth.GroupMember{UserRecord: listedMember, AddedAt: groupTime, AddedBy: auth.GrantParty{ID: grantAdminID, Name: "personal-admin"}}
	memberListing  = auth.MemberList{Members: []auth.GroupMember{memberRecord}, Truncated: true}
	listedMember   = auth.UserRecord{ID: grantUserID, Username: grantUsername, Role: auth.Member, CreatedAt: groupTime}
	membershipMade = auth.MembershipMutation{
		Membership: auth.Membership{
			Group: groupParty, User: auth.GrantParty{ID: grantUserID, Name: grantUsername},
			CreatedAt: groupTime, CreatedBy: auth.GrantParty{ID: grantAdminID, Name: "personal-admin"},
		},
		Added: true,
	}
	membershipGone = auth.MembershipRemoval{Group: groupParty,
		User: auth.GrantParty{ID: grantUserID, Name: grantUsername}, Removed: true}
)

// groupPath substitutes the one reference every targeted group route takes.
func groupPath(pattern, reference string) string {
	return strings.Replace(pattern, "{groupID}", reference, 1)
}

// groupRoute is the design's group route table expressed once: every test
// below walks all eight routes rather than a representative subset.
type groupRoute struct {
	name, method, pattern, body, operation string
	success                                int
	expected                               any
	targeted, dryRunnable                  bool
}

func groupRoutes() []groupRoute {
	return []groupRoute{
		{"list", "GET", auth.GroupsPath, "", "list", 200, groupListing, false, false},
		{"create", "POST", auth.GroupsPath, validGroupBody, "create", 201, groupCreated, false, true},
		{"get", "GET", auth.GroupPath, "", "get", 200, groupRecord, true, false},
		{"update", "POST", auth.GroupUpdatePath, `{"description":"Finance"}`, "update", 200, groupCreated, true, true},
		{"delete", "POST", auth.GroupDeletePath, "", "delete", 200, groupRemoved, true, true},
		{"members", "GET", auth.GroupMembersPath, "", "members", 200, memberListing, true, false},
		{"add", "POST", auth.GroupMemberAddPath, validMemberAdd, "add", 201, membershipMade, true, true},
		{"remove", "POST", auth.GroupMemberRemovePath, validMemberAdd, "remove", 200, membershipGone, true, true},
	}
}

func (route groupRoute) path() string { return groupPath(route.pattern, groupName) }

func (route groupRoute) headers() http.Header {
	headers := bearerHeaders()
	if route.body != "" {
		headers.Set("Content-Type", "application/json")
	}
	return headers
}

func groupFixture(t *testing.T) (*backendFixture, http.Handler) {
	t.Helper()
	f := &backendFixture{}
	f.groupList, f.groupRecord, f.groupMutation = groupListing, groupRecord, groupCreated
	f.groupDeletion, f.memberList = groupRemoved, memberListing
	f.membership, f.removal = membershipMade, membershipGone
	return f, authHandler(t, f, nil, "http://127.0.0.1")
}

func TestGroupRoutesReturnDocumentedSuccessBodies(t *testing.T) {
	for _, route := range groupRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := groupFixture(t)
			// Browser negotiation headers must never turn a JSON route into a
			// document or a redirect.
			headers := route.headers()
			headers.Set("Accept", "text/html")
			headers.Set("Hx-Request", "true")
			response := requestAuth(handler, route.method, route.path(), route.body, headers)
			require.Equal(t, route.success, response.Code)
			require.Equal(t, "application/json", response.Header().Get("Content-Type"))
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.Empty(t, response.Header().Get("Location"))
			require.Empty(t, response.Header().Get("Set-Cookie"))
			expected, err := json.Marshal(route.expected)
			require.NoError(t, err)
			require.JSONEq(t, string(expected), response.Body.String())
			require.Len(t, f.groupCalls, 1)
			require.Equal(t, route.operation, f.groupCalls[0].operation)
			require.False(t, f.groupCalls[0].dryRun)
		})
	}
}

// Adding a member is idempotent, so its status carries the only fact a
// retrying agent needs: 201 when the membership was written, 200 when it was
// already in place.
func TestMemberAdditionAnswers200WhenTheMembershipExisted(t *testing.T) {
	f, handler := groupFixture(t)
	f.membership = auth.MembershipMutation{Membership: membershipMade.Membership}
	response := requestAuth(handler, "POST", groupPath(auth.GroupMemberAddPath, groupName), validMemberAdd,
		bearerHeaders("Content-Type", "application/json"))
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), `"added":false`)
}

func TestGroupRoutesHandTheServiceExactlyWhatWasAsked(t *testing.T) {
	f, handler := groupFixture(t)
	description, renamed := "Finance", "finance-leads"
	for _, tc := range []struct{ method, path, body string }{
		{"GET", auth.GroupsPath, ""},
		{"GET", auth.GroupsPath + "?limit=7", ""},
		{"POST", auth.GroupsPath, validGroupBody},
		{"GET", groupPath(auth.GroupPath, groupID), ""},
		{"POST", groupPath(auth.GroupUpdatePath, groupName), `{"name":"finance-leads","description":"Finance"}`},
		{"POST", groupPath(auth.GroupDeletePath, groupName), ""},
		{"GET", groupPath(auth.GroupMembersPath, groupName) + "?limit=3", ""},
		{"POST", groupPath(auth.GroupMemberAddPath, groupName), `{"user":"` + grantUserID + `"}`},
		{"POST", groupPath(auth.GroupMemberRemovePath, groupID), validMemberAdd},
	} {
		headers := bearerHeaders()
		if tc.body != "" {
			headers.Set("Content-Type", "application/json")
		}
		require.Less(t, requestAuth(handler, tc.method, tc.path, tc.body, headers).Code, 300, tc.path)
	}
	require.Equal(t, []groupCall{
		// A missing limit asks for the documented bound, not for nothing.
		{operation: "list", role: auth.Admin, limit: auth.MaxGroupListing},
		{operation: "list", role: auth.Admin, limit: 7},
		{operation: "create", role: auth.Admin, request: auth.GroupRequest{Name: groupName, Description: "Finance managers"}},
		// The reference travels unchanged: the service decides whether it is a
		// UUID or a name.
		{operation: "get", role: auth.Admin, target: groupID},
		{operation: "update", role: auth.Admin, target: groupName,
			update: auth.GroupUpdate{Name: &renamed, Description: &description}},
		{operation: "delete", role: auth.Admin, target: groupName},
		{operation: "members", role: auth.Admin, target: groupName, limit: 3},
		{operation: "add", role: auth.Admin, target: groupName, user: grantUserID},
		{operation: "remove", role: auth.Admin, target: groupID, user: grantUsername},
	}, f.groupCalls)
}

func TestGroupDryRunIsRequestedExplicitlyAndMarksTheResult(t *testing.T) {
	for _, route := range groupRoutes() {
		if !route.dryRunnable {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			f, handler := groupFixture(t)
			f.groupMutation.DryRun, f.groupDeletion.DryRun = true, true
			f.membership.DryRun, f.removal.DryRun = true, true
			response := requestAuth(handler, route.method, route.path()+"?dryRun=true", route.body, route.headers())
			// A rehearsed creation answers 200 with the mutation it would have
			// made rather than 201 with a group that does not exist.
			require.Equal(t, 200, response.Code)
			require.Len(t, f.groupCalls, 1)
			require.True(t, f.groupCalls[0].dryRun)
			require.Contains(t, response.Body.String(), `"dryRun":true`)
		})
	}
}

// The routes field is the design's per-route error column: a nil list means
// every route, and a named list keeps undocumented pairings out of the
// asserted contract. The hint is the service's, passed through unchanged.
func TestGroupServiceFailuresUseDocumentedStatusesAndHints(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		hint   string
		routes []string
	}{
		{&auth.Error{Code: auth.Unauthenticated}, 401, auth.Unauthenticated, "", nil},
		{&auth.Error{Code: auth.Forbidden}, 403, auth.Forbidden, "", nil},
		{&auth.Error{Code: auth.GroupNotFound, Hint: "List groups to find the name."}, 404, auth.GroupNotFound,
			"List groups to find the name.", []string{"get", "update", "delete", "members", "add", "remove"}},
		{&auth.Error{Code: auth.GroupExists, Hint: "Choose another name."}, 409, auth.GroupExists,
			"Choose another name.", []string{"create", "update"}},
		{&auth.Error{Code: auth.GroupInUse, Hint: "Revoke the 2 remaining grants first."}, 409, auth.GroupInUse,
			"Revoke the 2 remaining grants first.", []string{"delete"}},
		{&auth.Error{Code: auth.UserNotFound, Hint: "List users to find the username."}, 404, auth.UserNotFound,
			"List users to find the username.", []string{"add", "remove"}},
		{errors.New("SENTINEL_PRIVATE_DRIVER"), 503, auth.ServiceUnavailable, "", nil},
	} {
		for _, route := range groupRoutes() {
			if len(tc.routes) != 0 && !slices.Contains(tc.routes, route.name) {
				continue
			}
			t.Run(tc.code+"/"+route.name, func(t *testing.T) {
				f, handler := groupFixture(t)
				f.groupErr = tc.err
				response := requestAuth(handler, route.method, route.path(), route.body, route.headers())
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

func TestGroupBodiesAndQueriesAreStrict(t *testing.T) {
	long := strings.Repeat("g", auth.MaxCredentialBody)
	for _, tc := range []struct {
		name, method, path, body, contentType string
	}{
		{"unknown field", "POST", auth.GroupsPath, `{"name":"finance-managers","members":3}`, "application/json"},
		{"duplicate field", "POST", auth.GroupsPath, `{"name":"a-group","name":"b-group"}`, "application/json"},
		{"case alias", "POST", auth.GroupsPath, `{"Name":"finance-managers"}`, "application/json"},
		{"null name", "POST", auth.GroupsPath, `{"name":null}`, "application/json"},
		{"numeric name", "POST", auth.GroupsPath, `{"name":7}`, "application/json"},
		{"trailing document", "POST", auth.GroupsPath, validGroupBody + `{}`, "application/json"},
		{"empty create", "POST", auth.GroupsPath, `{}`, "application/json"},
		{"uppercase name", "POST", auth.GroupsPath, `{"name":"Finance"}`, "application/json"},
		{"short name", "POST", auth.GroupsPath, `{"name":"ab"}`, "application/json"},
		{"uuid-shaped name", "POST", auth.GroupsPath, `{"name":"` + groupID + `"}`, "application/json"},
		{"form create", "POST", auth.GroupsPath, "name=finance-managers", "application/x-www-form-urlencoded"},
		{"typeless create", "POST", auth.GroupsPath, validGroupBody, ""},
		{"oversized create", "POST", auth.GroupsPath, `{"name":"finance-managers","description":"` + long + `"}`, "application/json"},
		{"create dry run value", "POST", auth.GroupsPath + "?dryRun=yes", validGroupBody, "application/json"},
		{"create unknown parameter", "POST", auth.GroupsPath + "?limit=1", validGroupBody, "application/json"},
		{"listing body", "GET", auth.GroupsPath, `{"groups":[]}`, "application/json"},
		{"listing limit zero", "GET", auth.GroupsPath + "?limit=0", "", ""},
		{"listing limit above bound", "GET", auth.GroupsPath + "?limit=1001", "", ""},
		{"listing limit text", "GET", auth.GroupsPath + "?limit=abc", "", ""},
		{"listing limit repeated", "GET", auth.GroupsPath + "?limit=1&limit=2", "", ""},
		{"listing unknown parameter", "GET", auth.GroupsPath + "?dryRun=true", "", ""},
		{"listing malformed", "GET", auth.GroupsPath + "?limit=%zz", "", ""},
		{"get query", "GET", groupPath(auth.GroupPath, groupName) + "?limit=1", "", ""},
		{"get body", "GET", groupPath(auth.GroupPath, groupName), `{}`, "application/json"},
		{"empty update", "POST", groupPath(auth.GroupUpdatePath, groupName), `{}`, "application/json"},
		{"update bad name", "POST", groupPath(auth.GroupUpdatePath, groupName), `{"name":"FINANCE"}`, "application/json"},
		{"update unknown field", "POST", groupPath(auth.GroupUpdatePath, groupName), `{"members":1}`, "application/json"},
		{"delete body", "POST", groupPath(auth.GroupDeletePath, groupName), `{}`, "application/json"},
		{"delete dry run bare", "POST", groupPath(auth.GroupDeletePath, groupName) + "?dryRun", "", ""},
		{"members limit zero", "GET", groupPath(auth.GroupMembersPath, groupName) + "?limit=0", "", ""},
		{"members body", "GET", groupPath(auth.GroupMembersPath, groupName), `{}`, "application/json"},
		{"add no user", "POST", groupPath(auth.GroupMemberAddPath, groupName), `{}`, "application/json"},
		{"add bad user", "POST", groupPath(auth.GroupMemberAddPath, groupName), `{"user":"ALICE"}`, "application/json"},
		{"add unknown field", "POST", groupPath(auth.GroupMemberAddPath, groupName), `{"user":"alice","group":"x"}`, "application/json"},
		{"remove bad user", "POST", groupPath(auth.GroupMemberRemovePath, groupName), `{"user":"1alice"}`, "application/json"},
		{"remove typeless", "POST", groupPath(auth.GroupMemberRemovePath, groupName), validMemberAdd, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := groupFixture(t)
			headers := bearerHeaders()
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			response := requestAuth(handler, tc.method, tc.path, tc.body, headers)
			require.Equal(t, 400, response.Code)
			require.Contains(t, response.Body.String(), auth.InvalidArgument)
			require.Empty(t, f.groupCalls, "an invalid request must never reach the service")
		})
	}
}

// The chosen name and the empty update are the two rules this adapter owns, so
// each is refused with the rule it broke rather than a bare rejection.
func TestGroupAdapterRulesCarryTheirHints(t *testing.T) {
	for _, tc := range []struct{ path, body, hint string }{
		{auth.GroupsPath, `{"name":"Finance"}`, hintGroupName},
		{groupPath(auth.GroupUpdatePath, groupName), `{"name":"Finance"}`, hintGroupName},
		{groupPath(auth.GroupUpdatePath, groupName), `{}`, hintEmptyUpdate},
	} {
		f, handler := groupFixture(t)
		response := requestAuth(handler, "POST", tc.path, tc.body, bearerHeaders("Content-Type", "application/json"))
		require.Equal(t, 400, response.Code)
		var failure auth.ErrorResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
		require.Equal(t, auth.InvalidArgument, failure.Error.Code)
		require.Equal(t, tc.hint, failure.Error.Hint)
		require.Empty(t, f.groupCalls)
	}
}

// Every targeted group route takes a reference: a UUID or a name, sent
// unchanged for the service to resolve. Only a shape that can be neither is
// refused here, including the empty segment of a doubled slash.
func TestGroupRoutesRefuseUnusableReferences(t *testing.T) {
	for _, route := range groupRoutes() {
		if !route.targeted {
			continue
		}
		for _, reference := range []string{"ab", "FINANCE", "1finance", "fin!ance"} {
			f, handler := groupFixture(t)
			response := requestAuth(handler, route.method, groupPath(route.pattern, reference), route.body, route.headers())
			require.Equal(t, 400, response.Code, route.name+"/"+reference)
			require.Empty(t, f.groupCalls)
		}
		// The empty segment of a doubled slash is refused too. The bare
		// collection path has a route of its own, so only the routes with a
		// suffix reach the handler; either way the service is never invoked.
		f, handler := groupFixture(t)
		response := requestAuth(handler, route.method, groupPath(route.pattern, ""), route.body, route.headers())
		require.Contains(t, []int{400, 404}, response.Code, route.name)
		require.Empty(t, f.groupCalls, route.name)
	}
}

// A cookie is not a CLI credential: the group routes are bearer-only exactly
// like the connection routes, and an ambiguous credential never reaches them.
func TestGroupRoutesAreBearerOnly(t *testing.T) {
	for _, route := range groupRoutes() {
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
				f, handler := groupFixture(t)
				headers := tc.headers.Clone()
				if route.body != "" {
					headers.Set("Content-Type", "application/json")
				}
				response := requestAuth(handler, route.method, route.path(), route.body, headers)
				require.Equal(t, tc.status, response.Code)
				require.Empty(t, response.Header().Get("Set-Cookie"))
				require.Empty(t, f.groupCalls)
			})
		}
	}
}

// Members are not refused here: every group operation is administrator-only,
// and the service rechecks the caller's current role inside its transaction,
// so the adapter hands it the session rather than deciding on the role itself.
func TestGroupRoutesPassMemberSessionsToTheService(t *testing.T) {
	for _, route := range groupRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := groupFixture(t)
			f.role = auth.Member
			f.groupErr = &auth.Error{Code: auth.Forbidden}
			response := requestAuth(handler, route.method, route.path(), route.body, route.headers())
			require.Equal(t, 403, response.Code)
			require.Len(t, f.groupCalls, 1)
			require.Equal(t, auth.Member, f.groupCalls[0].role)
		})
	}
}

func TestGroupRoutesFailClosedWithoutAService(t *testing.T) {
	for _, route := range groupRoutes() {
		f := &backendFixture{}
		adapter, err := newAuthHTTP("http://127.0.0.1", f, fixtureViews())
		require.NoError(t, err)
		adapter.admin, adapter.connections, adapter.grants, adapter.members = f, f, f, f
		ready := platform.CheckFunc(func(context.Context) platform.Readiness { return platform.Readiness{State: platform.Ready} })
		handler := handler(time.Second, ready, slog.New(slog.NewJSONHandler(io.Discard, nil)), adapter)
		response := requestAuth(handler, route.method, route.path(), route.body, route.headers())
		require.Equal(t, 503, response.Code, route.name)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
		require.Empty(t, f.groupCalls)
	}
}

func TestGroupRoutesHonorTheOperationDeadline(t *testing.T) {
	for _, route := range groupRoutes() {
		f, handler := groupFixture(t)
		f.groupBlock = func(ctx context.Context) { <-ctx.Done() }
		start := time.Now()
		response := requestAuth(handler, route.method, route.path(), route.body, route.headers())
		require.Equal(t, 503, response.Code, route.name)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
		require.Less(t, time.Since(start), 7*time.Second)
	}
}

// maximalGroup is the largest group the contract allows: a full-length name
// and a description at the documented bound. A thousand of them are larger
// than the listing body, so the byte budget, not the row bound, truncates.
func maximalGroup() auth.Group {
	return auth.Group{
		ID: groupID, Name: "g" + strings.Repeat("z", 63),
		Description: strings.Repeat("d", auth.MaxDescriptionLength),
		CreatedAt:   groupTime, UpdatedAt: groupTime, Members: 1000, Grants: 1000,
	}
}

func maximalMember() auth.GroupMember {
	return auth.GroupMember{
		UserRecord: auth.UserRecord{ID: grantUserID, Username: "u" + strings.Repeat("z", 63),
			Role: auth.Member, CreatedAt: groupTime},
		AddedAt: groupTime,
		AddedBy: auth.GrantParty{ID: grantAdminID, Name: "a" + strings.Repeat("z", 63)},
	}
}

// A legitimate listing far above the general 64 KiB response limit is answered
// under the listing limit instead of refused, and only the byte budget, not
// the row bound, decides where it stops.
func TestGroupListingsStayWithinTheDocumentedBodyLimit(t *testing.T) {
	f, handler := groupFixture(t)
	groups := make([]auth.Group, 0, auth.MaxGroupListing)
	for index := 0; index < auth.MaxGroupListing; index++ {
		groups = append(groups, maximalGroup())
	}
	f.groupList = auth.GroupList{Groups: groups}
	response := requestAuth(handler, "GET", auth.GroupsPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.Greater(t, response.Body.Len(), auth.MaxResponseBody, "a legitimate listing exceeds the general limit")
	require.LessOrEqual(t, response.Body.Len(), auth.MaxListingBody)
	var decoded auth.GroupList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
	require.True(t, decoded.Truncated)
	require.Greater(t, len(decoded.Groups), 0)
	require.Less(t, len(decoded.Groups), auth.MaxGroupListing)
	require.Equal(t, auth.MaxGroupListing, f.groupCalls[0].limit)

	f, handler = groupFixture(t)
	members := make([]auth.GroupMember, 0, auth.MaxMemberListing)
	for index := 0; index < auth.MaxMemberListing; index++ {
		members = append(members, maximalMember())
	}
	f.memberList = auth.MemberList{Members: members}
	response = requestAuth(handler, "GET", groupPath(auth.GroupMembersPath, groupName), "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.LessOrEqual(t, response.Body.Len(), auth.MaxListingBody)
	var membersDecoded auth.MemberList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &membersDecoded))
	require.True(t, membersDecoded.Truncated)
	require.Less(t, len(membersDecoded.Members), auth.MaxMemberListing)
}

// The row bound is the service's, and the adapter reports it unchanged: a
// listing truncated at the ceiling stays truncated in the response even when
// every record fits the byte budget.
func TestGroupListingsReportTheServiceCeiling(t *testing.T) {
	f, handler := groupFixture(t)
	groups := make([]auth.Group, 0, auth.MaxGroupListing)
	for index := 0; index < auth.MaxGroupListing; index++ {
		groups = append(groups, auth.Group{ID: groupID, Name: fmt.Sprintf("g%03d", index),
			CreatedAt: groupTime, UpdatedAt: groupTime})
	}
	f.groupList = auth.GroupList{Groups: groups, Truncated: true}
	response := requestAuth(handler, "GET", auth.GroupsPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	var decoded auth.GroupList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
	require.Len(t, decoded.Groups, auth.MaxGroupListing, "the byte budget must not truncate these")
	require.True(t, decoded.Truncated)
}

// An empty listing is a documented answer, not an absent one: the array is
// present and empty so a client never has to tell null from [].
func TestGroupListingsAnswerEmptyLists(t *testing.T) {
	f, handler := groupFixture(t)
	f.groupList, f.memberList = auth.GroupList{Groups: []auth.Group{}}, auth.MemberList{Members: []auth.GroupMember{}}
	response := requestAuth(handler, "GET", auth.GroupsPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.JSONEq(t, `{"groups":[],"truncated":false}`, response.Body.String())
	response = requestAuth(handler, "GET", groupPath(auth.GroupMembersPath, groupName), "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.JSONEq(t, `{"members":[],"truncated":false}`, response.Body.String())
}
