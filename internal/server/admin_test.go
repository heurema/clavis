package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

// fakeAdministration records what each route handed to the service so a
// rejected request can be proven never to have reached it. It is embedded in
// backendFixture, which supplies the session and the event recorder.
type fakeAdministration struct {
	list                                              auth.UserList
	record                                            auth.UserRecord
	mutation                                          auth.UserMutation
	listErr, createErr, disableErr, resetErr, roleErr error
	adminCalls                                        []adminCall
	adminBlock                                        func(context.Context)
}

type adminCall struct {
	operation, target, username string
	password                    auth.Secret
	disabled                    bool
	role                        auth.Role
}

func (f *fakeAdministration) call(ctx context.Context, call adminCall) {
	f.adminCalls = append(f.adminCalls, call)
	if f.adminBlock != nil {
		f.adminBlock(ctx)
	}
}

func (f *fakeAdministration) ListUsers(ctx context.Context, _ auth.Session) (auth.UserList, error) {
	f.call(ctx, adminCall{operation: "list"})
	return f.list, f.listErr
}

func (f *fakeAdministration) CreateUser(ctx context.Context, _ auth.Session, request auth.CreateUserRequest) (auth.UserRecord, error) {
	f.call(ctx, adminCall{operation: "create", username: request.Username, password: request.Password})
	return f.record, f.createErr
}

func (f *fakeAdministration) SetUserDisabled(ctx context.Context, _ auth.Session, userID string, disabled bool) (auth.UserMutation, error) {
	f.call(ctx, adminCall{operation: "disable", target: userID, disabled: disabled})
	return f.mutation, f.disableErr
}

func (f *fakeAdministration) ResetPassword(ctx context.Context, _ auth.Session, userID string, password auth.Secret) (auth.UserMutation, error) {
	f.call(ctx, adminCall{operation: "reset", target: userID, password: password})
	return f.mutation, f.resetErr
}

func (f *fakeAdministration) SetRole(ctx context.Context, _ auth.Session, userID string, role auth.Role) (auth.UserMutation, error) {
	f.call(ctx, adminCall{operation: "role", target: userID, role: role})
	return f.mutation, f.roleErr
}

const adminTargetID = "abcdefab-1234-4234-8234-123456789abc"

func userPath(pattern string) string {
	return strings.Replace(pattern, "{userID}", adminTargetID, 1)
}

func bearerHeaders(extra ...string) http.Header {
	headers := http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}
	for index := 0; index+1 < len(extra); index += 2 {
		headers.Set(extra[index], extra[index+1])
	}
	return headers
}

var (
	adminCreated  = time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	adminRecord   = auth.UserRecord{ID: adminTargetID, Username: "member-user", Role: auth.Member, CreatedAt: adminCreated}
	adminMutation = auth.UserMutation{User: adminRecord, SessionsRevoked: true}
	adminList     = auth.UserList{Users: []auth.UserRecord{adminRecord}, Truncated: true}
)

const (
	validCreateBody   = `{"username":"member-user","password":"valid test password"}`
	validPasswordBody = `{"password":"another valid password"}`
	validRoleBody     = `{"role":"admin"}`
)

// administrationRoute is the design's route table expressed once: every test
// below walks all six routes rather than a representative subset.
type administrationRoute struct {
	name, method, path, body string
	success                  int
	action                   auth.EventAction
	expected                 any
}

func administrationRoutes() []administrationRoute {
	return []administrationRoute{
		{"list", "GET", auth.UsersPath, "", 200, auth.EventUsersList, adminList},
		{"create", "POST", auth.UsersPath, validCreateBody, 201, auth.EventUserCreate, adminRecord},
		{"block", "POST", userPath(auth.UserBlockPath), "", 200, auth.EventUserBlock, adminMutation},
		{"unblock", "POST", userPath(auth.UserUnblockPath), "", 200, auth.EventUserUnblock, adminMutation},
		{"password", "POST", userPath(auth.UserPasswordPath), validPasswordBody, 200, auth.EventUserResetPassword, adminMutation},
		// A rejected role request is recorded as user.demote whatever it asked
		// for; the adapter must not trust the submitted role.
		{"role", "POST", userPath(auth.UserRolePath), validRoleBody, 200, auth.EventUserDemote, adminMutation},
	}
}

func (route administrationRoute) headers() http.Header {
	headers := bearerHeaders()
	if route.body != "" {
		headers.Set("Content-Type", "application/json")
	}
	return headers
}

func adminFixture(t *testing.T) (*backendFixture, http.Handler) {
	t.Helper()
	f := &backendFixture{}
	f.list, f.record, f.mutation = adminList, adminRecord, adminMutation
	return f, authHandler(t, f, nil, "http://127.0.0.1")
}

func TestAdministrationRoutesReturnDocumentedSuccessBodies(t *testing.T) {
	for _, route := range administrationRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := adminFixture(t)
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
			require.Len(t, f.adminCalls, 1)
			require.Empty(t, f.events, "a service-owned outcome must not be recorded again by the adapter")
		})
	}
	f, handler := adminFixture(t)
	require.Equal(t, 200, requestAuth(handler, "POST", userPath(auth.UserBlockPath), "", bearerHeaders()).Code)
	require.Equal(t, 200, requestAuth(handler, "POST", userPath(auth.UserUnblockPath), "", bearerHeaders()).Code)
	require.Equal(t, 200, requestAuth(handler, "POST", userPath(auth.UserPasswordPath), validPasswordBody,
		bearerHeaders("Content-Type", "application/json")).Code)
	require.Equal(t, 200, requestAuth(handler, "POST", userPath(auth.UserRolePath), `{"role":"member"}`,
		bearerHeaders("Content-Type", "application/json")).Code)
	require.Equal(t, []adminCall{
		{operation: "disable", target: adminTargetID, disabled: true},
		{operation: "disable", target: adminTargetID, disabled: false},
		{operation: "reset", target: adminTargetID, password: "another valid password"},
		{operation: "role", target: adminTargetID, role: auth.Member},
	}, f.adminCalls)
}

// The routes field is the design's per-route error column: a nil list means
// every route, and a named list keeps undocumented pairings (429 on listing,
// USERNAME_TAKEN on a mutation) out of the asserted contract.
func TestAdministrationServiceFailuresUseDocumentedStatuses(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		routes []string
	}{
		{&auth.Error{Code: auth.Unauthenticated}, 401, auth.Unauthenticated, nil},
		{&auth.Error{Code: auth.Forbidden}, 403, auth.Forbidden, nil},
		{&auth.Error{Code: auth.UserNotFound}, 404, auth.UserNotFound, []string{"block", "unblock", "password", "role"}},
		{&auth.Error{Code: auth.UsernameTaken}, 409, auth.UsernameTaken, []string{"create"}},
		{&auth.Error{Code: auth.LastAdministrator}, 409, auth.LastAdministrator, []string{"block", "role"}},
		{&auth.Error{Code: auth.SelfTarget}, 409, auth.SelfTarget, []string{"block", "role"}},
		{&auth.Error{Code: auth.RateLimited, RetryAfter: 3 * time.Second}, 429, auth.RateLimited, []string{"create", "password"}},
		{&auth.Error{Code: platform.CodeSetupRequired}, 503, platform.CodeSetupRequired, nil},
		{errors.New("SENTINEL_PRIVATE_DRIVER"), 503, auth.ServiceUnavailable, nil},
	} {
		for _, route := range administrationRoutes() {
			if len(tc.routes) != 0 && !slices.Contains(tc.routes, route.name) {
				continue
			}
			t.Run(tc.code+"/"+route.name, func(t *testing.T) {
				f, handler := adminFixture(t)
				f.listErr, f.createErr, f.disableErr, f.resetErr, f.roleErr = tc.err, tc.err, tc.err, tc.err, tc.err
				response := requestAuth(handler, route.method, route.path, route.body, route.headers())
				require.Equal(t, tc.status, response.Code)
				require.Contains(t, response.Body.String(), tc.code)
				require.NotContains(t, response.Body.String(), "SENTINEL")
				require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				require.Len(t, f.adminCalls, 1)
				require.Empty(t, f.events)
				if tc.status == 429 {
					require.Equal(t, "3", response.Header().Get("Retry-After"))
				}
			})
		}
	}
}

func TestAdministrationRequiresBearerCredentials(t *testing.T) {
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
		for _, route := range administrationRoutes() {
			t.Run(tc.name+"/"+route.name, func(t *testing.T) {
				f, handler := adminFixture(t)
				headers := tc.headers.Clone()
				if route.body != "" {
					headers.Set("Content-Type", "application/json")
				}
				response := requestAuth(handler, route.method, route.path, route.body, headers)
				require.Equal(t, tc.status, response.Code)
				require.Equal(t, "application/json", response.Header().Get("Content-Type"))
				require.Empty(t, response.Header().Get("Location"))
				require.Empty(t, response.Header().Get("Set-Cookie"))
				require.Empty(t, f.adminCalls, "no mutation may reach the service")
				require.Equal(t, []auth.Event{{Action: route.action, Outcome: tc.outcome}}, f.events)
			})
		}
	}
}

func TestAdministrationBodiesAreStrictAndUnreflected(t *testing.T) {
	const sentinel = "SENTINEL_PRIVATE_PASSWORD"
	bodies := map[string][]string{
		"create": {
			`{"username":"member-user","password":"` + sentinel + `","extra":"x"}`,
			`{"username":"member-user","password":"` + sentinel + `"} {}`,
			`{"username":"member-user","username":"other","password":"` + sentinel + `"}`,
			`{"Username":"member-user","password":"` + sentinel + `"}`,
			`{"username":"member-user","password":null}`,
			`{"username":"MEMBER-USER","password":"` + sentinel + `"}`,
			`{"username":"member-user","password":"short"}`,
			`[]`,
			`{"username":"member-user","password":"` + strings.Repeat("x", 8193) + `"}`,
		},
		"password": {
			`{"password":"` + sentinel + `","extra":"x"}`,
			`{"password":"` + sentinel + `"} {}`,
			`{"password":"` + sentinel + `","password":"` + sentinel + `"}`,
			`{"Password":"` + sentinel + `"}`,
			`{"password":null}`,
			`{"password":"short"}`,
			`{}`,
		},
		"role": {
			`{"role":"admin","extra":"x"}`,
			`{"role":"admin"} {}`,
			`{"role":"admin","role":"member"}`,
			`{"Role":"admin"}`,
			`{"role":null}`,
			`{"role":"SENTINEL_PRIVATE_ROLE"}`,
			`{"role":"Admin"}`,
			`{}`,
		},
	}
	for _, route := range administrationRoutes() {
		for index, body := range bodies[route.name] {
			t.Run(route.name+"/"+strconv.Itoa(index), func(t *testing.T) {
				f, handler := adminFixture(t)
				response := requestAuth(handler, route.method, route.path, body, bearerHeaders("Content-Type", "application/json"))
				require.Equal(t, 400, response.Code)
				require.Contains(t, response.Body.String(), auth.InvalidArgument)
				require.NotContains(t, response.Body.String(), "SENTINEL")
				require.NotContains(t, response.Body.String(), "member-user")
				require.Empty(t, f.adminCalls, "an invalid body must never reach hashing or the service")
				require.Equal(t, []auth.Event{{Action: route.action, Outcome: auth.OutcomeInvalidArgument}}, f.events)
			})
		}
	}
	// Wrong or absent content types and bodies on bodyless routes.
	for _, tc := range []struct {
		name, method, path, body, contentType string
		action                                auth.EventAction
	}{
		{"form create", "POST", auth.UsersPath, "username=member-user&password=" + sentinel, "application/x-www-form-urlencoded", auth.EventUserCreate},
		{"typeless create", "POST", auth.UsersPath, validCreateBody, "", auth.EventUserCreate},
		{"form password", "POST", userPath(auth.UserPasswordPath), "password=" + sentinel, "application/x-www-form-urlencoded", auth.EventUserResetPassword},
		{"listing body", "GET", auth.UsersPath, `{"users":[]}`, "application/json", auth.EventUsersList},
		{"block body", "POST", userPath(auth.UserBlockPath), `{}`, "application/json", auth.EventUserBlock},
		{"unblock body", "POST", userPath(auth.UserUnblockPath), `{}`, "application/json", auth.EventUserUnblock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, handler := adminFixture(t)
			headers := bearerHeaders()
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			response := requestAuth(handler, tc.method, tc.path, tc.body, headers)
			require.Equal(t, 400, response.Code)
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Empty(t, f.adminCalls)
			require.Equal(t, []auth.Event{{Action: tc.action, Outcome: auth.OutcomeInvalidArgument}}, f.events)
		})
	}
}

func TestAdministrationRejectsInvalidTargetsAfterIdentifyingTheActor(t *testing.T) {
	const sessionID = "12345678-1234-4234-8234-123456789aaa"
	for _, pattern := range []string{auth.UserBlockPath, auth.UserUnblockPath, auth.UserPasswordPath, auth.UserRolePath} {
		// An empty segment (doubled slash) still matches the route and must be rejected here.
		for _, target := range []string{"", "not-a-uuid", "12345678-1234-4234-8234-123456789ab", "12345678123442348234123456789abc"} {
			f, handler := adminFixture(t)
			path := strings.Replace(pattern, "{userID}", target, 1)
			body := ""
			if pattern == auth.UserPasswordPath {
				body = validPasswordBody
			}
			if pattern == auth.UserRolePath {
				body = validRoleBody
			}
			headers := bearerHeaders()
			if body != "" {
				headers.Set("Content-Type", "application/json")
			}
			response := requestAuth(handler, "POST", path, body, headers)
			require.Equal(t, 400, response.Code, path)
			require.Contains(t, response.Body.String(), auth.InvalidArgument)
			require.Empty(t, f.adminCalls)
			require.Len(t, f.events, 1)
			require.Equal(t, auth.OutcomeInvalidArgument, f.events[0].Outcome)
			require.Equal(t, fixtureIdentity.User.ID, f.events[0].ActorID)
			require.Equal(t, sessionID, f.events[0].SessionID)
			require.Empty(t, f.events[0].TargetID, "an unverified target never enters an event")
		}
	}
}

func TestAdministrationMemberDenialIsRecordedOnlyByTheService(t *testing.T) {
	for _, route := range administrationRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := adminFixture(t)
			f.role = auth.Member
			denied := &auth.Error{Code: auth.Forbidden}
			f.listErr, f.createErr, f.disableErr, f.resetErr, f.roleErr = denied, denied, denied, denied, denied
			response := requestAuth(handler, route.method, route.path, route.body, route.headers())
			require.Equal(t, 403, response.Code)
			require.Len(t, f.adminCalls, 1)
			require.Empty(t, f.events)
		})
	}
}

func TestAdministrationRejectionAuditFailureReturnsUnavailability(t *testing.T) {
	for _, route := range administrationRoutes() {
		t.Run(route.name, func(t *testing.T) {
			f, handler := adminFixture(t)
			f.recordErr = errors.New("SENTINEL_PRIVATE_DRIVER")
			response := requestAuth(handler, route.method, route.path, route.body, http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, 503, response.Code)
			require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
			require.NotContains(t, response.Body.String(), "SENTINEL")
			require.Empty(t, f.adminCalls)
		})
	}
}

func TestAdministrationHonorsTheOperationDeadline(t *testing.T) {
	for _, route := range administrationRoutes() {
		f, handler := adminFixture(t)
		f.adminBlock = func(ctx context.Context) { <-ctx.Done() }
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body)).WithContext(ctx)
		request.RemoteAddr = "127.0.0.1:43210"
		request.Header = route.headers()
		response := httptest.NewRecorder()
		start := time.Now()
		handler.ServeHTTP(response, request)
		cancel()
		require.Equal(t, 503, response.Code, route.name)
		require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
		require.Less(t, time.Since(start), time.Second)
	}
}

func TestListingResponseStaysWithinTheDocumentedBodyLimit(t *testing.T) {
	f, handler := adminFixture(t)
	longest := "u" + strings.Repeat("z", 63)
	require.True(t, auth.ValidUsername(longest))
	users := make([]auth.UserRecord, 0, auth.MaxUserListing)
	for index := 0; index < auth.MaxUserListing; index++ {
		users = append(users, auth.UserRecord{ID: adminTargetID, Username: longest, Role: auth.Admin,
			Disabled: true, CreatedAt: time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.UTC)})
	}
	f.list = auth.UserList{Users: users, Truncated: true}
	response := requestAuth(handler, "GET", auth.UsersPath, "", bearerHeaders())
	require.Equal(t, 200, response.Code)
	require.Less(t, response.Body.Len(), auth.MaxListingBody)
	var decoded auth.UserList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &decoded))
	require.Len(t, decoded.Users, auth.MaxUserListing)
	require.True(t, decoded.Truncated)
}

func TestRealHTTPAdministrationRoutesRecordAndFailClosed(t *testing.T) {
	pool, path, password := serverDatabase(t)
	checker := store.NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, checker.Attempt(t.Context()).State)
	service, err := store.NewLocalAuth(pool, checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	handler, err := HandlerWithAuth(time.Second, checker, service, service, service, service, "http://127.0.0.1", fixtureViews(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	encoded, err := json.Marshal(auth.LoginRequest{Username: "personal-admin", Password: password})
	require.NoError(t, err)
	response := requestAuth(handler, "POST", auth.LoginPath, string(encoded), http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, 200, response.Code)
	var issued auth.LoginResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &issued))
	headers := http.Header{"Authorization": {"Bearer " + string(issued.Token)}}
	jsonHeaders := func(body string) http.Header {
		result := headers.Clone()
		if body != "" {
			result.Set("Content-Type", "application/json")
		}
		return result
	}
	response = requestAuth(handler, "POST", auth.UsersPath, `{"username":"member-user","password":"valid member password"}`, jsonHeaders("x"))
	require.Equal(t, 201, response.Code)
	var created auth.UserRecord
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &created))
	require.Equal(t, auth.Member, created.Role)
	require.False(t, created.Disabled)

	response = requestAuth(handler, "GET", auth.UsersPath, "", headers)
	require.Equal(t, 200, response.Code)
	var list auth.UserList
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &list))
	require.Len(t, list.Users, 2)
	require.False(t, list.Truncated)

	for _, tc := range []struct {
		pattern, body string
		status        int
		revoked       bool
	}{
		{auth.UserBlockPath, "", 200, true},
		{auth.UserUnblockPath, "", 200, false},
		{auth.UserPasswordPath, `{"password":"another member password"}`, 200, true},
		{auth.UserRolePath, `{"role":"admin"}`, 200, false},
	} {
		response = requestAuth(handler, "POST", strings.Replace(tc.pattern, "{userID}", created.ID, 1), tc.body, jsonHeaders(tc.body))
		require.Equal(t, tc.status, response.Code, tc.pattern)
		var mutation auth.UserMutation
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &mutation))
		require.Equal(t, created.ID, mutation.User.ID)
		require.Equal(t, tc.revoked, mutation.SessionsRevoked)
	}
	response = requestAuth(handler, "POST", strings.Replace(auth.UserBlockPath, "{userID}", issued.User.ID, 1), "", headers)
	require.Equal(t, 409, response.Code)
	require.Contains(t, response.Body.String(), auth.SelfTarget)
	response = requestAuth(handler, "POST", strings.Replace(auth.UserBlockPath, "{userID}", adminTargetID, 1), "", headers)
	require.Equal(t, 404, response.Code)

	// One pre-service rejection records exactly one event with the new action,
	// which the migrated check constraint must accept.
	var before, after int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events`).Scan(&before))
	response = requestAuth(handler, "POST", auth.UsersPath, `{"SENTINEL_PRIVATE_BODY":"x"}`, jsonHeaders("x"))
	require.Equal(t, 400, response.Code)
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth_events WHERE action='user.create' AND outcome='invalid_argument'`).Scan(&after))
	require.Equal(t, 1, after)
	var total int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events`).Scan(&total))
	require.Equal(t, before+1, total)
	var row string
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT row_to_json(auth_events)::text FROM auth_events WHERE outcome='invalid_argument'`).Scan(&row))
	require.NotContains(t, row, "SENTINEL")

	// A held row lock on the target blocks the mutation's ordered lock; the
	// operation deadline must still answer with safe unavailability.
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), `SELECT id FROM users WHERE id=$1 FOR UPDATE`, created.ID)
	require.NoError(t, err)
	start := time.Now()
	response = requestAuth(handler, "POST", strings.Replace(auth.UserUnblockPath, "{userID}", created.ID, 1), "", headers)
	require.Equal(t, 503, response.Code)
	require.Contains(t, response.Body.String(), auth.ServiceUnavailable)
	require.Greater(t, time.Since(start), 4*time.Second)
	require.Less(t, time.Since(start), 6*time.Second)
	require.NoError(t, tx.Rollback(t.Context()))
	response = requestAuth(handler, "GET", auth.UsersPath, "", headers)
	require.Equal(t, 200, response.Code)
}
