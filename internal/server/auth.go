package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/config"
	"github.com/heurema/clavis/internal/web"
)

const browserCookie = "__Host-clavis-session"
const developmentCookie = "clavis-dev-session"

// AuthViews is only a presentation seam. No fixture service or account is
// installed by the production constructor.
type AuthViews struct {
	Login            func(web.LoginModel) templ.Component
	Admin            func(web.AdminModel) templ.Component
	Error            func(web.AuthErrorModel) templ.Component
	Authorize        func(web.AuthorizeModel) templ.Component
	AuthorizeInvalid func() templ.Component
}

type authHTTP struct {
	service     auth.Service
	admin       auth.Administration
	connections auth.Connections
	grants      auth.Grants
	groups      auth.Groups
	members     MemberConnections
	executor    auth.QueryExecutor
	origin      string
	secure      bool
	views       AuthViews
}

func (a *authHTTP) mount(router chi.Router) {
	// The sign-in document reads only its own query: a return target is kept
	// when it parses as an authorization link, so no database is involved.
	router.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		next, _ := returnLink(r.URL.RawQuery)
		a.render(w, r, 200, a.views.Login(web.LoginModel{Next: next}))
	})
	router.With(a.operation).Post("/login", a.loginBrowser)
	router.With(a.operation).Get(auth.AuthorizePath, a.authorizePage)
	router.With(a.operation).Post(auth.AuthorizePath, a.approveBrowser)
	router.With(a.operation).Post(auth.TokenPath, a.tokenJSON)
	router.With(a.operation).Post("/logout", a.logoutBrowser)
	// Old bookmarks keep working. The redirect is public: it reads neither the
	// database nor the request's cookies, so it answers during an outage.
	router.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	})
	// One loader serves the four pages: the page value is the only difference
	// between them, because the sidebar's counts come from all four lists.
	router.With(a.operation).Get("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		a.adminPage(w, r, web.PageUsers)
	})
	router.With(a.operation).Get("/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		a.adminPage(w, r, web.PageGroups)
	})
	router.With(a.operation).Get("/admin/connections", func(w http.ResponseWriter, r *http.Request) {
		a.adminPage(w, r, web.PageConnections)
	})
	router.With(a.operation).Get("/admin/grants", func(w http.ResponseWriter, r *http.Request) {
		a.adminPage(w, r, web.PageGrants)
	})
	router.With(a.operation).Get(auth.WhoAmIPath, a.identityJSON)
	router.With(a.operation).Post(auth.LogoutPath, a.logoutJSON)
	router.With(a.operation).Post(auth.RevokePath, a.revokeJSON)
	router.With(a.operation).Get(auth.UsersPath, a.listUsersJSON)
	router.With(a.operation).Post(auth.UsersPath, a.createUserJSON)
	router.With(a.operation).Post(auth.UserBlockPath, a.blockUserJSON)
	router.With(a.operation).Post(auth.UserUnblockPath, a.unblockUserJSON)
	router.With(a.operation).Post(auth.UserPasswordPath, a.resetPasswordJSON)
	router.With(a.operation).Post(auth.UserRolePath, a.setRoleJSON)
	router.With(a.operation).Get(auth.ConnectionsPath, a.listConnectionsJSON)
	router.With(a.operation).Post(auth.ConnectionsPath, a.createConnectionJSON)
	router.With(a.operation).Get(auth.ConnectionPath, a.getConnectionJSON)
	router.With(a.operation).Post(auth.ConnectionUpdatePath, a.updateConnectionJSON)
	router.With(a.operation).Post(auth.ConnectionCredentialsPath, a.setConnectionCredentialsJSON)
	router.With(a.operation).Post(auth.ConnectionEnablePath, a.enableConnectionJSON)
	router.With(a.operation).Post(auth.ConnectionDisablePath, a.disableConnectionJSON)
	router.With(a.operation).Post(auth.ConnectionDeletePath, a.deleteConnectionJSON)
	router.With(a.operation).Post(auth.ConnectionCheckPath, a.checkConnectionJSON)
	router.With(a.operation).Get(auth.GrantsPath, a.listGrantsJSON)
	router.With(a.operation).Post(auth.GrantsPath, a.createGrantJSON)
	router.With(a.operation).Post(auth.GrantRevokePath, a.revokeGrantJSON)
	router.With(a.operation).Get(auth.GrantsEffectivePath, a.listEffectiveAccessJSON)
	router.With(a.operation).Get(auth.GroupsPath, a.listGroupsJSON)
	router.With(a.operation).Post(auth.GroupsPath, a.createGroupJSON)
	router.With(a.operation).Get(auth.GroupPath, a.getGroupJSON)
	router.With(a.operation).Post(auth.GroupUpdatePath, a.updateGroupJSON)
	router.With(a.operation).Post(auth.GroupDeletePath, a.deleteGroupJSON)
	router.With(a.operation).Get(auth.GroupMembersPath, a.listMembersJSON)
	router.With(a.operation).Post(auth.GroupMemberAddPath, a.addMemberJSON)
	router.With(a.operation).Post(auth.GroupMemberRemovePath, a.removeMemberJSON)
	// Execution is not administration: a member with a grant uses it, so it
	// sits outside /api/admin and alongside the member connection reads.
	router.With(a.queryOperation).Post(auth.QueryPath, a.executeQueryJSON)
}

type responseBuffer struct {
	header http.Header
	status int
	bytes.Buffer
}

// operationState carries the status an early browser rejection already
// rendered, so the failure path can tell a 400 apart from other rejections.
type operationState struct {
	rejectionStatus int
}
type operationStateKey struct{}

func (w *responseBuffer) Header() http.Header { return w.header }
func (w *responseBuffer) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *responseBuffer) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.Buffer.Write(b)
}

// Socket read deadlines unblock body consumption, while the context also bounds
// pool and row locks. Response publication waits for preparation.
func (a *authHTTP) operation(next http.Handler) http.Handler {
	return a.bounded(auth.OperationTimeout, false, next)
}

// queryOperation is operation with the execution budget. A query waits on an
// external source whose own statement timeout may be twenty times the shared
// bound, so cutting it at five seconds would report unavailability for a
// perfectly ordinary statement instead of the source's own outcome. The
// per-request write deadline is extended past the server's global one for the
// same reason: the response cannot be published after it.
func (a *authHTTP) queryOperation(next http.Handler) http.Handler {
	return a.bounded(auth.QueryRequestBudget, true, next)
}

func (a *authHTTP) bounded(budget time.Duration, extendWrite bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), budget)
		defer cancel()
		deadline, _ := ctx.Deadline()
		controller := http.NewResponseController(w)
		// The body is read under the shared bound whatever the budget: a long
		// budget is for waiting on a source, never for a trickling request.
		readDeadline := time.Now().Add(min(budget, auth.OperationTimeout))
		_ = controller.SetReadDeadline(readDeadline)
		if extendWrite {
			_ = controller.SetWriteDeadline(time.Now().Add(budget + 5*time.Second))
		}
		defer func() {
			// Never re-enable draining a stalled body after its deadline.
			if time.Now().Before(readDeadline) && ctx.Err() == nil {
				_ = controller.SetReadDeadline(time.Time{})
			}
		}()
		r = r.WithContext(context.WithValue(ctx, operationStateKey{}, &operationState{}))
		buffer := &responseBuffer{header: make(http.Header)}
		next.ServeHTTP(buffer, r)
		timedOut := ctx.Err() != nil || !time.Now().Before(deadline)
		if timedOut {
			keepCookie := !a.originAllowed(r, true) || r.Context().Value(operationStateKey{}).(*operationState).rejectionStatus == 400
			buffer = &responseBuffer{header: make(http.Header)}
			r = r.WithContext(context.WithoutCancel(ctx))
			failure := &auth.Error{Code: auth.ServiceUnavailable}
			switch r.URL.Path {
			case "/login":
				a.loginFailure(buffer, r, "", "", failure)
			case auth.AuthorizePath:
				buffer.Header().Set("Referrer-Policy", "no-referrer")
				a.render(buffer, r, 503, a.views.Error(web.AuthErrorModel{ErrorCode: auth.ServiceUnavailable}))
			case "/logout":
				if keepCookie {
					a.render(buffer, r, 503, a.views.Error(web.AuthErrorModel{ErrorCode: auth.ServiceUnavailable}))
				} else {
					a.logoutResult(buffer, r, auth.LogoutOutcome(true, failure))
				}
			default:
				// Every administration page renders the same safe document as
				// before, so the fallback follows the prefix rather than a list
				// of routes that would drift from the router.
				if strings.HasPrefix(r.URL.Path, "/admin/") {
					a.adminResult(buffer, r, auth.Session{}, adminLists{}, pageFor(r.URL.Path), failure)
				} else {
					jsonFailure(buffer, failure)
				}
			}
		}
		// Early rejections may deliberately leave an untrusted body unread.
		// Do not let HTTP/1 keep-alive draining extend the operation deadline.
		if timedOut || r.Method == http.MethodPost {
			buffer.Header().Set("Connection", "close")
		}
		for key, values := range buffer.header {
			w.Header()[key] = values
		}
		status := buffer.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		_, _ = w.Write(buffer.Bytes())
	})
}

// Service methods own readiness. The fixture-only composition has no service
// and must reject protected requests without invoking one.
func (a *authHTTP) requireService() error {
	if a.service == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

func (a *authHTTP) originAllowed(r *http.Request, required bool) bool {
	metadata := r.Header.Values("Sec-Fetch-Site")
	if len(metadata) > 1 || (len(metadata) == 1 && metadata[0] != "same-origin" && metadata[0] != "none") {
		return false
	}
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return !required
	}
	// Compare serialized origins, not permissive URL parsing; reject whitespace,
	// lists, null, paths and default-port aliases not serialized by browsers.
	return len(values) == 1 && values[0] == a.origin
}

func (a *authHTTP) cookieName() string {
	if a.secure {
		return browserCookie
	}
	return developmentCookie
}

func (a *authHTTP) cookie(w http.ResponseWriter, token auth.Secret, expires time.Time, clear bool) {
	cookie := &http.Cookie{Name: a.cookieName(), Value: string(token), Path: "/", Secure: a.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires.UTC()}
	if clear {
		cookie.Value = ""
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0).UTC()
	}
	http.SetCookie(w, cookie)
}

func (a *authHTTP) token(r *http.Request) (auth.Secret, error) {
	if len(r.Header.Values("Authorization")) != 0 {
		return "", &auth.Error{Code: auth.InvalidArgument}
	}
	var value auth.Secret
	count := sessionCookieCount(r)
	for _, cookie := range r.Cookies() {
		if cookie.Name == browserCookie || cookie.Name == developmentCookie {
			if cookie.Name == a.cookieName() {
				value = auth.Secret(cookie.Value)
			}
		}
	}
	if count > 1 {
		return "", &auth.Error{Code: auth.InvalidArgument}
	}
	if !auth.ValidToken(value) {
		return "", &auth.Error{Code: auth.Unauthenticated}
	}
	return value, nil
}

// Count before net/http's cookie parser drops malformed values. A malformed
// duplicate must not silently disappear and turn ambiguous credentials valid.
func sessionCookieCount(r *http.Request) int {
	count := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			name = strings.TrimSpace(name)
			if name == browserCookie || name == developmentCookie {
				count++
			}
		}
	}
	return count
}

func bearer(r *http.Request) (auth.Secret, error) {
	values := r.Header.Values("Authorization")
	ambient := sessionCookieCount(r) > 0
	if len(values) == 0 {
		return "", &auth.Error{Code: auth.Unauthenticated}
	}
	if len(values) != 1 || ambient {
		return "", &auth.Error{Code: auth.InvalidArgument}
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !auth.ValidToken(auth.Secret(parts[1])) {
		return "", &auth.Error{Code: auth.Unauthenticated}
	}
	return auth.Secret(parts[1]), nil
}

func jsonFailure(w http.ResponseWriter, err error) {
	status, body := auth.FailureFor(err)
	setRetry(w, err)
	writeJSON(w, status, body)
}

func setRetry(w http.ResponseWriter, err error) int {
	var failure *auth.Error
	if errors.As(err, &failure) && failure.Code == auth.RateLimited {
		seconds := max(1, int(math.Ceil(failure.RetryAfter.Seconds())))
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		return seconds
	}
	return 0
}

func mediaType(r *http.Request, want string) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	got, params, err := mime.ParseMediaType(values[0])
	if err != nil || got != want {
		return false
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func boundedBody(r *http.Request, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(b) > limit || !utf8.Valid(b) {
		return nil, &auth.Error{Code: auth.InvalidArgument}
	}
	return b, nil
}

func credentialBody(r *http.Request) ([]byte, error) {
	return boundedBody(r, auth.MaxCredentialBody)
}

// jsonValue decodes one allowlisted member's value from the token stream. Each
// member type has exactly one decoder, so a value of the wrong shape is a
// rejection rather than a coercion.
type jsonValue func(*json.Decoder) error

func invalidArgument() error { return &auth.Error{Code: auth.InvalidArgument} }

func jsonString(assign func(string)) jsonValue {
	return func(decoder *json.Decoder) error {
		token, err := decoder.Token()
		text, ok := token.(string)
		if err != nil || !ok {
			return invalidArgument()
		}
		assign(text)
		return nil
	}
}

// jsonInt accepts only an integer literal: the decoder reads numbers as
// json.Number, so a fraction, an exponent or a quoted digit string is refused
// instead of being rounded into a resource bound.
func jsonInt(assign func(int)) jsonValue {
	return func(decoder *json.Decoder) error {
		token, err := decoder.Token()
		number, ok := token.(json.Number)
		if err != nil || !ok {
			return invalidArgument()
		}
		value, convErr := strconv.Atoi(number.String())
		if convErr != nil {
			return invalidArgument()
		}
		assign(value)
		return nil
	}
}

// jsonStringMap reads one nested object of string values, the shape both
// target settings and labels take. Duplicate keys are rejected here too, so a
// nested object cannot smuggle an ambiguous member past the outer check.
func jsonStringMap(assign func(map[string]string)) jsonValue {
	return func(decoder *json.Decoder) error {
		token, err := decoder.Token()
		if err != nil || token != json.Delim('{') {
			return invalidArgument()
		}
		values := map[string]string{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return invalidArgument()
			}
			if _, duplicate := values[name]; duplicate {
				return invalidArgument()
			}
			value, err := decoder.Token()
			text, ok := value.(string)
			if err != nil || !ok {
				return invalidArgument()
			}
			values[name] = text
		}
		if _, err := decoder.Token(); err != nil {
			return invalidArgument()
		}
		assign(values)
		return nil
	}
}

// decodeFields reads one bounded JSON object whose members are exactly the
// allowlisted fields in into. Members are decoded explicitly so duplicate
// fields, case aliases, null, wrongly typed values and trailing documents
// cannot be accepted by encoding/json's permissive struct decoder. Values are
// assigned but never validated here and never reflected back. A member absent
// from the body leaves its field untouched, which is how optional update
// fields stay distinguishable from supplied empty ones.
func decodeFields(r *http.Request, limit int, into map[string]jsonValue) error {
	if !mediaType(r, "application/json") {
		return invalidArgument()
	}
	b, err := boundedBody(r, limit)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return invalidArgument()
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || into[name] == nil || seen[name] {
			return invalidArgument()
		}
		seen[name] = true
		if err := into[name](decoder); err != nil {
			return invalidArgument()
		}
	}
	if _, err := decoder.Token(); err != nil {
		return invalidArgument()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalidArgument()
	}
	return nil
}

// decodeJSON is decodeFields for the credential bodies whose members are all
// plain strings.
func decodeJSON(r *http.Request, limit int, into map[string]func(string)) error {
	fields := make(map[string]jsonValue, len(into))
	for name, assign := range into {
		fields[name] = jsonString(assign)
	}
	return decodeFields(r, limit, fields)
}

func peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	value, _ := netip.ParseAddr(host)
	return value.Unmap()
}

func (a *authHTTP) authenticate(r *http.Request, token auth.Secret, kind auth.Kind) (auth.Session, error) {
	return a.service.Authenticate(r.Context(), token, kind)
}

func (a *authHTTP) cliSession(r *http.Request) (auth.Session, error) {
	if !a.originAllowed(r, false) {
		return auth.Session{}, &auth.Error{Code: auth.Forbidden}
	}
	token, err := bearer(r)
	if err != nil {
		return auth.Session{}, err
	}
	if err = a.requireService(); err != nil {
		return auth.Session{}, err
	}
	return a.authenticate(r, token, auth.CLI)
}

// identityJSON answers the caller's own identity: the groups they belong to,
// whatever their role, and for a member the names of the connections they may
// use, so an agent's first call already says what is available. Administrators
// need no grant, so their connection list stays empty rather than enumerating
// every connection; their groups are still reported, because membership is a
// fact about the account rather than the source of their access. Login
// responses are untouched: only this route fills the names.
func (a *authHTTP) identityJSON(w http.ResponseWriter, r *http.Request) {
	session, err := a.cliSession(r)
	if err == nil {
		err = a.requireMembers()
	}
	if err == nil {
		session.Groups, session.GroupsTruncated, err =
			a.members.ListGroupNames(r.Context(), session, auth.MaxGroupListing)
	}
	if err == nil && session.User.Role != auth.Admin {
		session.Connections, session.ConnectionsTruncated, err =
			a.members.ListGrantedConnectionNames(r.Context(), session, auth.MaxConnectionListing)
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, 200, boundedIdentity(session.Identity))
}

// identityHeadroom is what the identity carries besides the names: the user
// record, the expiry and the envelope, all far below this reservation.
// groupReservation is the share of what is left that the group names are
// measured against first, so a member with many long connection names still
// learns which groups they belong to.
const (
	identityHeadroom = 4096
	groupReservation = 8192
)

// boundedIdentity keeps whoami inside the general response limit, which is the
// limit the CLI reads it under: 1,000 names of 64 bytes would exceed it on
// their own. The groups are measured first against their reservation and the
// connections against everything the groups did not use, so an unused
// reservation goes back to the connections and neither list can starve the
// other. The two truncation flags stay independent.
func boundedIdentity(identity auth.Identity) auth.Identity {
	budget := auth.MaxResponseBody - identityHeadroom
	var used int
	identity.Groups, identity.GroupsTruncated, used =
		boundedNames(identity.Groups, identity.GroupsTruncated, min(groupReservation, budget))
	identity.Connections, identity.ConnectionsTruncated, _ =
		boundedNames(identity.Connections, identity.ConnectionsTruncated, budget-used)
	return identity
}

// boundedNames drops the names past the budget in order, reports that as
// truncation and returns the bytes the kept names occupy inside the encoded
// array, so the caller can hand the remainder to the next list.
func boundedNames(names []string, truncated bool, budget int) ([]string, bool, int) {
	size := 0
	for index, name := range names {
		next := size + len(name) + 2 // quotes
		if index > 0 {
			next++ // the separating comma
		}
		if next > budget {
			return names[:index], true, size
		}
		size = next
	}
	return names, truncated, size
}

func emptyBody(r *http.Request) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(data) != 0 {
		return &auth.Error{Code: auth.InvalidArgument}
	}
	return nil
}

func (a *authHTTP) logoutJSON(w http.ResponseWriter, r *http.Request) {
	if err := emptyBody(r); err != nil {
		jsonFailure(w, err)
		return
	}
	session, err := a.cliSession(r)
	if err == nil {
		err = a.service.Logout(r.Context(), session)
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, 200, auth.Revocation{Revoked: true})
}

func (a *authHTTP) revokeJSON(w http.ResponseWriter, r *http.Request) {
	if err := emptyBody(r); err != nil {
		jsonFailure(w, err)
		return
	}
	session, err := a.cliSession(r)
	// The target is a reference: a UUID or a username. The service resolves it
	// inside its transaction; the adapter only refuses a shape that can be
	// neither, including the empty segment of a doubled slash.
	if err == nil && !auth.ValidUserRef(chi.URLParam(r, "userID")) {
		err = &auth.Error{Code: auth.InvalidArgument}
	}
	if err == nil {
		err = a.service.RevokeUserSessions(r.Context(), session, chi.URLParam(r, "userID"))
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, 200, auth.Revocation{Revoked: true})
}

func (a *authHTTP) render(w http.ResponseWriter, r *http.Request, status int, component templ.Component) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	if state, ok := r.Context().Value(operationStateKey{}).(*operationState); ok && status >= 400 {
		state.rejectionStatus = status
	}
	_ = web.Render(w, r, status, component)
}

func (a *authHTTP) loginFailure(w http.ResponseWriter, r *http.Request, username, next string, err error) {
	outcome := auth.LoginOutcome(err)
	if !auth.ValidUsername(username) {
		username = ""
	}
	retry := setRetry(w, err)
	a.render(w, r, outcome.Status, a.views.Login(web.LoginModel{Username: username, ErrorCode: outcome.ErrorCode, RetryAfterSeconds: retry, Next: next}))
}

// returnLink reads a return target from a query or form: exactly one next
// value that parses as an authorization link, returned rebuilt from the parsed
// values. Anything else is no return target.
func returnLink(query string) (string, bool) {
	values, err := url.ParseQuery(query)
	if err != nil || len(values["next"]) != 1 {
		return "", false
	}
	link, ok := auth.ParseAuthorizeLink(values.Get("next"))
	if !ok {
		return "", false
	}
	return link.Link(), true
}

// loginLocation is where a request without a valid browser session goes to
// sign in and come back to the same authorization link.
func loginLocation(link auth.CLIAuthorization) string {
	return "/login?" + url.Values{"next": {link.Link()}}.Encode()
}

// authorizePage validates the link, then renders the approval document for a
// valid browser session or the sign-in document returning to the link. It
// writes nothing but the renewal Authenticate may perform.
func (a *authHTTP) authorizePage(w http.ResponseWriter, r *http.Request) {
	// The link carries the state; no document on this route passes it on.
	w.Header().Set("Referrer-Policy", "no-referrer")
	values, err := url.ParseQuery(r.URL.RawQuery)
	link, ok := auth.ParseCLIAuthorization(values)
	if err != nil || !ok {
		a.render(w, r, 400, a.views.AuthorizeInvalid())
		return
	}
	token, err := a.token(r)
	var session auth.Session
	if err == nil {
		err = a.requireService()
	}
	if err == nil {
		session, err = a.authenticate(r, token, auth.Browser)
	}
	status, failure := auth.FailureFor(err)
	switch {
	case err == nil:
		a.render(w, r, 200, a.views.Authorize(web.AuthorizeModel{Username: session.User.Username, Link: link}))
	case failure.Error.Code == auth.Unauthenticated:
		a.render(w, r, 200, a.views.Login(web.LoginModel{Next: link.Link()}))
	default:
		a.render(w, r, status, a.views.Error(web.AuthErrorModel{ErrorCode: failure.Error.Code}))
	}
}

// approveBrowser stores an approval and sends the browser to the CLI's
// loopback callback. It is a browser mutation: Origin, Fetch Metadata and the
// form content type are checked before anything else, and the redirect is
// built only from the parsed port, the fresh code and the validated state.
func (a *authHTTP) approveBrowser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	fail := func(err error) {
		status, failure := auth.FailureFor(err)
		a.render(w, r, status, a.views.Error(web.AuthErrorModel{ErrorCode: failure.Error.Code}))
	}
	if !a.originAllowed(r, true) {
		fail(&auth.Error{Code: auth.Forbidden})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || !mediaType(r, "application/x-www-form-urlencoded") {
		fail(&auth.Error{Code: auth.InvalidArgument})
		return
	}
	token, tokenErr := a.token(r)
	var failure *auth.Error
	if errors.As(tokenErr, &failure) && failure.Code == auth.InvalidArgument {
		fail(tokenErr)
		return
	}
	body, err := credentialBody(r)
	values, parseErr := url.ParseQuery(string(body))
	link, ok := auth.ParseCLIAuthorization(values)
	if err != nil || parseErr != nil || !ok {
		a.render(w, r, 400, a.views.AuthorizeInvalid())
		return
	}
	err = tokenErr
	var session auth.Session
	if err == nil {
		err = a.requireService()
	}
	if err == nil {
		session, err = a.authenticate(r, token, auth.Browser)
	}
	var code auth.Secret
	if err == nil {
		code, err = a.service.ApproveCLI(r.Context(), session, link)
	}
	location := ""
	if err == nil {
		location = link.CallbackURL(code)
	} else if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
		location = loginLocation(link)
	} else {
		fail(err)
		return
	}
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

// tokenJSON redeems an approved code under the JSON credential transport
// rules: JSON only, bounded and strictly decoded, and never with a cookie or an
// Authorization header. Those are refused before the service is called.
func (a *authHTTP) tokenJSON(w http.ResponseWriter, r *http.Request) {
	if !a.originAllowed(r, false) {
		jsonFailure(w, &auth.Error{Code: auth.Forbidden})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 || !mediaType(r, "application/json") {
		jsonFailure(w, &auth.Error{Code: auth.InvalidArgument})
		return
	}
	var input auth.TokenRequest
	err := decodeJSON(r, auth.MaxCredentialBody, map[string]func(string){
		"code":     func(value string) { input.Code = auth.Secret(value) },
		"verifier": func(value string) { input.Verifier = auth.Secret(value) },
	})
	if err == nil && (!auth.ValidToken(input.Code) || !auth.ValidToken(input.Verifier)) {
		err = &auth.Error{Code: auth.InvalidArgument}
	}
	if err == nil {
		err = a.requireService()
	}
	var response auth.LoginResponse
	if err == nil {
		response, err = a.service.ExchangeCLICode(r.Context(), input)
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, 200, response)
}

func (a *authHTTP) loginBrowser(w http.ResponseWriter, r *http.Request) {
	if !a.originAllowed(r, true) {
		a.loginFailure(w, r, "", "", &auth.Error{Code: auth.Forbidden})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || !mediaType(r, "application/x-www-form-urlencoded") {
		a.loginFailure(w, r, "", "", &auth.Error{Code: auth.InvalidArgument})
		return
	}
	// A valid existing cookie is replaced only on successful login. Duplicate
	// session credentials are rejected before touching the service.
	if _, err := a.token(r); err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.InvalidArgument {
			a.loginFailure(w, r, "", "", err)
			return
		}
	}
	body, err := credentialBody(r)
	values, parseErr := url.ParseQuery(string(body))
	// The form carries a username, a password and at most one return target.
	fields := 2 + min(len(values["next"]), 1)
	next, _ := returnLink(string(body))
	if err != nil || parseErr != nil || len(values) != fields || len(values["username"]) != 1 || len(values["password"]) != 1 ||
		!auth.ValidUsername(values.Get("username")) || !auth.ValidPassword(auth.Secret(values.Get("password"))) {
		a.loginFailure(w, r, "", next, &auth.Error{Code: auth.InvalidArgument})
		return
	}
	if err := a.requireService(); err != nil {
		a.loginFailure(w, r, values.Get("username"), next, err)
		return
	}
	response, err := a.service.Login(r.Context(), auth.LoginInput{Username: values.Get("username"), Password: auth.Secret(values.Get("password")), Peer: peer(r)})
	if err != nil {
		a.loginFailure(w, r, values.Get("username"), next, err)
		return
	}
	// The contract owns where a successful browser sign-in lands, so the handler
	// reads it rather than repeating the location. A valid return target
	// replaces it with the link rebuilt from its parsed values.
	outcome := auth.LoginOutcome(nil)
	if next != "" {
		outcome.Location = next
	}
	a.cookie(w, response.Token, response.ExpiresAt, false)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", outcome.Location)
	w.WriteHeader(outcome.Status)
}

func (a *authHTTP) logoutResult(w http.ResponseWriter, r *http.Request, outcome auth.BrowserOutcome) {
	if outcome.ClearCookie {
		a.cookie(w, "", time.Time{}, true)
	}
	if outcome.Location != "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", outcome.Location)
		w.WriteHeader(outcome.Status)
		return
	}
	a.render(w, r, outcome.Status, a.views.Error(web.AuthErrorModel{ErrorCode: outcome.ErrorCode, RemoteRevocationUnconfirmed: outcome.RemoteRevocationUnconfirmed}))
}

func (a *authHTTP) logoutBrowser(w http.ResponseWriter, r *http.Request) {
	if !a.originAllowed(r, true) {
		a.logoutResult(w, r, auth.LogoutOutcome(false, nil))
		return
	}
	token, err := a.token(r)
	if err != nil {
		// Ambiguity is not evidence of an absent session; do not mutate either.
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.InvalidArgument {
			a.render(w, r, 400, a.views.Error(web.AuthErrorModel{ErrorCode: auth.InvalidArgument}))
			return
		}
		a.logoutResult(w, r, auth.LogoutOutcome(true, err))
		return
	}
	err = a.requireService()
	if err == nil {
		var session auth.Session
		session, err = a.authenticate(r, token, auth.Browser)
		if err == nil {
			err = a.service.Logout(r.Context(), session)
		}
	}
	a.logoutResult(w, r, auth.LogoutOutcome(true, err))
}

// pageFor maps an administration path to the page it renders. Only the four
// routes above are mounted, so an unknown suffix never reaches it; the default
// exists so the timeout fallback always has a page to render.
func pageFor(path string) web.AdminPage {
	switch path {
	case "/admin/groups":
		return web.PageGroups
	case "/admin/connections":
		return web.PageConnections
	case "/admin/grants":
		return web.PageGrants
	default:
		return web.PageUsers
	}
}

// adminLists is every bounded listing the shell shows at once: the table of
// the page that was asked for and the counts beside it. They travel together
// because the page renders none of them unless all of them are current.
type adminLists struct {
	users       auth.UserList
	groups      auth.GroupList
	connections auth.ConnectionList
	grants      auth.GrantList
}

func (a *authHTTP) adminResult(w http.ResponseWriter, r *http.Request, session auth.Session, lists adminLists, page web.AdminPage, err error) {
	outcome := auth.AdminOutcome(err)
	if outcome.Location != "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", outcome.Location)
		w.WriteHeader(outcome.Status)
		return
	}
	if err != nil {
		a.render(w, r, outcome.Status, a.views.Error(web.AuthErrorModel{ErrorCode: outcome.ErrorCode}))
		return
	}
	a.render(w, r, 200, a.views.Admin(web.AdminModel{
		Page: page,
		User: session.User, Users: lists.users.Users, Truncated: lists.users.Truncated,
		Groups: lists.groups.Groups, GroupsTruncated: lists.groups.Truncated,
		Connections: lists.connections.Connections, ConnectionsTruncated: lists.connections.Truncated,
		Grants: lists.grants.Grants, GrantsTruncated: lists.grants.Truncated,
	}))
}

// adminPage loads every administration page: the shell shows the four bounded
// counts, and a count is current data like the table itself, so all four lists
// load and the first failure fails the page closed.
func (a *authHTTP) adminPage(w http.ResponseWriter, r *http.Request, page web.AdminPage) {
	token, err := a.token(r)
	var session auth.Session
	if err == nil {
		err = a.requireService()
	}
	if err == nil {
		session, err = a.authenticate(r, token, auth.Browser)
	}
	if err == nil && session.User.Role != auth.Admin {
		err = &auth.Error{Code: auth.Forbidden}
	}
	// The page fails closed rather than rendering administration without the
	// current list.
	var lists adminLists
	if err == nil {
		if err = a.requireAdministration(); err == nil {
			lists.users, err = a.admin.ListUsers(r.Context(), session)
		}
	}
	// Groups load after users, because a group is about people too.
	if err == nil {
		if err = a.requireGroups(); err == nil {
			lists.groups, err = a.groups.ListGroups(r.Context(), session, auth.MaxGroupListing)
		}
	}
	if err == nil {
		if a.connections == nil {
			err = &auth.Error{Code: auth.ServiceUnavailable}
		} else {
			lists.connections, err = a.connections.ListConnections(r.Context(), session, nil, auth.MaxConnectionListing)
		}
	}
	// Grants load last and the page fails closed without them too.
	if err == nil {
		if err = a.requireGrants(); err == nil {
			lists.grants, err = a.grants.ListGrants(r.Context(), session, auth.GrantFilter{Limit: auth.MaxGrantListing})
		}
	}
	a.adminResult(w, r, session, lists, page, err)
}

func newAuthHTTP(origin string, service auth.Service, views AuthViews) (*authHTTP, error) {
	canonical, err := config.CanonicalOrigin(origin)
	if err != nil {
		return nil, err
	}
	if views.Login == nil {
		views.Login = web.Login
	}
	if views.Admin == nil {
		views.Admin = web.Admin
	}
	if views.Error == nil {
		views.Error = web.AuthError
	}
	if views.Authorize == nil {
		views.Authorize = web.Authorize
	}
	if views.AuthorizeInvalid == nil {
		views.AuthorizeInvalid = web.AuthorizeInvalid
	}
	return &authHTTP{service: service, origin: canonical, secure: strings.HasPrefix(canonical, "https:"), views: views}, nil
}
