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
	Login func(web.LoginModel) templ.Component
	Admin func(web.AdminModel) templ.Component
	Error func(web.AuthErrorModel) templ.Component
}

type authHTTP struct {
	service     auth.Service
	admin       auth.Administration
	connections auth.Connections
	grants      auth.Grants
	members     MemberConnections
	recorder    auth.EventRecorder
	origin      string
	secure      bool
	views       AuthViews
}

func (a *authHTTP) mount(router chi.Router) {
	router.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		a.render(w, r, 200, a.views.Login(web.LoginModel{}))
	})
	router.With(a.operation).Post("/login", a.loginBrowser)
	router.With(a.operation).Post("/logout", a.logoutBrowser)
	router.With(a.operation).Get("/admin", a.adminBrowser)
	router.With(a.operation).Post(auth.LoginPath, a.loginJSON)
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
}

type responseBuffer struct {
	header http.Header
	status int
	bytes.Buffer
}

type operationAudit struct {
	serviceOwns     bool
	rejectionStatus int
	actorID         string
	sessionID       string
}
type operationAuditKey struct{}

func serviceOwnsEvent(r *http.Request) {
	r.Context().Value(operationAuditKey{}).(*operationAudit).serviceOwns = true
}

// rejectionAction maps the matched route, never the raw request path, to the
// action an adapter rejection records. Routes absent from the table record
// nothing: reading existing credentials (whoami, the browser admin page) is not
// a rejectable mutation, and the listing route is the only recorded GET.
func rejectionAction(r *http.Request) (auth.EventAction, bool) {
	switch chi.RouteContext(r.Context()).RoutePattern() {
	case "/login", auth.LoginPath:
		return auth.EventLogin, true
	case "/logout", auth.LogoutPath:
		return auth.EventLogout, true
	case auth.RevokePath:
		return auth.EventRevoke, true
	case auth.UsersPath:
		if r.Method == http.MethodGet {
			return auth.EventUsersList, true
		}
		return auth.EventUserCreate, true
	case auth.UserBlockPath:
		return auth.EventUserBlock, true
	case auth.UserUnblockPath:
		return auth.EventUserUnblock, true
	case auth.UserPasswordPath:
		return auth.EventUserResetPassword, true
	case auth.UserRolePath:
		// A rejected role request is recorded as user.demote whether or not a
		// role was submitted: the request never reached the service, no role
		// changed, and the rejection must not depend on untrusted body fields.
		return auth.EventUserDemote, true
	case auth.ConnectionsPath:
		if r.Method == http.MethodGet {
			return auth.EventConnectionsList, true
		}
		return auth.EventConnectionCreate, true
	case auth.ConnectionPath:
		return auth.EventConnectionGet, true
	case auth.ConnectionUpdatePath:
		return auth.EventConnectionUpdate, true
	case auth.ConnectionCredentialsPath:
		return auth.EventConnectionSecrets, true
	case auth.ConnectionEnablePath:
		return auth.EventConnectionEnable, true
	case auth.ConnectionDisablePath:
		return auth.EventConnectionDisable, true
	case auth.ConnectionDeletePath:
		return auth.EventConnectionDelete, true
	case auth.ConnectionCheckPath:
		return auth.EventConnectionCheck, true
	case auth.GrantsPath:
		if r.Method == http.MethodGet {
			return auth.EventGrantsList, true
		}
		return auth.EventGrantCreate, true
	case auth.GrantRevokePath:
		return auth.EventGrantRevoke, true
	}
	return "", false
}

func (a *authHTTP) auditRejection(r *http.Request, status int) error {
	state := r.Context().Value(operationAuditKey{}).(*operationAudit)
	if state.serviceOwns {
		return nil
	}
	action, ok := rejectionAction(r)
	if !ok {
		return nil
	}
	if state.rejectionStatus != 0 {
		status = state.rejectionStatus
	}
	var outcome auth.EventOutcome
	switch status {
	case 400:
		outcome = auth.OutcomeInvalidArgument
	case 401:
		outcome = auth.OutcomeUnauthenticated
	case 403:
		outcome = auth.OutcomeForbidden
	case 429:
		outcome = auth.OutcomeRateLimited
	default:
		return nil
	}
	if a.recorder == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return a.recorder.RecordEvent(r.Context(), auth.Event{
		Action: action, Outcome: outcome, ActorID: state.actorID, SessionID: state.sessionID,
	})
}

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
// pool/row locks and audit writes. Response publication waits for preparation.
func (a *authHTTP) operation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), auth.OperationTimeout)
		defer cancel()
		deadline, _ := ctx.Deadline()
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(deadline)
		defer func() {
			// Never re-enable draining a stalled body after its deadline.
			if time.Now().Before(deadline) && ctx.Err() == nil {
				_ = controller.SetReadDeadline(time.Time{})
			}
		}()
		r = r.WithContext(context.WithValue(ctx, operationAuditKey{}, &operationAudit{}))
		buffer := &responseBuffer{header: make(http.Header)}
		next.ServeHTTP(buffer, r)
		auditErr := a.auditRejection(r, buffer.status)
		timedOut := ctx.Err() != nil || !time.Now().Before(deadline)
		if timedOut || auditErr != nil {
			keepCookie := !a.originAllowed(r, true) || r.Context().Value(operationAuditKey{}).(*operationAudit).rejectionStatus == 400
			buffer = &responseBuffer{header: make(http.Header)}
			r = r.WithContext(context.WithoutCancel(ctx))
			failure := &auth.Error{Code: auth.ServiceUnavailable}
			switch r.URL.Path {
			case "/login":
				a.loginFailure(buffer, r, "", failure)
			case "/logout":
				if keepCookie {
					a.render(buffer, r, 503, a.views.Error(web.AuthErrorModel{ErrorCode: auth.ServiceUnavailable}))
				} else {
					a.logoutResult(buffer, r, auth.LogoutOutcome(true, failure))
				}
			case "/admin":
				a.adminResult(buffer, r, auth.Session{}, auth.UserList{}, auth.ConnectionList{}, failure)
			default:
				jsonFailure(buffer, failure)
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

func decodeLogin(r *http.Request) (auth.LoginRequest, error) {
	var input auth.LoginRequest
	err := decodeJSON(r, auth.MaxCredentialBody, map[string]func(string){
		"username": func(value string) { input.Username = value },
		"password": func(value string) { input.Password = auth.Secret(value) },
	})
	if err != nil {
		return input, err
	}
	if !auth.ValidUsername(input.Username) || !auth.ValidPassword(input.Password) {
		return input, &auth.Error{Code: auth.InvalidArgument}
	}
	return input, nil
}

func peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	value, _ := netip.ParseAddr(host)
	return value.Unmap()
}

func (a *authHTTP) loginJSON(w http.ResponseWriter, r *http.Request) {
	if !a.originAllowed(r, false) {
		jsonFailure(w, &auth.Error{Code: auth.Forbidden})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 || !mediaType(r, "application/json") {
		jsonFailure(w, &auth.Error{Code: auth.InvalidArgument})
		return
	}
	input, err := decodeLogin(r)
	if err == nil {
		err = a.requireService()
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	serviceOwnsEvent(r)
	response, err := a.service.Login(r.Context(), auth.LoginInput{Username: input.Username, Password: input.Password, Kind: auth.CLI, Peer: peer(r)})
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, 200, response)
}

// Remember only identities established by successful authentication. Subsequent
// adapter rejection can then be attributed without looking up rejected input.
func (a *authHTTP) authenticate(r *http.Request, token auth.Secret, kind auth.Kind) (auth.Session, error) {
	session, err := a.service.Authenticate(r.Context(), token, kind)
	if err == nil {
		state := r.Context().Value(operationAuditKey{}).(*operationAudit)
		state.actorID, state.sessionID = session.User.ID, session.ID
	}
	return session, err
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

// identityJSON answers the caller's own identity and, for a member, the names
// of the connections they may use, so an agent's first call already says what
// is available. Administrators need no grant, so their list stays empty rather
// than enumerating every connection. Login responses are untouched: only this
// route fills the names.
func (a *authHTTP) identityJSON(w http.ResponseWriter, r *http.Request) {
	session, err := a.cliSession(r)
	if err == nil && session.User.Role != auth.Admin {
		if err = a.requireMembers(); err == nil {
			session.Connections, session.ConnectionsTruncated, err =
				a.members.ListGrantedConnectionNames(r.Context(), session, auth.MaxConnectionListing)
		}
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, 200, session.Identity)
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
		serviceOwnsEvent(r)
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
		serviceOwnsEvent(r)
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
	if state, ok := r.Context().Value(operationAuditKey{}).(*operationAudit); ok && status >= 400 {
		state.rejectionStatus = status
	}
	_ = web.Render(w, r, status, component)
}

func (a *authHTTP) loginFailure(w http.ResponseWriter, r *http.Request, username string, err error) {
	outcome := auth.LoginOutcome(err)
	if !auth.ValidUsername(username) {
		username = ""
	}
	retry := setRetry(w, err)
	a.render(w, r, outcome.Status, a.views.Login(web.LoginModel{Username: username, ErrorCode: outcome.ErrorCode, RetryAfterSeconds: retry}))
}

func (a *authHTTP) loginBrowser(w http.ResponseWriter, r *http.Request) {
	if !a.originAllowed(r, true) {
		a.loginFailure(w, r, "", &auth.Error{Code: auth.Forbidden})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || !mediaType(r, "application/x-www-form-urlencoded") {
		a.loginFailure(w, r, "", &auth.Error{Code: auth.InvalidArgument})
		return
	}
	// A valid existing cookie is replaced only on successful login. Duplicate
	// session credentials are rejected before touching the service.
	if _, err := a.token(r); err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.InvalidArgument {
			a.loginFailure(w, r, "", err)
			return
		}
	}
	body, err := credentialBody(r)
	values, parseErr := url.ParseQuery(string(body))
	if err != nil || parseErr != nil || len(values) != 2 || len(values["username"]) != 1 || len(values["password"]) != 1 ||
		!auth.ValidUsername(values.Get("username")) || !auth.ValidPassword(auth.Secret(values.Get("password"))) {
		a.loginFailure(w, r, "", &auth.Error{Code: auth.InvalidArgument})
		return
	}
	if err := a.requireService(); err != nil {
		a.loginFailure(w, r, values.Get("username"), err)
		return
	}
	serviceOwnsEvent(r)
	response, err := a.service.Login(r.Context(), auth.LoginInput{Username: values.Get("username"), Password: auth.Secret(values.Get("password")), Kind: auth.Browser, Peer: peer(r)})
	if err != nil {
		a.loginFailure(w, r, values.Get("username"), err)
		return
	}
	a.cookie(w, response.Token, response.ExpiresAt, false)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", "/admin")
	w.WriteHeader(303)
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
			serviceOwnsEvent(r)
			err = a.service.Logout(r.Context(), session)
		} else {
			status, _ := auth.FailureFor(err)
			r.Context().Value(operationAuditKey{}).(*operationAudit).rejectionStatus = status
		}
	}
	a.logoutResult(w, r, auth.LogoutOutcome(true, err))
}

func (a *authHTTP) adminResult(w http.ResponseWriter, r *http.Request, session auth.Session, users auth.UserList, connections auth.ConnectionList, err error) {
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
		User: session.User, Users: users.Users, Truncated: users.Truncated,
		Connections: connections.Connections, ConnectionsTruncated: connections.Truncated,
	}))
}

func (a *authHTTP) adminBrowser(w http.ResponseWriter, r *http.Request) {
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
	// current list. Listing a validated session records no event of its own.
	var users auth.UserList
	if err == nil {
		if err = a.requireAdministration(); err == nil {
			users, err = a.admin.ListUsers(r.Context(), session)
		}
	}
	var connections auth.ConnectionList
	if err == nil {
		if a.connections == nil {
			err = &auth.Error{Code: auth.ServiceUnavailable}
		} else {
			connections, err = a.connections.ListConnections(r.Context(), session, nil, auth.MaxConnectionListing)
		}
	}
	a.adminResult(w, r, session, users, connections, err)
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
	return &authHTTP{service: service, origin: canonical, secure: strings.HasPrefix(canonical, "https:"), views: views}, nil
}
