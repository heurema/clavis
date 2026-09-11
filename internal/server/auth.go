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
	service  auth.Service
	recorder auth.EventRecorder
	origin   string
	secure   bool
	views    AuthViews
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

func (a *authHTTP) auditRejection(r *http.Request, status int) error {
	state := r.Context().Value(operationAuditKey{}).(*operationAudit)
	if r.Method != http.MethodPost || state.serviceOwns {
		return nil
	}
	if state.rejectionStatus != 0 {
		status = state.rejectionStatus
	}
	var action auth.EventAction
	switch r.URL.Path {
	case "/login", auth.LoginPath:
		action = auth.EventLogin
	case "/logout", auth.LogoutPath:
		action = auth.EventLogout
	default:
		action = auth.EventRevoke
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
				a.adminResult(buffer, r, auth.Session{}, failure)
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

func credentialBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, auth.MaxCredentialBody+1))
	if err != nil || len(b) > auth.MaxCredentialBody || !utf8.Valid(b) {
		return nil, &auth.Error{Code: auth.InvalidArgument}
	}
	return b, nil
}

// Decode object members explicitly so duplicate fields, case aliases and null
// cannot be accepted by encoding/json's otherwise permissive struct decoder.
func decodeLogin(r *http.Request) (auth.LoginRequest, error) {
	var input auth.LoginRequest
	b, err := credentialBody(r)
	if err != nil {
		return input, err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return input, &auth.Error{Code: auth.InvalidArgument}
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || (name != "username" && name != "password") || seen[name] {
			return input, &auth.Error{Code: auth.InvalidArgument}
		}
		seen[name] = true
		value, err := decoder.Token()
		text, ok := value.(string)
		if err != nil || !ok {
			return input, &auth.Error{Code: auth.InvalidArgument}
		}
		if name == "username" {
			input.Username = text
		} else {
			input.Password = auth.Secret(text)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return input, &auth.Error{Code: auth.InvalidArgument}
	}
	if _, err := decoder.Token(); err != io.EOF || !auth.ValidUsername(input.Username) || !auth.ValidPassword(input.Password) {
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

func (a *authHTTP) identityJSON(w http.ResponseWriter, r *http.Request) {
	session, err := a.cliSession(r)
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
	if err == nil && !auth.ValidUserID(chi.URLParam(r, "userID")) {
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

func (a *authHTTP) adminResult(w http.ResponseWriter, r *http.Request, session auth.Session, err error) {
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
	a.render(w, r, 200, a.views.Admin(web.AdminModel{User: session.User}))
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
	a.adminResult(w, r, session, err)
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
