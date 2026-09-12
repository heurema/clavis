package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
)

// strictJSON rejects ambiguous duplicate keys as well as unknown fields and
// trailing values. Never expose the decoder's error (it may contain a secret).
func strictJSON(body []byte, value any) bool {
	if !json.Valid(body) || !uniqueJSONKeys(json.NewDecoder(bytes.NewReader(body))) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	// encoding/json otherwise accepts case-insensitive aliases for struct tags.
	// Compare the wire keys with the DTO's actual JSON projection.
	canonical, err := json.Marshal(value)
	var wire, projected any
	if err != nil || json.Unmarshal(body, &wire) != nil || json.Unmarshal(canonical, &projected) != nil {
		return false
	}
	return exactJSONKeys(wire, projected)
}

func exactJSONKeys(wire, projected any) bool {
	if items, ok := wire.([]any); ok {
		expected, ok := projected.([]any)
		if !ok || len(items) != len(expected) {
			return false
		}
		for i := range items {
			if !exactJSONKeys(items[i], expected[i]) {
				return false
			}
		}
		return true
	}
	object, ok := wire.(map[string]any)
	if !ok {
		return true
	}
	expected, ok := projected.(map[string]any)
	if !ok {
		return false
	}
	for key, value := range object {
		target, exists := expected[key]
		if !exists || !exactJSONKeys(value, target) {
			return false
		}
	}
	return true
}

func uniqueJSONKeys(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return true
	}
	keys := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || keys[name] {
				return false
			}
			keys[name] = true
		}
		if !uniqueJSONKeys(d) {
			return false
		}
	}
	_, err = d.Token()
	return err == nil
}

func validIdentity(value auth.Identity) bool {
	_, offset := value.ExpiresAt.Zone()
	return auth.ValidUserID(value.User.ID) && auth.ValidUsername(value.User.Username) &&
		validRole(value.User.Role) && !value.ExpiresAt.IsZero() && offset == 0
}

func validRole(role auth.Role) bool { return role == auth.Admin || role == auth.Member }

func validRecord(value auth.UserRecord) bool {
	_, offset := value.CreatedAt.Zone()
	return auth.ValidUserID(value.ID) && auth.ValidUsername(value.Username) &&
		validRole(value.Role) && !value.CreatedAt.IsZero() && offset == 0
}

func validList(value auth.UserList) bool {
	if len(value.Users) > auth.MaxUserListing {
		return false
	}
	for _, user := range value.Users {
		if !validRecord(user) {
			return false
		}
	}
	return true
}

func validTimestamp(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0
}

func validOutcome(outcome auth.CheckOutcome) bool {
	switch outcome {
	case auth.CheckReachable, auth.CheckAuthRejected, auth.CheckUnreachable, auth.CheckCredentialsUnavailable:
		return true
	}
	return false
}

func validCheck(value auth.CheckResult) bool {
	return validOutcome(value.Outcome) && validTimestamp(value.CheckedAt)
}

// maxTargetSettings bounds the non-secret provider settings a record may carry.
const maxTargetSettings = 8

func validTarget(target map[string]string) bool {
	if len(target) == 0 || len(target) > maxTargetSettings {
		return false
	}
	for key, value := range target {
		if !auth.ValidLabelKey(key) || !printableSetting(value) {
			return false
		}
	}
	return true
}

// validConnection accepts only the safe administrative projection: identifiers,
// bounded text, valid labels, in-range resource bounds and UTC timestamps. A
// response carrying any extra field is already refused by strict decoding.
func validConnection(value auth.Connection) bool {
	if !auth.ValidUserID(value.ID) || !auth.ValidConnectionName(value.Name) || !auth.ValidProvider(value.Provider) {
		return false
	}
	if len(value.Title) > auth.MaxTitleLength || len(value.Description) > auth.MaxDescriptionLength ||
		len(value.Scope) > auth.MaxDescriptionLength {
		return false
	}
	// A hostile server must not be able to rewrite the terminal through text
	// fields that reach `--output text`.
	if (value.Title != "" && !printableSetting(value.Title)) || !printableText(value.Description) || !printableText(value.Scope) {
		return false
	}
	if !auth.ValidLabels(value.Labels) || !validTarget(value.Target) {
		return false
	}
	if value.StatementTimeoutMS < int(auth.MinStatementTimeout/time.Millisecond) ||
		value.StatementTimeoutMS > int(auth.MaxStatementTimeout/time.Millisecond) {
		return false
	}
	if value.MaxRows < 1 || value.MaxRows > auth.MaxMaxRows ||
		value.MaxBytes < auth.MinMaxBytes || value.MaxBytes > auth.MaxMaxBytes {
		return false
	}
	if !validTimestamp(value.CreatedAt) || !validTimestamp(value.UpdatedAt) {
		return false
	}
	return value.LastCheck == nil || validCheck(*value.LastCheck)
}

func validConnectionList(value auth.ConnectionList) bool {
	if len(value.Connections) > auth.MaxConnectionListing {
		return false
	}
	for _, connection := range value.Connections {
		if !validConnection(connection) {
			return false
		}
	}
	return true
}

// documentedFailure is the per-route error allowlist from the HTTP contract.
// Codes every bearer route may return (400, 401, 403, 503) pass; the rest are
// only accepted where routeFailures lists them for that method and path.
func documentedFailure(code, method, path string) bool {
	switch code {
	case auth.InvalidCredentials:
		return path == auth.LoginPath
	case auth.Unauthenticated:
		return path != auth.LoginPath
	case auth.UserNotFound, auth.UsernameTaken, auth.LastAdministrator, auth.SelfTarget, auth.RateLimited,
		auth.ConnectionExists, auth.ConnectionNotFound, auth.ConnectionInUse, auth.CredentialsUnavailable:
		return slices.Contains(routeFailures(method, path), code)
	}
	return true
}

// maxHintBytes bounds the optional server hint the CLI is willing to render.
const maxHintBytes = 512

// safeHint passes the server's optional next-step guidance through unchanged
// when it is plainly renderable. Anything longer, invalid or carrying control
// characters is dropped rather than printed: a hint is guidance, never data.
func safeHint(hint string) string {
	if hint == "" || len(hint) > maxHintBytes || !utf8.ValidString(hint) {
		return ""
	}
	if strings.ContainsFunc(hint, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	return hint
}

// routeFailures is the positive list of route-specific codes from the design's
// HTTP table. Administration routes are POST except the listing.
func routeFailures(method, path string) []string {
	target := strings.HasPrefix(path, auth.UsersPath+"/")
	connection := strings.HasPrefix(path, auth.ConnectionsPath+"/")
	switch {
	case path == auth.ConnectionsPath && method == http.MethodPost:
		return []string{auth.ConnectionExists}
	case path == auth.ConnectionsPath: // the bounded listing
		return nil
	case connection && strings.HasSuffix(path, "/update"):
		return []string{auth.ConnectionNotFound, auth.ConnectionExists}
	case connection && strings.HasSuffix(path, "/delete"):
		return []string{auth.ConnectionNotFound, auth.ConnectionInUse}
	case connection && strings.HasSuffix(path, "/check"):
		return []string{auth.ConnectionNotFound, auth.CredentialsUnavailable}
	case connection: // the record, credentials, enable and disable
		return []string{auth.ConnectionNotFound}
	case path == auth.UsersPath && method == http.MethodPost:
		return []string{auth.UsernameTaken, auth.RateLimited}
	case path == auth.UsersPath:
		return nil
	case target && (strings.HasSuffix(path, "/block") || strings.HasSuffix(path, "/role")):
		return []string{auth.UserNotFound, auth.LastAdministrator, auth.SelfTarget}
	case target && strings.HasSuffix(path, "/unblock"):
		return []string{auth.UserNotFound}
	case target: // password reset and session revocation
		return []string{auth.UserNotFound, auth.RateLimited}
	default: // login, whoami, logout
		return []string{auth.RateLimited}
	}
}

type authTransport struct {
	origin  string
	timeout time.Duration
}

// Each call uses a fresh transport, with no reusable connection on which net/http
// could retry a request. Redirect destinations never receive credentials.
func (a authTransport) request(ctx context.Context, path string, token auth.Secret, input *auth.LoginRequest, output any) *Result {
	method := http.MethodPost
	if path == auth.WhoAmIPath {
		method = http.MethodGet
	}
	if input == nil {
		return a.call(ctx, method, path, token, nil, output)
	}
	return a.call(ctx, method, path, token, input, output)
}

// apiCall names one documented route: its method, path, optional query string
// and the success status the HTTP contract documents for it.
type apiCall struct {
	method string
	path   string
	query  string
	status int
}

// call performs one bounded request on a route without query parameters.
// Creation (POST UsersPath) is the only such route whose documented success
// status is 201; every other one expects 200.
func (a authTransport) call(ctx context.Context, method, path string, token auth.Secret, input, output any) *Result {
	status := http.StatusOK
	if method == http.MethodPost && path == auth.UsersPath {
		status = http.StatusCreated
	}
	return a.send(ctx, apiCall{method: method, path: path, status: status}, token, input, output)
}

// send performs one bounded request against a documented route.
func (a authTransport) send(ctx context.Context, route apiCall, token auth.Secret, input, output any) *Result {
	method, path := route.method, route.path
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > auth.MaxCredentialBody {
			r := failure("INVALID_ARGUMENT", "Invalid request input", nil)
			return &r
		}
		body = bytes.NewReader(encoded)
	}
	address := a.origin + path
	if route.query != "" {
		address += "?" + route.query
	}
	request, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		r := failure("INVALID_ARGUMENT", "Invalid server origin", nil)
		return &r
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+string(token))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return transportFailure(ctx)
	}
	defer func() { _ = response.Body.Close() }()
	// Only the bounded listings may exceed the general response limit.
	limit := auth.MaxResponseBody
	if method == http.MethodGet && (path == auth.UsersPath || path == auth.ConnectionsPath) {
		limit = auth.MaxListingBody
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if ctx.Err() != nil {
		return transportFailure(ctx)
	}
	invalid := failure("INVALID_RESPONSE", "Server returned an invalid authentication response", nil)
	contentType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	// Every documented body, success or error, is one JSON object.
	if err != nil || len(data) > limit || typeErr != nil || contentType != "application/json" ||
		!bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return &invalid
	}
	if response.StatusCode != route.status {
		var remote auth.ErrorResponse
		if !strictJSON(data, &remote) || remote.Error.Message == "" {
			return &invalid
		}
		status, safe, known := auth.LookupFailure(remote.Error.Code)
		if !known || status != response.StatusCode || !documentedFailure(remote.Error.Code, method, path) {
			return &invalid
		}
		// The message is the client's own allowlisted text; only the optional
		// hint is server-authored, and it is rendered as guidance.
		r := failureWithHint(safe.Code, safe.Message, safeHint(remote.Error.Hint))
		return &r
	}
	if !strictJSON(data, output) {
		return &invalid
	}
	valid := false
	switch value := output.(type) {
	case *auth.LoginResponse:
		valid = auth.ValidToken(value.Token) && validIdentity(value.Identity) && value.ExpiresAt.After(time.Now())
	case *auth.Identity:
		valid = validIdentity(*value) && value.ExpiresAt.After(time.Now())
	case *auth.Revocation:
		valid = value.Revoked
	case *auth.UserRecord:
		valid = validRecord(*value)
	case *auth.UserList:
		valid = validList(*value)
	case *auth.UserMutation:
		valid = validRecord(value.User)
	case *auth.Connection:
		valid = validConnection(*value)
	case *auth.ConnectionList:
		valid = validConnectionList(*value)
	case *auth.ConnectionMutation:
		valid = validConnection(value.Connection)
	case *auth.ConnectionDeletion:
		valid = auth.ValidUserID(value.ID) && auth.ValidConnectionName(value.Name) && value.Deleted
	case *auth.ConnectionCheck:
		valid = validConnection(value.Connection) && validCheck(value.Check)
	}
	if !valid {
		return &invalid
	}
	return nil
}

func transportFailure(ctx context.Context) *Result {
	r := failure("SERVER_UNREACHABLE", "Server could not be reached", nil)
	if ctx.Err() != nil {
		r = failure("TIMEOUT", "Authentication request did not complete; a mutation may have taken effect", nil)
	}
	return &r
}
