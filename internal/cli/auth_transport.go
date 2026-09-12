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

// documentedFailure is the per-route error allowlist from the HTTP contract.
// Codes every bearer route may return (400, 401, 403, 503) pass; the rest are
// only accepted where routeFailures lists them for that method and path.
func documentedFailure(code, method, path string) bool {
	switch code {
	case auth.InvalidCredentials:
		return path == auth.LoginPath
	case auth.Unauthenticated:
		return path != auth.LoginPath
	case auth.UserNotFound, auth.UsernameTaken, auth.LastAdministrator, auth.SelfTarget, auth.RateLimited:
		return slices.Contains(routeFailures(method, path), code)
	}
	return true
}

// routeFailures is the positive list of route-specific codes from the design's
// HTTP table. Administration routes are POST except the listing.
func routeFailures(method, path string) []string {
	target := strings.HasPrefix(path, auth.UsersPath+"/")
	switch {
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

// call performs one bounded request. Creation (POST UsersPath) is the only
// route whose documented success status is 201; every other route expects 200.
func (a authTransport) call(ctx context.Context, method, path string, token auth.Secret, input, output any) *Result {
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
	request, err := http.NewRequestWithContext(ctx, method, a.origin+path, body)
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
	// Only the bounded user listing may exceed the general response limit.
	limit := auth.MaxResponseBody
	if method == http.MethodGet && path == auth.UsersPath {
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
	expected := http.StatusOK
	if method == http.MethodPost && path == auth.UsersPath {
		expected = http.StatusCreated
	}
	if response.StatusCode != expected {
		var remote auth.ErrorResponse
		if !strictJSON(data, &remote) || remote.Error.Message == "" {
			return &invalid
		}
		status, safe, known := auth.LookupFailure(remote.Error.Code)
		if !known || status != response.StatusCode || !documentedFailure(remote.Error.Code, method, path) {
			return &invalid
		}
		r := failure(safe.Code, safe.Message, nil)
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
