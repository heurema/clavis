package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
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
		(value.User.Role == auth.Admin || value.User.Role == auth.Member) &&
		!value.ExpiresAt.IsZero() && offset == 0
}

type authTransport struct {
	origin  string
	timeout time.Duration
}

// Each call uses a fresh transport, with no reusable connection on which net/http
// could retry a request. Redirect destinations never receive credentials.
func (a authTransport) request(ctx context.Context, path string, token auth.Secret, input *auth.LoginRequest, output any) *Result {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	method := http.MethodPost
	if path == auth.WhoAmIPath {
		method = http.MethodGet
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > auth.MaxCredentialBody {
			r := failure("INVALID_ARGUMENT", "Invalid login input", nil)
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
	data, err := io.ReadAll(io.LimitReader(response.Body, auth.MaxResponseBody+1))
	if ctx.Err() != nil {
		return transportFailure(ctx)
	}
	invalid := failure("INVALID_RESPONSE", "Server returned an invalid authentication response", nil)
	contentType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || len(data) > auth.MaxResponseBody || typeErr != nil || contentType != "application/json" {
		return &invalid
	}
	if response.StatusCode != http.StatusOK {
		var remote auth.ErrorResponse
		if !strictJSON(data, &remote) || remote.Error.Message == "" {
			return &invalid
		}
		status, safe, known := auth.LookupFailure(remote.Error.Code)
		if !known || status != response.StatusCode ||
			(remote.Error.Code == auth.InvalidCredentials && path != auth.LoginPath) ||
			(remote.Error.Code == auth.Unauthenticated && path == auth.LoginPath) ||
			(remote.Error.Code == auth.UserNotFound && !strings.HasPrefix(path, "/api/admin/users/")) {
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
