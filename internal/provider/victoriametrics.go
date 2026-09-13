package provider

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/heurema/clavis/internal/auth"
)

// Raw input keys; url, auth and whichever of user or header the method needs
// are also the canonical stored keys.
const (
	keyAuth   = "auth"
	keyUser   = "user"
	keyHeader = "header"
)

const (
	authNone   = "none"
	authBasic  = "basic"
	authBearer = "bearer"
	authHeader = "header"
)

const (
	healthPath      = "/health"
	maxProbeBody    = 1 << 10
	authorization   = "authorization"
	maxUserLength   = 256
	maxHeaderLength = 64
)

var (
	httpSchemes = []string{"http://", "https://"}
	authMethods = []string{authNone, authBasic, authBearer, authHeader}
	// Headers the transport owns. Letting a target choose one of these would
	// turn a stored setting into control over the request itself.
	reservedHeaders = []string{authorization, "host", "content-length"}
)

type victoriaMetrics struct{}

func (victoriaMetrics) Type() auth.ProviderType { return auth.ProviderVictoriaMetrics }

// ParseTarget accepts a base URL plus an authentication method. Only the
// non-secret half of the method lives in the target: the basic username or the
// custom header name.
func (victoriaMetrics) ParseTarget(raw map[string]string) (map[string]string, error) {
	if err := allowedKeys(raw, keyURL, keyAuth, keyUser, keyHeader); err != nil {
		return nil, err
	}
	base, err := victoriaMetricsURL(raw[keyURL])
	if err != nil {
		return nil, err
	}
	method := raw[keyAuth]
	if !slices.Contains(authMethods, method) {
		return nil, invalid("Setting auth must be one of " + strings.Join(authMethods, ", ") + ".")
	}
	target := map[string]string{keyURL: base, keyAuth: method}
	user, hasUser := raw[keyUser]
	header, hasHeader := raw[keyHeader]
	if hasUser != (method == authBasic) {
		return nil, invalid("Setting user is required with auth basic and not allowed with any other method.")
	}
	if hasHeader != (method == authHeader) {
		return nil, invalid("Setting header is required with auth header and not allowed with any other method.")
	}
	if hasUser {
		if !validBasicUser(user) {
			return nil, invalid("Setting user must be 1 to 256 printable characters without a colon.")
		}
		target[keyUser] = user
	}
	if hasHeader {
		if !validHeaderName(header) {
			return nil, invalid("Setting header must be an HTTP header name and must not be Authorization, Host or Content-Length.")
		}
		target[keyHeader] = header
	}
	return target, nil
}

// victoriaMetricsURL canonicalizes the base URL: scheme and host only, a
// trimmed path, and nothing that could carry a credential or steer a request.
func victoriaMetricsURL(value string) (string, error) {
	if !printableURL(value) {
		return "", invalid("Setting url is required and must be a URL without spaces or control characters.")
	}
	if !hasPrefix(value, httpSchemes) {
		return "", invalid("Setting url must begin with http:// or https://.")
	}
	if strings.Contains(value, "#") {
		return "", invalid("Setting url must not contain a fragment.")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" {
		return "", invalid("Setting url must be a valid base URL.")
	}
	if parsed.User != nil {
		return "", invalid("Setting url must not contain credentials; supply the secret separately.")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", invalid("Setting url must not contain a query string.")
	}
	if !validHost(parsed.Hostname()) {
		return "", invalid("Setting url must name exactly one host or IP address.")
	}
	if port := parsed.Port(); (port == "" && strings.HasSuffix(parsed.Host, ":")) || (port != "" && !validPort(port)) {
		return "", invalid("The port in setting url must be between 1 and 65535.")
	}
	base := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: strings.TrimRight(parsed.Path, "/")}
	return base.String(), nil
}

func validBasicUser(value string) bool {
	if value == "" || len(value) > maxUserLength {
		return false
	}
	for index := range len(value) {
		if value[index] <= ' ' || value[index] > '~' || value[index] == ':' {
			return false
		}
	}
	return true
}

// validHeaderName accepts an RFC 9110 field-name token and refuses the headers
// the transport owns, case-insensitively.
func validHeaderName(value string) bool {
	if value == "" || len(value) > maxHeaderLength {
		return false
	}
	for index := range len(value) {
		c := value[index]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return !slices.Contains(reservedHeaders, strings.ToLower(value))
}

func (victoriaMetrics) ValidateSecret(target map[string]string, secret auth.Secret) error {
	if target[keyAuth] == authNone {
		if secret != "" {
			return invalid("Setting auth none takes no secret.")
		}
		return nil
	}
	if !auth.ValidSecret(secret) {
		return invalid("The secret is 1 to 4096 bytes without null bytes or line breaks.")
	}
	// Bearer tokens and header values travel in an HTTP header, which the
	// client refuses for control bytes; reject them here rather than at check time.
	if target[keyAuth] != authBasic {
		for _, b := range []byte(secret) {
			if b < 0x20 || b == 0x7f {
				return invalid("The secret for this authentication method must be printable header text.")
			}
		}
	}
	return nil
}

// Probe sends exactly one GET to the health endpoint. The client is built per
// probe so no connection, cookie or redirect state is shared between
// connections, and a redirect is reported rather than followed: following one
// would send the secret to a host the administrator never configured.
func (victoriaMetrics) Probe(ctx context.Context, target map[string]string, secret auth.Secret) auth.CheckOutcome {
	timeout, ok := probeTimeout(ctx)
	if !ok {
		return auth.CheckUnreachable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target[keyURL]+healthPath, nil)
	if err != nil {
		return auth.CheckUnreachable
	}
	switch target[keyAuth] {
	case authBasic:
		request.SetBasicAuth(target[keyUser], string(secret))
	case authBearer:
		request.Header.Set("Authorization", "Bearer "+string(secret))
	case authHeader:
		request.Header.Set(target[keyHeader], string(secret))
	}
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true},
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return auth.CheckUnreachable
	}
	defer func() { _ = response.Body.Close() }()
	// The body is never inspected; draining a bounded prefix keeps the read
	// side tidy without letting a source stream an unbounded response at us.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProbeBody))
	switch response.StatusCode {
	case http.StatusOK:
		return auth.CheckReachable
	case http.StatusUnauthorized, http.StatusForbidden:
		return auth.CheckAuthRejected
	default:
		return auth.CheckUnreachable
	}
}
