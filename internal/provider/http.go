package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
)

// This file holds what the two HTTP sources share. Both reach a base URL an
// administrator configured, apply the same four authentication methods per
// request, refuse a redirect, keep no connection alive and bound a body they
// did not write. Sharing it rather than copying it keeps one answer to "what
// does the platform send and what will it read back" for every HTTP provider.

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

const (
	// How much of a failing answer is read before it is examined, and how much
	// of it may travel to the caller as the source's own text.
	maxErrorBody = 64 << 10
	maxErrorText = 4 << 10
)

var (
	httpSchemes = []string{"http://", "https://"}
	authMethods = []string{authNone, authBasic, authBearer, authHeader}
	// Headers the transport owns. Letting a target choose one of these would
	// turn a stored setting into control over the request itself.
	reservedHeaders = []string{authorization, "host", "content-length"}
)

// The two body failures. They are internal: each provider turns them into the
// source failure the caller sees, with the platform's own fixed text.
var (
	errBodyTooLarge = errors.New("the response body passed the ceiling")
	errMalformed    = errors.New("the response is not the source's envelope")
)

// httpTarget parses the settings both HTTP providers share: a base URL plus an
// authentication method and the non-secret half of that method. A provider
// that takes further settings checks the whole key set itself and adds its own
// keys to what this returns; this reads only the four it knows.
func httpTarget(raw map[string]string) (map[string]string, error) {
	base, err := httpBaseURL(raw[keyURL])
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

// httpBaseURL canonicalizes the base URL: scheme and host only, a trimmed
// path, and nothing that could carry a credential or steer a request.
func httpBaseURL(value string) (string, error) {
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

// validateHTTPSecret is the secret rule both HTTP providers apply: none takes
// nothing, and a secret that travels in a header must be header text.
func validateHTTPSecret(target map[string]string, secret auth.Secret) error {
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

// applyHTTPAuth puts the stored authentication on one request. Every request a
// provider sends, probe or execution, goes through here, so a source sees the
// same credential in the same place whatever the request was for.
func applyHTTPAuth(request *http.Request, target map[string]string, secret auth.Secret) {
	switch target[keyAuth] {
	case authBasic:
		request.SetBasicAuth(target[keyUser], string(secret))
	case authBearer:
		request.Header.Set("Authorization", "Bearer "+string(secret))
	case authHeader:
		request.Header.Set(target[keyHeader], string(secret))
	}
}

// httpClient builds the one client shape both providers use. It is built per
// request so no connection, cookie or redirect state is shared between
// connections, and a redirect is reported rather than followed: following one
// would send the secret to a host the administrator never configured.
func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true},
	}
}

// httpProbe sends exactly one GET to the health endpoint under the stored
// authentication plus whatever headers the provider adds of its own.
func httpProbe(ctx context.Context, target map[string]string, secret auth.Secret, extra http.Header) auth.CheckOutcome {
	timeout, ok := probeTimeout(ctx)
	if !ok {
		return auth.CheckUnreachable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target[keyURL]+healthPath, nil)
	if err != nil {
		return auth.CheckUnreachable
	}
	applyHTTPHeaders(request, extra)
	applyHTTPAuth(request, target, secret)
	client := httpClient(timeout)
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

// applyHTTPHeaders adds a provider's own headers before the authentication, so
// a provider header can never overwrite the credential the target configured.
func applyHTTPHeaders(request *http.Request, extra http.Header) {
	for name, values := range extra {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
}

// httpStatusFailure maps the statuses that are the same for every HTTP source:
// a refused credential, and a redirect that was refused rather than followed,
// which means the source we were configured to reach said nothing. The second
// return says whether the status was one of them.
func httpStatusFailure(status int) (error, bool) {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return ErrAuthRejected, true
	case status >= 300 && status < 400:
		return ErrUnreachable, true
	default:
		return nil, false
	}
}

// httpTransportError maps a request that never produced a response. A spent
// deadline, ours or the client's, is the timeout the caller was promised;
// everything else is an unreachable source, as the probe treats it.
func httpTransportError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return ErrTimeout
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return ErrTimeout
	}
	return ErrUnreachable
}

// readError keeps the body ceiling and a spent deadline apart from a document
// that simply is not what the source promised.
func readError(err error) error {
	switch {
	case errors.Is(err, errBodyTooLarge):
		return errBodyTooLarge
	case errors.Is(err, context.DeadlineExceeded), os.IsTimeout(err):
		return ErrTimeout
	default:
		return errMalformed
	}
}

// sourceTimeout gives a missing bound the documented default: a caller that
// passes none must not get an unbounded query.
func sourceTimeout(timeout time.Duration) time.Duration {
	if timeout < time.Millisecond {
		return auth.DefaultStatementTimeout
	}
	return timeout
}

// timeoutValue renders the timeout as the source's own duration parameter. The
// source caps it at its configured maximum, which the platform respects rather
// than working around.
func timeoutValue(timeout time.Duration) string {
	return strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64) + "s"
}

// ceilingReader stops a body at the documented ceiling with an error of its
// own, so a source that streams past it fails the request rather than
// producing a document that merely looks cut short.
type ceilingReader struct {
	reader    io.Reader
	remaining int64
}

func (c *ceilingReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	read, err := c.reader.Read(p)
	c.remaining -= int64(read)
	return read, err
}

// boundedText bounds text the platform did not write. It is cut on a rune
// boundary and made valid UTF-8, so it can travel through the JSON envelope as
// the source sent it without becoming something else.
func boundedText(body []byte) string {
	text := strings.TrimSpace(strings.ToValidUTF8(string(body), ""))
	if len(text) <= maxErrorText {
		return text
	}
	cut := maxErrorText
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

// jsonString encodes one JSON string. The escapes may differ from the source's
// own bytes; the value does not, which is what the platform promises.
func jsonString(value string) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte(`""`)
	}
	return encoded
}

// setParameter puts a parameter on the wire only when the caller gave it: an
// absent value is an absent parameter, so the source applies its own default
// rather than one the platform invented.
func setParameter(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

// maxJSONDepth bounds JSON nesting, so a document cannot drive the decoder's
// recursion; nothing either source answers is anywhere near this deep.
const maxJSONDepth = 32

// jsonWalker reads a source's answer as a stream of tokens rather than
// unmarshalling it: the document may be far larger than the response the
// caller is allowed, and what fits must be kept in source order while the rest
// is read and dropped. Member order survives because every member is
// re-encoded as it is read, never through a map.
type jsonWalker struct {
	decoder *json.Decoder
}

func (w *jsonWalker) next() (json.Token, error) {
	token, err := w.decoder.Token()
	if err != nil {
		return nil, readError(err)
	}
	return token, nil
}

func (w *jsonWalker) expect(want json.Delim) error {
	token, err := w.next()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != want {
		return errMalformed
	}
	return nil
}

func (w *jsonWalker) key() (string, error) {
	token, err := w.next()
	if err != nil {
		return "", err
	}
	key, ok := token.(string)
	if !ok {
		return "", errMalformed
	}
	return key, nil
}

func (w *jsonWalker) text() (string, error) {
	token, err := w.next()
	if err != nil {
		return "", err
	}
	text, ok := token.(string)
	if !ok {
		return "", errMalformed
	}
	return text, nil
}

// skip reads one value and discards it, bounded against a document whose
// nesting would otherwise drive this recursion.
func (w *jsonWalker) skip(depth int) error {
	if depth > maxJSONDepth {
		return errMalformed
	}
	token, err := w.next()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '}' || delim == ']' {
		return errMalformed
	}
	for w.decoder.More() {
		if delim == '{' {
			if _, err := w.next(); err != nil {
				return err
			}
		}
		if err := w.skip(depth + 1); err != nil {
			return err
		}
	}
	_, err = w.next()
	return err
}
