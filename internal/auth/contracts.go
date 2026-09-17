// Package auth defines shared identity and authentication service contracts.
// It does not depend on HTML, database drivers or the CLI output envelope.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	OperationTimeout  = 5 * time.Second
	MaxCredentialBody = 8 * 1024
	MaxResponseBody   = 64 * 1024
	MinPasswordBytes  = 15
	MaxPasswordBytes  = 1024
)

// Every session has an idle expiry, renewed on use, and an absolute expiry
// that never moves. Valid settings satisfy
// MinSessionDuration <= idle timeout <= max lifetime <= MaxSessionDuration.
const (
	DefaultSessionIdleTimeout = 168 * time.Hour
	DefaultSessionMaxLifetime = 720 * time.Hour
	MinSessionDuration        = 5 * time.Minute
	MaxSessionDuration        = 2160 * time.Hour
)

// ValidSessionDurations reports whether an idle timeout and a maximum lifetime
// satisfy the session duration rule.
func ValidSessionDurations(idle, lifetime time.Duration) bool {
	return idle >= MinSessionDuration && idle <= lifetime && lifetime <= MaxSessionDuration
}

const (
	TokenPath  = "/api/auth/token"
	WhoAmIPath = "/api/auth/whoami"
	LogoutPath = "/api/auth/logout"
	RevokePath = "/api/admin/users/{userID}/sessions/revoke"

	// Administration routes: GET UsersPath lists, POST UsersPath creates.
	UsersPath        = "/api/admin/users"
	UserBlockPath    = "/api/admin/users/{userID}/block"
	UserUnblockPath  = "/api/admin/users/{userID}/unblock"
	UserPasswordPath = "/api/admin/users/{userID}/password"
	UserRolePath     = "/api/admin/users/{userID}/role"
)

// MaxUserListing bounds one listing; a longer list reports truncation.
// MaxListingBody bounds the listing response alone: 1,000 records exceed the
// general MaxResponseBody, so GET UsersPath has its own documented limit.
const (
	MaxUserListing = 1000
	MaxListingBody = 256 * 1024
)

type Role string

const (
	Admin  Role = "admin"
	Member Role = "member"
)

type Kind string

const (
	Browser Kind = "browser"
	CLI     Kind = "cli"
)

// Secret redacts ordinary formatting. JSON deliberately retains the value for
// credential transport/storage: never put a secret-bearing DTO in CLI results.
type Secret string

func (Secret) String() string   { return "[REDACTED]" }
func (Secret) GoString() string { return "[REDACTED]" }

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
}

// Identity is the safe output projection shared by login and whoami.
// ExpiresAt is the session's absolute expiry and IdleExpiresAt the idle expiry
// that use renews, never later than ExpiresAt. The
// connection names are filled only by whoami for members: what the caller may
// use through any path, in name order, bounded with an explicit truncation
// flag. The group names are filled by whoami for every caller, bounded and
// truncated independently of the connections.
type Identity struct {
	User                 User      `json:"user"`
	ExpiresAt            time.Time `json:"expiresAt"`
	IdleExpiresAt        time.Time `json:"idleExpiresAt"`
	Connections          []string  `json:"connections,omitempty"`
	ConnectionsTruncated bool      `json:"connectionsTruncated,omitempty"`
	Groups               []string  `json:"groups,omitempty"`
	GroupsTruncated      bool      `json:"groupsTruncated,omitempty"`
}

// LoginResponse is secret-bearing and only for internal HTTP/cache handling.
type LoginResponse struct {
	Token Secret `json:"token"`
	Identity
}

type Revocation struct {
	Revoked bool `json:"revoked"`
}

// LoginInput is a browser sign-in form submission. A password reaches the
// service only here; CLI sessions come from ExchangeCLICode.
type LoginInput struct {
	Username string
	Password Secret
	Peer     netip.Addr
}

// Session contains no bearer token. It represents one freshly validated
// session; service implementations must recheck authority for mutations.
type Session struct {
	ID   string
	Kind Kind
	Identity
}

// Service owns readiness: every method must fail closed when its store is not
// ready, including direct calls without an HTTP adapter. A prior readiness or
// authentication result never replaces current authority checks for mutations.
type Service interface {
	// Login verifies a password from the browser form and issues a browser
	// session.
	Login(context.Context, LoginInput) (LoginResponse, error)
	Authenticate(context.Context, Secret, Kind) (Session, error)
	Logout(context.Context, Session) error
	RevokeUserSessions(context.Context, Session, string) error
	// ApproveCLI stores a one-time code for the approving browser session and
	// the link's challenge and returns the code, which only the loopback
	// callback redirect carries.
	ApproveCLI(context.Context, Session, CLIAuthorization) (Secret, error)
	// ExchangeCLICode consumes the code on its first presentation and issues a
	// CLI session only when the verifier matches the stored challenge.
	ExchangeCLICode(context.Context, TokenRequest) (LoginResponse, error)
}

// AuthorizePath is the browser document a CLI opens to request a session.
const AuthorizePath = "/authorize"

// CLIAuthorizationLifetime bounds how long an approved code can be redeemed.
const CLIAuthorizationLifetime = 2 * time.Minute

// Loopback ports a CLI may request: an unprivileged process never binds below
// 1024.
const (
	MinCallbackPort = 1024
	MaxCallbackPort = 65535
)

// CLIAuthorization is a parsed authorization link. Values that come from
// ParseCLIAuthorization are valid by construction, and every URL built from
// one uses only these parsed values, never submitted text.
type CLIAuthorization struct {
	Port      int
	Challenge string
	State     string
}

// TokenRequest redeems an approved code. It is secret-bearing transport input.
type TokenRequest struct {
	Code     Secret `json:"code"`
	Verifier Secret `json:"verifier"`
}

// ParseCLIAuthorization accepts exactly the three link parameters, each once:
// a canonical decimal port from 1024 to 65535, and a challenge and a state of
// 43 base64url characters encoding 32 bytes. Anything else is not a link.
func ParseCLIAuthorization(values url.Values) (CLIAuthorization, bool) {
	if len(values) != 3 || len(values["port"]) != 1 || len(values["challenge"]) != 1 || len(values["state"]) != 1 {
		return CLIAuthorization{}, false
	}
	raw := values.Get("port")
	port, err := strconv.Atoi(raw)
	if err != nil || strconv.Itoa(port) != raw || port < MinCallbackPort || port > MaxCallbackPort {
		return CLIAuthorization{}, false
	}
	challenge, state := values.Get("challenge"), values.Get("state")
	if !ValidToken(Secret(challenge)) || !ValidToken(Secret(state)) {
		return CLIAuthorization{}, false
	}
	return CLIAuthorization{Port: port, Challenge: challenge, State: state}, true
}

// ParseAuthorizeLink accepts a return target only in the literal shape of a
// relative authorization link: no scheme, host, user, fragment or alternative
// path spelling, and parameters ParseCLIAuthorization accepts.
func ParseAuthorizeLink(raw string) (CLIAuthorization, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != AuthorizePath || parsed.RawPath != "" || strings.Contains(raw, "#") {
		return CLIAuthorization{}, false
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return CLIAuthorization{}, false
	}
	return ParseCLIAuthorization(values)
}

// Link is the relative authorization link; a CLI prefixes the server origin.
func (a CLIAuthorization) Link() string {
	return AuthorizePath + "?" + url.Values{
		"port": {strconv.Itoa(a.Port)}, "challenge": {a.Challenge}, "state": {a.State},
	}.Encode()
}

// CallbackURL is where an approval sends the browser: the loopback listener at
// the parsed integer port, with the fresh code and the validated state.
func (a CLIAuthorization) CallbackURL(code Secret) string {
	return "http://127.0.0.1:" + strconv.Itoa(a.Port) + "/callback?" + url.Values{
		"code": {string(code)}, "state": {a.State},
	}.Encode()
}

// VerifierMatches compares the SHA-256 of a verifier with a stored 32-byte
// challenge in constant time.
func VerifierMatches(verifier Secret, challenge []byte) bool {
	digest := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare(digest[:], challenge) == 1
}

// UserRecord is the safe administrative projection of an account. It never
// carries a password hash or session data.
type UserRecord struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type UserList struct {
	Users     []UserRecord `json:"users"`
	Truncated bool         `json:"truncated"`
}

// Request DTOs carrying a Secret are transport inputs only; they are never
// result data.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password Secret `json:"password"`
}

type ResetPasswordRequest struct {
	Password Secret `json:"password"`
}

type SetRoleRequest struct {
	Role Role `json:"role"`
}

// UserMutation reports the account after a mutation and whether that
// mutation revoked the target's sessions.
type UserMutation struct {
	User            UserRecord `json:"user"`
	SessionsRevoked bool       `json:"sessionsRevoked"`
}

// Administration is separate from Service so sign-in contracts stay frozen.
// Every method rechecks the actor's current session and administrator role
// inside its own transaction; the passed Session is never trusted alone.
type Administration interface {
	ListUsers(context.Context, Session) (UserList, error)
	CreateUser(context.Context, Session, CreateUserRequest) (UserRecord, error)
	SetUserDisabled(context.Context, Session, string, bool) (UserMutation, error)
	ResetPassword(context.Context, Session, string, Secret) (UserMutation, error)
	SetRole(context.Context, Session, string, Role) (UserMutation, error)
}
