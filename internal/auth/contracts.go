// Package auth defines shared identity and authentication service contracts.
// It does not depend on HTML, database drivers or the CLI output envelope.
package auth

import (
	"context"
	"net/netip"
	"time"
)

const (
	OperationTimeout  = 5 * time.Second
	DefaultSessionTTL = 8 * time.Hour
	MinSessionTTL     = 5 * time.Minute
	MaxSessionTTL     = 24 * time.Hour
	MaxCredentialBody = 8 * 1024
	MaxResponseBody   = 64 * 1024
	MinPasswordBytes  = 15
	MaxPasswordBytes  = 1024
)

const (
	LoginPath  = "/api/auth/login"
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
const MaxUserListing = 1000

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
type Identity struct {
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password Secret `json:"password"`
}

// LoginResponse is secret-bearing and only for internal HTTP/cache handling.
type LoginResponse struct {
	Token Secret `json:"token"`
	Identity
}

type Revocation struct {
	Revoked bool `json:"revoked"`
}

type LoginInput struct {
	Username string
	Password Secret
	Kind     Kind
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
	Login(context.Context, LoginInput) (LoginResponse, error)
	Authenticate(context.Context, Secret, Kind) (Session, error)
	Logout(context.Context, Session) error
	RevokeUserSessions(context.Context, Session, string) error
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
