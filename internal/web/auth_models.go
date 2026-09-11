package web

import (
	"github.com/heurema/clavis/internal/auth"
)

// These models are the backend/web ownership boundary. They contain only safe
// display data; HTTP status, cookies and credential processing belong to server.
type LoginModel struct {
	Username          string
	ErrorCode         string
	RetryAfterSeconds int
}

type AdminModel struct {
	User auth.User
}

type AuthErrorModel struct {
	ErrorCode                   string
	RemoteRevocationUnconfirmed bool
}
