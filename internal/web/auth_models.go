package web

import (
	"context"
	"errors"
	"io"

	"github.com/a-h/templ"
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

// Authentication views are not routed by the foundation. Until the web lane
// provides them, fail rendering rather than presenting fixture data as a UI.
func Login(LoginModel) templ.Component {
	return unavailableAuthView()
}

func Admin(AdminModel) templ.Component {
	return unavailableAuthView()
}

func AuthError(AuthErrorModel) templ.Component {
	return unavailableAuthView()
}

func unavailableAuthView() templ.Component {
	return templ.ComponentFunc(func(context.Context, io.Writer) error {
		return errors.New("authentication views are not available")
	})
}
