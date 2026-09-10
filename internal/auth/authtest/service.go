// Package authtest provides opt-in service fixtures for adapter tests.
// It must not be imported by a production entry point.
package authtest

import (
	"context"

	"github.com/heurema/clavis/internal/auth"
)

// Service fails closed for any behavior a fixture has not explicitly provided.
type Service struct {
	LoginFunc              func(context.Context, auth.LoginInput) (auth.LoginResponse, error)
	AuthenticateFunc       func(context.Context, auth.Secret, auth.Kind) (auth.Session, error)
	LogoutFunc             func(context.Context, auth.Session) error
	RevokeUserSessionsFunc func(context.Context, auth.Session, string) error
}

var _ auth.Service = (*Service)(nil)

func (s *Service) Login(ctx context.Context, input auth.LoginInput) (auth.LoginResponse, error) {
	if s.LoginFunc == nil {
		return auth.LoginResponse{}, &auth.Error{Code: auth.ServiceUnavailable}
	}
	return s.LoginFunc(ctx, input)
}

func (s *Service) Authenticate(ctx context.Context, token auth.Secret, kind auth.Kind) (auth.Session, error) {
	if s.AuthenticateFunc == nil {
		return auth.Session{}, &auth.Error{Code: auth.ServiceUnavailable}
	}
	return s.AuthenticateFunc(ctx, token, kind)
}

func (s *Service) Logout(ctx context.Context, session auth.Session) error {
	if s.LogoutFunc == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return s.LogoutFunc(ctx, session)
}

func (s *Service) RevokeUserSessions(ctx context.Context, actor auth.Session, userID string) error {
	if s.RevokeUserSessionsFunc == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return s.RevokeUserSessionsFunc(ctx, actor, userID)
}
