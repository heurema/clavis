package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LocalAuth owns SQL authentication, not transport. Its methods bound their
// entire operation even when called without an HTTP adapter.
type LocalAuth struct {
	pool    *pgxpool.Pool
	checker platform.Checker
	ttl     time.Duration
	keys    *secrets.Keyring
}

func NewLocalAuth(pool *pgxpool.Pool, checker platform.Checker, ttl time.Duration) (*LocalAuth, error) {
	if checker == nil || ttl < auth.MinSessionTTL || ttl > auth.MaxSessionTTL {
		return nil, &auth.Error{Code: auth.InvalidArgument}
	}
	return &LocalAuth{pool: pool, checker: checker, ttl: ttl}, nil
}

var _ auth.Service = (*LocalAuth)(nil)

func unavailable() error { return &auth.Error{Code: auth.ServiceUnavailable} }

func (s *LocalAuth) ready(ctx context.Context) error {
	r := s.checker.Check(ctx)
	if ctx.Err() != nil {
		return unavailable()
	}
	if !r.Ready() {
		return &auth.Error{Code: r.Response().Error.Code}
	}
	return nil
}

func (s *LocalAuth) Login(ctx context.Context, input auth.LoginInput) (auth.LoginResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var response auth.LoginResponse
	if !auth.ValidUsername(input.Username) || !auth.ValidPassword(input.Password) ||
		(input.Kind != auth.CLI && input.Kind != auth.Browser) || !input.Peer.IsValid() {
		return response, &auth.Error{Code: auth.InvalidArgument}
	}
	if err := s.ready(ctx); err != nil {
		return response, err
	}
	reservation, err := s.reserve(ctx, input)
	if err != nil {
		return response, err
	}
	queries := sqlc.New(s.pool)
	found, err := queries.FindLoginUser(ctx, input.Username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return response, unavailable()
	}
	user := auth.User{ID: found.ID, Username: found.Username, Role: auth.Role(found.Role)}
	hash := found.PasswordHash
	unknown := errors.Is(err, pgx.ErrNoRows)
	if unknown {
		hash = auth.DummyPasswordHash()
	}
	valid, verifyErr := auth.VerifyPassword(ctx, input.Password, hash)
	if ctx.Err() != nil {
		return response, unavailable()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return response, unavailable()
	}
	defer rollback(ctx, tx)
	qtx := queries.WithTx(tx)
	if verifyErr != nil {
		var failure *auth.Error
		if errors.As(verifyErr, &failure) && failure.Code == auth.RateLimited {
			// The reservation is released because the attempt never reached a
			// password comparison; the release is committed like any other.
			if err := reservation.release(ctx, tx); err != nil {
				return response, unavailable()
			}
			if err := tx.Commit(ctx); err != nil {
				return response, unavailable()
			}
			return response, &auth.Error{Code: auth.RateLimited, RetryAfter: time.Second}
		}
		return response, unavailable()
	}
	if unknown || found.Disabled || !valid {
		return response, &auth.Error{Code: auth.InvalidCredentials}
	}
	// Re-read and lock the current account after hashing. Role/disabled/hash
	// changes cannot race issuance; revoke-all takes this same row lock.
	current, err := qtx.LockLoginUser(ctx, user.ID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (current.Disabled || current.PasswordHash != hash)) {
		return response, &auth.Error{Code: auth.InvalidCredentials}
	}
	if err != nil {
		return response, unavailable()
	}
	user.Username, user.Role = current.Username, auth.Role(current.Role)
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return response, unavailable()
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(token))
	id, err := bootstrapID()
	if err != nil {
		return response, unavailable()
	}
	expires, err := qtx.CreateSession(ctx, sqlc.CreateSessionParams{
		ID: id, TokenDigest: digest[:], UserID: user.ID,
		Kind: string(input.Kind), TtlSeconds: s.ttl.Seconds(),
	})
	if err != nil {
		return response, unavailable()
	}
	if err := reservation.release(ctx, tx); err != nil {
		return response, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return response, unavailable()
	}
	return auth.LoginResponse{Token: auth.Secret(token), Identity: auth.Identity{User: user, ExpiresAt: expires.UTC()}}, nil
}

func (s *LocalAuth) Authenticate(ctx context.Context, token auth.Secret, kind auth.Kind) (auth.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var session auth.Session
	if !auth.ValidToken(token) || (kind != auth.CLI && kind != auth.Browser) {
		return session, &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return session, err
	}
	digest := sha256.Sum256([]byte(token))
	row, err := sqlc.New(s.pool).AuthenticateSession(ctx, sqlc.AuthenticateSessionParams{
		TokenDigest: digest[:], Kind: string(kind),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return session, &auth.Error{Code: auth.Unauthenticated}
	}
	if err != nil || ctx.Err() != nil {
		return auth.Session{}, unavailable()
	}
	return auth.Session{
		ID: row.SessionID, Kind: auth.Kind(row.Kind),
		User:      auth.User{ID: row.UserID, Username: row.Username, Role: auth.Role(row.Role)},
		ExpiresAt: row.ExpiresAt.UTC(),
	}, nil
}

func recheck(ctx context.Context, tx pgx.Tx, previous auth.Session) (auth.Session, error) {
	var current auth.Session
	row, err := sqlc.New(tx).RecheckSession(ctx, sqlc.RecheckSessionParams{
		SessionID: previous.ID, UserID: previous.User.ID, Kind: string(previous.Kind),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return current, &auth.Error{Code: auth.Unauthenticated}
	}
	if err != nil {
		return current, unavailable()
	}
	return auth.Session{
		ID: row.SessionID, Kind: auth.Kind(row.Kind),
		User:      auth.User{ID: row.UserID, Username: row.Username, Role: auth.Role(row.Role)},
		ExpiresAt: row.ExpiresAt,
	}, nil
}

func (s *LocalAuth) Logout(ctx context.Context, session auth.Session) error {
	return s.mutate(ctx, session, "", false)
}

// RevokeUserSessions addresses its target by UUID or username; the reference
// is resolved inside the transaction, under the same lock, so both forms have
// the same outcome.
func (s *LocalAuth) RevokeUserSessions(ctx context.Context, session auth.Session, userRef string) error {
	if !auth.ValidUserRef(userRef) {
		return &auth.Error{Code: auth.InvalidArgument}
	}
	return s.mutate(ctx, session, userRef, true)
}

// mutate revokes either the caller's own session or every session of another
// user. revoke tells the two apart, because an unknown target reference must
// still be answered as a revocation denial rather than as a logout.
func (s *LocalAuth) mutate(ctx context.Context, previous auth.Session, ref string, revoke bool) error {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	if !auth.ValidUserID(previous.ID) || !auth.ValidUserID(previous.User.ID) {
		return &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return unavailable()
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	// Consistent ordering prevents opposing admin revocations from deadlocking.
	if err := lockMutationUsers(ctx, queries, previous.User.ID, ref); err != nil {
		return unavailable()
	}
	current, err := recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			return &auth.Error{Code: auth.Unauthenticated}
		}
		return unavailable()
	}
	if revoke && current.User.Role != auth.Admin {
		return &auth.Error{Code: auth.Forbidden}
	}
	if revoke {
		found, err := lockUser(ctx, queries, ref)
		if err != nil {
			var failure *auth.Error
			if errors.As(err, &failure) && failure.Code == auth.UserNotFound {
				return &auth.Error{Code: auth.UserNotFound}
			}
			return unavailable()
		}
		if err := queries.RevokeUserSessions(ctx, found.ID); err != nil {
			return unavailable()
		}
	} else if err := queries.RevokeSession(ctx, current.ID); err != nil {
		return unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable()
	}
	return nil
}
