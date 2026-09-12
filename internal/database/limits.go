package database

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/jackc/pgx/v5"
)

const limitLock int64 = 0x434c415649530002
const maxLimitRows = 10000

type limitReservation struct {
	keys    [2][32]byte
	expires [2]time.Time
}

// Reserve before hashing. In-flight attempts count conservatively as failures
// until success, so replicas cannot all slip past a limit concurrently. An
// interrupted attempt expires naturally and never permanently locks an account.
func (s *LocalAuth) reserve(ctx context.Context, input auth.LoginInput) (limitReservation, error) {
	r := limitReservation{keys: [2][32]byte{
		sha256.Sum256([]byte("username:" + input.Username)),
		sha256.Sum256([]byte("peer:" + input.Peer.Unmap().String())),
	}}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, unavailable()
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	if err = queries.LockTransaction(ctx, limitLock); err != nil {
		return r, unavailable()
	}
	// Indexed, bounded cleanup plus a hard state cap: randomized usernames or
	// peers cannot grow this table without bound.
	if err = queries.CleanupLoginLimits(ctx); err != nil {
		return r, unavailable()
	}
	count, err := queries.CountLoginLimits(ctx)
	if err != nil {
		return r, unavailable()
	}
	limited := count > maxLimitRows-2
	for index, key := range r.keys {
		limit, err := queries.GetLoginLimit(ctx, key[:])
		if err != nil && err != pgx.ErrNoRows {
			return r, unavailable()
		}
		threshold := int32(10)
		if index == 1 {
			threshold = 50
		}
		if limit.Active && limit.Failures >= threshold {
			limited = true
		}
	}
	if limited {
		// The bounded cleanup above is committed even when the attempt is
		// refused, so a refused window still retires its expired rows.
		if err := tx.Commit(ctx); err != nil {
			return r, unavailable()
		}
		return r, &auth.Error{Code: auth.RateLimited, RetryAfter: 5 * time.Minute}
	}
	for index, key := range r.keys {
		r.expires[index], err = queries.ReserveLoginLimit(ctx, key[:])
		if err != nil {
			return r, unavailable()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return r, unavailable()
	}
	return r, nil
}

func (r limitReservation) release(ctx context.Context, tx pgx.Tx) error {
	queries := sqlc.New(tx)
	if err := queries.LockTransaction(ctx, limitLock); err != nil {
		return err
	}
	for index, key := range r.keys {
		// Never decrement a newer window after an old reservation expires.
		if err := queries.ReleaseLoginLimit(ctx, sqlc.ReleaseLoginLimitParams{
			Key: key[:], ExpiresAt: r.expires[index],
		}); err != nil {
			return err
		}
	}
	return nil
}
