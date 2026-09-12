package database

import (
	"context"
	"github.com/heurema/clavis/internal/secrets"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a lazy pool. An unreachable database is a readiness failure,
// not a reason to withhold liveness or prevent the server from starting.
func Open(ctx context.Context, connectionString string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, err
	}
	// Keep the platform pool small and lazy, regardless of URL options.
	config.MinConns = 0
	config.MinIdleConns = 0
	config.MaxConns = 4
	return pgxpool.NewWithConfig(ctx, config)
}

// WithKeyring attaches the credential keyring used by connection management.
// It is set once at composition time; connection operations fail closed
// while it is absent.
func (s *LocalAuth) WithKeyring(keys *secrets.Keyring) *LocalAuth {
	s.keys = keys
	return s
}
