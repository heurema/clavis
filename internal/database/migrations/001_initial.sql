-- +goose Up
CREATE TABLE installation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    initialized_at timestamptz NOT NULL
);
CREATE TABLE users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE CHECK (username ~ '^[a-z][a-z0-9._-]{2,63}$'),
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'member')),
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('browser', 'cli')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE TABLE auth_events (
    id uuid PRIMARY KEY,
    actor_id uuid,
    target_id uuid,
    session_id uuid,
    action text NOT NULL CHECK (action IN ('bootstrap', 'login', 'logout', 'revoke')),
    outcome text NOT NULL CHECK (outcome IN ('success', 'invalid_argument', 'invalid_credentials', 'unauthenticated', 'forbidden', 'user_not_found', 'rate_limited')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE login_limits (
    key bytea PRIMARY KEY CHECK (octet_length(key) = 32),
    failures integer NOT NULL CHECK (failures >= 0),
    expires_at timestamptz NOT NULL
);
CREATE INDEX login_limits_expiry ON login_limits(expires_at);
