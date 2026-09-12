-- +goose Up
CREATE TABLE connections (
    id uuid PRIMARY KEY,
    -- A name is never UUID-shaped, so lookups by UUID or name stay unambiguous.
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9._-]{2,63}$'
        AND name !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    scope text NOT NULL DEFAULT '' CHECK (char_length(scope) <= 2000),
    provider text NOT NULL CHECK (provider IN ('postgresql', 'victoriametrics')),
    target jsonb NOT NULL CHECK (jsonb_typeof(target) = 'object'),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object'),
    secret_envelope text NOT NULL CHECK (secret_envelope <> ''),
    enabled boolean NOT NULL DEFAULT true,
    statement_timeout_ms integer NOT NULL DEFAULT 30000 CHECK (statement_timeout_ms BETWEEN 1000 AND 120000),
    max_rows integer NOT NULL DEFAULT 1000 CHECK (max_rows BETWEEN 1 AND 100000),
    max_bytes integer NOT NULL DEFAULT 1048576 CHECK (max_bytes BETWEEN 1024 AND 10485760),
    last_check_outcome text CHECK (last_check_outcome IN ('reachable', 'auth_rejected', 'unreachable', 'credentials_unavailable')),
    last_check_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((last_check_outcome IS NULL) = (last_check_at IS NULL))
);
CREATE INDEX connections_labels ON connections USING gin (labels);

-- Widen the event allowlists for connection management. Existing rows already
-- satisfy the new constraints, so this is transactional metadata only.
ALTER TABLE auth_events DROP CONSTRAINT auth_events_action_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_action_check CHECK (action IN (
    'bootstrap', 'login', 'logout', 'revoke',
    'user.create', 'user.block', 'user.unblock', 'user.reset_password',
    'user.promote', 'user.demote', 'users.list',
    'connection.create', 'connection.update', 'connection.set_credentials',
    'connection.enable', 'connection.disable', 'connection.delete',
    'connection.check', 'connections.list'
));
ALTER TABLE auth_events DROP CONSTRAINT auth_events_outcome_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_outcome_check CHECK (outcome IN (
    'success', 'invalid_argument', 'invalid_credentials', 'unauthenticated',
    'forbidden', 'user_not_found', 'rate_limited',
    'username_taken', 'last_administrator', 'self_target',
    'connection_exists', 'connection_not_found', 'connection_in_use',
    'credentials_unavailable', 'check_failed'
));
