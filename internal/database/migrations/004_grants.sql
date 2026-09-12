-- +goose Up
CREATE TABLE grants (
    user_id uuid NOT NULL REFERENCES users(id),
    connection_id uuid NOT NULL REFERENCES connections(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL REFERENCES users(id),
    PRIMARY KEY (user_id, connection_id)
);
CREATE INDEX grants_connection ON grants(connection_id);

-- An event may reference a user as its target and a connection at the same
-- time; grant events use both. Existing rows keep NULL.
ALTER TABLE auth_events ADD COLUMN connection_id uuid;

-- A username is never UUID-shaped, so a user reference is unambiguous.
ALTER TABLE users DROP CONSTRAINT users_username_check;
ALTER TABLE users ADD CONSTRAINT users_username_check CHECK (username ~ '^[a-z][a-z0-9._-]{2,63}$'
    AND username !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

ALTER TABLE auth_events DROP CONSTRAINT auth_events_action_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_action_check CHECK (action IN (
    'bootstrap', 'login', 'logout', 'revoke',
    'user.create', 'user.block', 'user.unblock', 'user.reset_password',
    'user.promote', 'user.demote', 'users.list',
    'connection.create', 'connection.update', 'connection.set_credentials',
    'connection.enable', 'connection.disable', 'connection.delete',
    'connection.check', 'connection.get', 'connections.list',
    'grant.create', 'grant.revoke', 'grants.list'
));
ALTER TABLE auth_events DROP CONSTRAINT auth_events_outcome_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_outcome_check CHECK (outcome IN (
    'success', 'invalid_argument', 'invalid_credentials', 'unauthenticated',
    'forbidden', 'user_not_found', 'rate_limited',
    'username_taken', 'last_administrator', 'self_target',
    'connection_exists', 'connection_not_found', 'connection_in_use',
    'credentials_unavailable', 'check_failed', 'connection_disabled'
));
