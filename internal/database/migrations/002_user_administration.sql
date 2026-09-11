-- +goose Up
-- Widen the event allowlists for user administration. Existing rows already
-- satisfy the new constraints, so this is transactional metadata only.
ALTER TABLE auth_events DROP CONSTRAINT auth_events_action_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_action_check CHECK (action IN (
    'bootstrap', 'login', 'logout', 'revoke',
    'user.create', 'user.block', 'user.unblock', 'user.reset_password',
    'user.promote', 'user.demote', 'users.list'
));
ALTER TABLE auth_events DROP CONSTRAINT auth_events_outcome_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_outcome_check CHECK (outcome IN (
    'success', 'invalid_argument', 'invalid_credentials', 'unauthenticated',
    'forbidden', 'user_not_found', 'rate_limited',
    'username_taken', 'last_administrator'
));
