-- name: LockTransaction :exec
SELECT pg_advisory_xact_lock(sqlc.arg(lock_id)::bigint);

-- name: CheckUsersColumns :exec
SELECT id, username, password_hash, role, disabled, created_at, updated_at FROM users LIMIT 0;

-- name: CheckSessionsColumns :exec
SELECT id, token_digest, user_id, kind, created_at, expires_at, revoked_at FROM sessions LIMIT 0;

-- name: CheckAuthEventsColumns :exec
SELECT id, actor_id, target_id, session_id, action, outcome, created_at FROM auth_events LIMIT 0;

-- name: CheckLoginLimitsColumns :exec
SELECT key, failures, expires_at FROM login_limits LIMIT 0;

-- name: InstallationInitialized :one
SELECT EXISTS(SELECT 1 FROM installation WHERE singleton AND initialized_at IS NOT NULL);

-- name: BootstrapState :one
SELECT EXISTS(SELECT 1 FROM installation WHERE singleton AND initialized_at IS NOT NULL) AS initialized,
    EXISTS(SELECT 1 FROM users) AS has_users;

-- name: CreateInitialAdministrator :exec
INSERT INTO users (id, username, password_hash, role)
VALUES (sqlc.arg(id)::text::uuid, sqlc.arg(username), sqlc.arg(password_hash), 'admin');

-- name: MarkInstallationInitialized :exec
INSERT INTO installation (singleton, initialized_at) VALUES (true, clock_timestamp());
