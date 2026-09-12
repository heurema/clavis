-- name: FindLoginUser :one
SELECT id::text, username, role, password_hash, disabled
FROM users WHERE username = sqlc.arg(username);

-- name: LockLoginUser :one
SELECT username, role, password_hash, disabled
FROM users WHERE id = sqlc.arg(id)::text::uuid FOR UPDATE;

-- name: CreateSession :one
INSERT INTO sessions (id, token_digest, user_id, kind, expires_at)
VALUES (
    sqlc.arg(id)::text::uuid,
    sqlc.arg(token_digest),
    sqlc.arg(user_id)::text::uuid,
    sqlc.arg(kind),
    clock_timestamp() + sqlc.arg(ttl_seconds)::double precision * interval '1 second'
)
RETURNING expires_at;

-- name: AuthenticateSession :one
SELECT s.id::text AS session_id, s.kind, u.id::text AS user_id,
    u.username, u.role, s.expires_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_digest = sqlc.arg(token_digest) AND s.kind = sqlc.arg(kind)
    AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() AND NOT u.disabled;

-- name: RecheckSession :one
SELECT s.id::text AS session_id, s.kind, u.id::text AS user_id,
    u.username, u.role, s.expires_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.id = sqlc.arg(session_id)::text::uuid
    AND s.user_id = sqlc.arg(user_id)::text::uuid AND s.kind = sqlc.arg(kind)
    AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() AND NOT u.disabled
FOR UPDATE OF s;

-- name: LockMutationUsers :exec
-- Consistent ordering serializes issuance/revocation without opposing-admin deadlocks.
SELECT id FROM users
WHERE id = sqlc.arg(actor_id)::text::uuid
    OR id = NULLIF(sqlc.arg(target_id)::text, '')::uuid
ORDER BY id FOR UPDATE;

-- name: UserExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE id = sqlc.arg(id)::text::uuid);

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = clock_timestamp()
WHERE user_id = sqlc.arg(user_id)::text::uuid AND revoked_at IS NULL;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = clock_timestamp() WHERE id = sqlc.arg(id)::text::uuid;

-- name: InsertAuthEvent :exec
INSERT INTO auth_events (id, actor_id, target_id, session_id, connection_id, action, outcome)
VALUES (
    sqlc.arg(id)::text::uuid,
    NULLIF(sqlc.arg(actor_id)::text, '')::uuid,
    NULLIF(sqlc.arg(target_id)::text, '')::uuid,
    NULLIF(sqlc.arg(session_id)::text, '')::uuid,
    NULLIF(sqlc.arg(connection_id)::text, '')::uuid,
    sqlc.arg(action),
    sqlc.arg(outcome)
);
