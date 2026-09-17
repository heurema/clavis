-- name: FindLoginUser :one
SELECT id::text, username, role, password_hash, disabled
FROM users WHERE username = sqlc.arg(username);

-- name: LockLoginUser :one
SELECT username, role, password_hash, disabled
FROM users WHERE id = sqlc.arg(id)::text::uuid FOR UPDATE;

-- name: CreateSession :one
-- The idle expiry starts at the idle timeout and the absolute expiry at the
-- maximum lifetime; configuration keeps the first no later than the second.
INSERT INTO sessions (id, token_digest, user_id, kind, expires_at, max_expires_at)
SELECT sqlc.arg(id)::text::uuid, sqlc.arg(token_digest), sqlc.arg(user_id)::text::uuid, sqlc.arg(kind),
    issued + sqlc.arg(idle_seconds)::double precision * interval '1 second',
    issued + sqlc.arg(max_seconds)::double precision * interval '1 second'
FROM (SELECT clock_timestamp() AS issued) issuance
RETURNING expires_at AS idle_expires_at, max_expires_at;

-- name: RenewSession :one
-- Renewal writes only when less than half the idle window remains and the
-- session is not yet at its cap, and only to a session AuthenticateSession
-- would accept: a revoked, expired or disabled session is never touched, and
-- the absolute expiry is never written. A renewal waiting on a row that a
-- revocation holds re-evaluates revoked_at once the lock is released.
UPDATE sessions s
SET expires_at = LEAST(clock_timestamp() + sqlc.arg(idle_seconds)::double precision * interval '1 second', s.max_expires_at)
FROM users u
WHERE u.id = s.user_id AND s.token_digest = sqlc.arg(token_digest) AND s.kind = sqlc.arg(kind)
    AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() AND NOT u.disabled
    AND s.expires_at < clock_timestamp() + (sqlc.arg(idle_seconds)::double precision / 2) * interval '1 second'
    AND s.expires_at < s.max_expires_at
RETURNING s.id::text AS session_id, s.kind, u.id::text AS user_id,
    u.username, u.role, s.expires_at AS idle_expires_at, s.max_expires_at;

-- name: AuthenticateSession :one
SELECT s.id::text AS session_id, s.kind, u.id::text AS user_id,
    u.username, u.role, s.expires_at AS idle_expires_at, s.max_expires_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_digest = sqlc.arg(token_digest) AND s.kind = sqlc.arg(kind)
    AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() AND NOT u.disabled;

-- name: CleanupSessions :exec
-- Indexed, bounded cleanup of the oldest sessions whose idle expiry passed.
-- Revoked sessions age out through the same predicate.
DELETE FROM sessions WHERE id IN (
    SELECT id FROM sessions WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at LIMIT 100
);

-- name: RecheckSession :one
SELECT s.id::text AS session_id, s.kind, u.id::text AS user_id,
    u.username, u.role, s.expires_at AS idle_expires_at, s.max_expires_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.id = sqlc.arg(session_id)::text::uuid
    AND s.user_id = sqlc.arg(user_id)::text::uuid AND s.kind = sqlc.arg(kind)
    AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() AND NOT u.disabled
FOR UPDATE OF s;

-- name: LockMutationUsers :exec
-- Consistent ordering serializes issuance/revocation without opposing-admin
-- deadlocks. A target addressed by username is locked by this same statement,
-- so resolving a name never splits acquisition into two ordered waits.
SELECT id FROM users
WHERE id = sqlc.arg(actor_id)::text::uuid
    OR id = NULLIF(sqlc.arg(target_id)::text, '')::uuid
    OR username = NULLIF(sqlc.arg(target_username)::text, '')
ORDER BY id FOR UPDATE;

-- name: UserExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE id = sqlc.arg(id)::text::uuid);

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = clock_timestamp()
WHERE user_id = sqlc.arg(user_id)::text::uuid AND revoked_at IS NULL;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = clock_timestamp() WHERE id = sqlc.arg(id)::text::uuid;
