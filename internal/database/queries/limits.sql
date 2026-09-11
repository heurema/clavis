-- name: CleanupLoginLimits :exec
-- Indexed, bounded cleanup; the caller holds the shared limit lock.
DELETE FROM login_limits WHERE key IN (
    SELECT key FROM login_limits WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at LIMIT 100
);

-- name: CountLoginLimits :one
SELECT count(*) FROM login_limits;

-- name: GetLoginLimit :one
SELECT failures, expires_at > clock_timestamp() AS active
FROM login_limits WHERE key = sqlc.arg(key);

-- name: ReserveLoginLimit :one
INSERT INTO login_limits (key, failures, expires_at)
VALUES (sqlc.arg(key), 1, clock_timestamp() + interval '5 minutes')
ON CONFLICT (key) DO UPDATE SET
    failures = CASE WHEN login_limits.expires_at <= clock_timestamp() THEN 1 ELSE login_limits.failures + 1 END,
    expires_at = CASE WHEN login_limits.expires_at <= clock_timestamp() THEN clock_timestamp() + interval '5 minutes' ELSE login_limits.expires_at END
RETURNING expires_at;

-- name: ReleaseLoginLimit :exec
-- Never decrement a newer window after an old reservation expires.
UPDATE login_limits SET failures = GREATEST(failures - 1, 0)
WHERE key = sqlc.arg(key) AND expires_at = sqlc.arg(expires_at);
