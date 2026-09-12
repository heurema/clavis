-- name: InsertUser :one
INSERT INTO users (id, username, password_hash, role)
VALUES (sqlc.arg(id)::text::uuid, sqlc.arg(username), sqlc.arg(password_hash), 'member')
RETURNING id::text, username, role, disabled, created_at;

-- name: UsernameExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE username = sqlc.arg(username));

-- name: FindUser :one
SELECT id::text, username, role, disabled, created_at
FROM users WHERE id = sqlc.arg(id)::text::uuid;

-- name: LockUser :one
-- The same projection under the row lock a mutation's target needs, so a
-- concurrent block, demotion or revocation serializes behind it.
SELECT id::text, username, role, disabled, created_at
FROM users WHERE id = sqlc.arg(id)::text::uuid FOR UPDATE;

-- name: ListUsers :many
-- The caller requests one row beyond its bound to detect truncation.
SELECT id::text, username, role, disabled, created_at
FROM users ORDER BY username LIMIT sqlc.arg(limit_rows)::integer;

-- name: CountEnabledAdministrators :one
SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled;

-- name: SetUserDisabled :one
UPDATE users SET disabled = sqlc.arg(disabled), updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid
RETURNING id::text, username, role, disabled, created_at;

-- name: SetUserRole :one
UPDATE users SET role = sqlc.arg(role), updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid
RETURNING id::text, username, role, disabled, created_at;

-- name: SetUserPasswordHash :exec
UPDATE users SET password_hash = sqlc.arg(password_hash), updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid;
