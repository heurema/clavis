-- name: InsertGrant :one
-- A repeated grant is a no-op: no row is returned and the caller reads the
-- existing one.
INSERT INTO grants (user_id, connection_id, created_by)
VALUES (sqlc.arg(user_id)::text::uuid, sqlc.arg(connection_id)::text::uuid, sqlc.arg(created_by)::text::uuid)
ON CONFLICT DO NOTHING
RETURNING user_id::text, connection_id::text, created_at, created_by::text;

-- name: FindGrant :one
SELECT g.user_id::text AS user_id, u.username, g.connection_id::text AS connection_id, c.name AS connection_name,
    g.created_at, g.created_by::text AS created_by, cb.username AS created_by_username
FROM grants g
    JOIN users u ON u.id = g.user_id
    JOIN connections c ON c.id = g.connection_id
    JOIN users cb ON cb.id = g.created_by
WHERE g.user_id = sqlc.arg(user_id)::text::uuid AND g.connection_id = sqlc.arg(connection_id)::text::uuid;

-- name: ListGrants :many
-- NULL filters match every row; the caller requests one row beyond its bound.
SELECT g.user_id::text AS user_id, u.username, g.connection_id::text AS connection_id, c.name AS connection_name,
    g.created_at, g.created_by::text AS created_by, cb.username AS created_by_username
FROM grants g
    JOIN users u ON u.id = g.user_id
    JOIN connections c ON c.id = g.connection_id
    JOIN users cb ON cb.id = g.created_by
WHERE (sqlc.narg(user_id)::text IS NULL OR g.user_id = sqlc.narg(user_id)::text::uuid)
    AND (sqlc.narg(connection_id)::text IS NULL OR g.connection_id = sqlc.narg(connection_id)::text::uuid)
ORDER BY u.username, c.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: DeleteGrant :execrows
DELETE FROM grants WHERE user_id = sqlc.arg(user_id)::text::uuid AND connection_id = sqlc.arg(connection_id)::text::uuid;

-- name: CountConnectionGrants :one
SELECT count(*) FROM grants WHERE connection_id = sqlc.arg(connection_id)::text::uuid;

-- name: ListGrantedConnections :many
-- The member listing: granted connections only, same selector semantics as
-- the administrator listing, one row beyond the bound for truncation.
SELECT c.* FROM connections c JOIN grants g ON g.connection_id = c.id
WHERE g.user_id = sqlc.arg(user_id)::text::uuid
    AND c.labels @> COALESCE(sqlc.arg(contains)::jsonb, '{}'::jsonb)
    AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(COALESCE(sqlc.arg(excludes)::jsonb, '[]'::jsonb)) AS excluded
        WHERE c.labels @> excluded
    )
    AND c.labels ?& COALESCE(sqlc.arg(keys)::text[], '{}'::text[])
ORDER BY c.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: FindGrantedConnectionByID :one
SELECT c.* FROM connections c JOIN grants g ON g.connection_id = c.id
WHERE g.user_id = sqlc.arg(user_id)::text::uuid AND c.id = sqlc.arg(id)::text::uuid;

-- name: FindGrantedConnectionByName :one
SELECT c.* FROM connections c JOIN grants g ON g.connection_id = c.id
WHERE g.user_id = sqlc.arg(user_id)::text::uuid AND c.name = sqlc.arg(name);

-- name: ListGrantedConnectionNames :many
SELECT c.name FROM connections c JOIN grants g ON g.connection_id = c.id
WHERE g.user_id = sqlc.arg(user_id)::text::uuid
ORDER BY c.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: FindUserIDByUsername :one
SELECT id::text FROM users WHERE username = sqlc.arg(username);

-- name: CheckGrantsColumns :exec
SELECT user_id, connection_id, created_at, created_by FROM grants LIMIT 0;
