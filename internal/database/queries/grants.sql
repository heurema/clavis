-- name: InsertGrant :one
-- Exactly one recipient is non-NULL; the table's check enforces that and the
-- two partial unique indexes make a repeated grant of either kind a no-op:
-- no row is returned and the caller reads the existing one.
INSERT INTO grants (user_id, group_id, connection_id, created_by)
VALUES (sqlc.narg(user_id)::text::uuid, sqlc.narg(group_id)::text::uuid,
    sqlc.arg(connection_id)::text::uuid, sqlc.arg(created_by)::text::uuid)
ON CONFLICT DO NOTHING
RETURNING user_id, group_id, connection_id, created_at, created_by;

-- name: FindGrant :one
-- The recipient is matched on both columns at once: IS NOT DISTINCT FROM makes
-- the NULL side of the pair part of the key rather than an unmatchable value.
SELECT g.user_id, u.username, g.group_id, gr.name AS group_name,
    g.connection_id, c.name AS connection_name,
    g.created_at, g.created_by, cb.username AS created_by_username
FROM grants g
    LEFT JOIN users u ON u.id = g.user_id
    LEFT JOIN groups gr ON gr.id = g.group_id
    JOIN connections c ON c.id = g.connection_id
    JOIN users cb ON cb.id = g.created_by
WHERE g.connection_id = sqlc.arg(connection_id)::text::uuid
    AND g.user_id IS NOT DISTINCT FROM sqlc.narg(user_id)::text::uuid
    AND g.group_id IS NOT DISTINCT FROM sqlc.narg(group_id)::text::uuid;

-- name: ListGrants :many
-- NULL filters match every row; the caller requests one row beyond its bound.
-- User grants order before group grants, then by recipient name and connection.
SELECT g.user_id, u.username, g.group_id, gr.name AS group_name,
    g.connection_id, c.name AS connection_name,
    g.created_at, g.created_by, cb.username AS created_by_username
FROM grants g
    LEFT JOIN users u ON u.id = g.user_id
    LEFT JOIN groups gr ON gr.id = g.group_id
    JOIN connections c ON c.id = g.connection_id
    JOIN users cb ON cb.id = g.created_by
WHERE (sqlc.narg(user_id)::text IS NULL OR g.user_id = sqlc.narg(user_id)::text::uuid)
    AND (sqlc.narg(group_id)::text IS NULL OR g.group_id = sqlc.narg(group_id)::text::uuid)
    AND (sqlc.narg(connection_id)::text IS NULL OR g.connection_id = sqlc.narg(connection_id)::text::uuid)
ORDER BY (g.user_id IS NULL), COALESCE(u.username, gr.name), c.name
LIMIT sqlc.arg(limit_rows)::integer;

-- name: DeleteGrant :execrows
DELETE FROM grants
WHERE connection_id = sqlc.arg(connection_id)::text::uuid
    AND user_id IS NOT DISTINCT FROM sqlc.narg(user_id)::text::uuid
    AND group_id IS NOT DISTINCT FROM sqlc.narg(group_id)::text::uuid;

-- name: CountConnectionGrants :one
-- Both recipient kinds live in this table, so the connection delete guard
-- counts them together without knowing that groups exist.
SELECT count(*) FROM grants WHERE connection_id = sqlc.arg(connection_id)::text::uuid;

-- name: ListGrantedConnections :many
-- The member listing: effectively accessible connections only, same selector
-- semantics as the administrator listing, one row beyond the bound. EXISTS
-- yields each connection once however many paths reach it, so neither this
-- query nor its caller deduplicates.
SELECT c.* FROM connections c
WHERE EXISTS (
        SELECT 1 FROM grants g
        WHERE g.connection_id = c.id
            AND (g.user_id = sqlc.arg(user_id)::text::uuid
                OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = sqlc.arg(user_id)::text::uuid))
    )
    AND c.labels @> COALESCE(sqlc.arg(contains)::jsonb, '{}'::jsonb)
    AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(COALESCE(sqlc.arg(excludes)::jsonb, '[]'::jsonb)) AS excluded
        WHERE c.labels @> excluded
    )
    AND c.labels ?& COALESCE(sqlc.arg(keys)::text[], '{}'::text[])
ORDER BY c.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: FindGrantedConnectionByID :one
SELECT c.* FROM connections c
WHERE c.id = sqlc.arg(id)::text::uuid
    AND EXISTS (
        SELECT 1 FROM grants g
        WHERE g.connection_id = c.id
            AND (g.user_id = sqlc.arg(user_id)::text::uuid
                OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = sqlc.arg(user_id)::text::uuid))
    );

-- name: FindGrantedConnectionByName :one
SELECT c.* FROM connections c
WHERE c.name = sqlc.arg(name)
    AND EXISTS (
        SELECT 1 FROM grants g
        WHERE g.connection_id = c.id
            AND (g.user_id = sqlc.arg(user_id)::text::uuid
                OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = sqlc.arg(user_id)::text::uuid))
    );

-- name: ListGrantedConnectionNames :many
SELECT c.name FROM connections c
WHERE EXISTS (
    SELECT 1 FROM grants g
    WHERE g.connection_id = c.id
        AND (g.user_id = sqlc.arg(user_id)::text::uuid
            OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = sqlc.arg(user_id)::text::uuid))
)
ORDER BY c.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: ListEffectiveAccess :many
-- One row per configured path: a direct grant carries no group, a grant the
-- subject inherits carries the group it came through. A connection reached
-- twice is two entries, which is the provenance an administrator asked for.
SELECT c.id AS connection_id, c.name AS connection_name,
    gr.id AS group_id, gr.name AS group_name, g.created_at
FROM grants g
    JOIN connections c ON c.id = g.connection_id
    LEFT JOIN groups gr ON gr.id = g.group_id
WHERE (g.user_id = sqlc.arg(user_id)::text::uuid
        OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = sqlc.arg(user_id)::text::uuid))
    AND (sqlc.narg(connection_id)::text IS NULL OR c.id = sqlc.narg(connection_id)::text::uuid)
ORDER BY c.name, (g.group_id IS NOT NULL), gr.name
LIMIT sqlc.arg(limit_rows)::integer;

-- name: FindUserIDByUsername :one
SELECT id FROM users WHERE username = sqlc.arg(username);

-- name: CheckGrantsColumns :exec
SELECT user_id, group_id, connection_id, created_at, created_by FROM grants LIMIT 0;
