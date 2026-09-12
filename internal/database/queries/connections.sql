-- name: InsertConnection :one
INSERT INTO connections (id, name, title, description, scope, provider, target, labels,
    secret_envelope, statement_timeout_ms, max_rows, max_bytes)
VALUES (
    sqlc.arg(id)::text::uuid, sqlc.arg(name), sqlc.arg(title), sqlc.arg(description),
    sqlc.arg(scope), sqlc.arg(provider), sqlc.arg(target)::jsonb, sqlc.arg(labels)::jsonb,
    sqlc.arg(secret_envelope), sqlc.arg(statement_timeout_ms), sqlc.arg(max_rows), sqlc.arg(max_bytes)
)
RETURNING *;

-- name: FindConnectionByID :one
SELECT * FROM connections WHERE id = sqlc.arg(id)::text::uuid;

-- name: FindConnectionByName :one
SELECT * FROM connections WHERE name = sqlc.arg(name);

-- name: LockConnection :one
SELECT * FROM connections WHERE id = sqlc.arg(id)::text::uuid FOR UPDATE;

-- name: ConnectionNameExists :one
SELECT EXISTS(SELECT 1 FROM connections WHERE name = sqlc.arg(name));

-- name: ListConnections :many
-- Selector terms compile to containment (equals), negated containment
-- (not-equals) and key existence; empty or NULL inputs match every row. The
-- caller requests one row beyond its bound to detect truncation.
SELECT * FROM connections
WHERE labels @> COALESCE(sqlc.arg(contains)::jsonb, '{}'::jsonb)
    AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(COALESCE(sqlc.arg(excludes)::jsonb, '[]'::jsonb)) AS excluded
        WHERE labels @> excluded
    )
    AND labels ?& COALESCE(sqlc.arg(keys)::text[], '{}'::text[])
ORDER BY name LIMIT sqlc.arg(limit_rows)::integer;

-- name: UpdateConnection :one
UPDATE connections SET
    name = COALESCE(sqlc.narg(name)::text, name),
    title = COALESCE(sqlc.narg(title)::text, title),
    description = COALESCE(sqlc.narg(description)::text, description),
    scope = COALESCE(sqlc.narg(scope)::text, scope),
    target = COALESCE(sqlc.narg(target)::jsonb, target),
    labels = COALESCE(sqlc.narg(labels)::jsonb, labels),
    statement_timeout_ms = COALESCE(sqlc.narg(statement_timeout_ms)::integer, statement_timeout_ms),
    max_rows = COALESCE(sqlc.narg(max_rows)::integer, max_rows),
    max_bytes = COALESCE(sqlc.narg(max_bytes)::integer, max_bytes),
    updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid
RETURNING *;

-- name: SetConnectionSecret :one
-- Replacing credentials invalidates the last check.
UPDATE connections SET secret_envelope = sqlc.arg(secret_envelope),
    last_check_outcome = NULL, last_check_at = NULL, updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid
RETURNING *;

-- name: SetConnectionEnabled :one
UPDATE connections SET enabled = sqlc.arg(enabled), updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid
RETURNING *;

-- name: SetConnectionCheck :one
UPDATE connections SET last_check_outcome = sqlc.arg(outcome)::text, last_check_at = clock_timestamp()
WHERE id = sqlc.arg(id)::text::uuid
RETURNING *;

-- name: DeleteConnection :execrows
DELETE FROM connections WHERE id = sqlc.arg(id)::text::uuid AND NOT enabled;

-- name: CheckConnectionsColumns :exec
SELECT id, name, title, description, scope, provider, target, labels, secret_envelope, enabled,
    statement_timeout_ms, max_rows, max_bytes, last_check_outcome, last_check_at, created_at, updated_at
FROM connections LIMIT 0;
