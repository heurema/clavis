-- name: InsertGroup :one
INSERT INTO groups (id, name, description)
VALUES (sqlc.arg(id)::text::uuid, sqlc.arg(name), sqlc.arg(description))
RETURNING *;

-- name: FindGroupByID :one
SELECT * FROM groups WHERE id = sqlc.arg(id)::text::uuid;

-- name: FindGroupByName :one
SELECT * FROM groups WHERE name = sqlc.arg(name);

-- name: LockGroup :one
SELECT * FROM groups WHERE id = sqlc.arg(id)::text::uuid FOR UPDATE;

-- name: GroupNameExists :one
SELECT EXISTS(SELECT 1 FROM groups WHERE name = sqlc.arg(name));

-- name: ListGroups :many
-- The counts an administrator needs before deleting a group come from the
-- listing itself; the caller requests one row beyond its bound.
SELECT g.*,
    (SELECT count(*) FROM group_members m WHERE m.group_id = g.id) AS members,
    (SELECT count(*) FROM grants r WHERE r.group_id = g.id) AS grants
FROM groups g ORDER BY g.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: UpdateGroup :one
-- Absent fields keep their stored value; updated_at moves only when a supplied
-- field differs, so a no-op update leaves the record untouched.
UPDATE groups SET
    name = COALESCE(sqlc.narg(name)::text, name),
    description = COALESCE(sqlc.narg(description)::text, description),
    updated_at = CASE
        WHEN COALESCE(sqlc.narg(name)::text, name) IS DISTINCT FROM name
            OR COALESCE(sqlc.narg(description)::text, description) IS DISTINCT FROM description
        THEN clock_timestamp() ELSE updated_at END
WHERE id = sqlc.arg(id)::text::uuid
RETURNING *;

-- name: DeleteGroup :execrows
DELETE FROM groups WHERE id = sqlc.arg(id)::text::uuid;

-- name: CountGroupMembers :one
SELECT count(*) FROM group_members WHERE group_id = sqlc.arg(group_id)::text::uuid;

-- name: CountGroupGrants :one
SELECT count(*) FROM grants WHERE group_id = sqlc.arg(group_id)::text::uuid;

-- name: InsertGroupMember :one
-- A repeated membership is a no-op: no row is returned and the caller reads
-- the existing one.
INSERT INTO group_members (group_id, user_id, created_by)
VALUES (sqlc.arg(group_id)::text::uuid, sqlc.arg(user_id)::text::uuid, sqlc.arg(created_by)::text::uuid)
ON CONFLICT DO NOTHING
RETURNING group_id, user_id, created_at, created_by;

-- name: FindGroupMember :one
SELECT m.group_id, g.name AS group_name, m.user_id, u.username,
    m.created_at, m.created_by, cb.username AS created_by_username
FROM group_members m
    JOIN groups g ON g.id = m.group_id
    JOIN users u ON u.id = m.user_id
    JOIN users cb ON cb.id = m.created_by
WHERE m.group_id = sqlc.arg(group_id)::text::uuid AND m.user_id = sqlc.arg(user_id)::text::uuid;

-- name: DeleteGroupMember :execrows
DELETE FROM group_members
WHERE group_id = sqlc.arg(group_id)::text::uuid AND user_id = sqlc.arg(user_id)::text::uuid;

-- name: ListGroupMembers :many
-- The member listing is the safe user record plus how the membership came
-- about, ordered by username, one row beyond the bound.
SELECT u.id, u.username, u.role, u.disabled, u.created_at,
    m.created_at AS added_at, m.created_by AS added_by, ab.username AS added_by_username
FROM group_members m
    JOIN users u ON u.id = m.user_id
    JOIN users ab ON ab.id = m.created_by
WHERE m.group_id = sqlc.arg(group_id)::text::uuid
ORDER BY u.username LIMIT sqlc.arg(limit_rows)::integer;

-- name: ListGroupNames :many
-- The identity question "which groups am I in", bounded like every listing.
SELECT g.name FROM groups g JOIN group_members m ON m.group_id = g.id
WHERE m.user_id = sqlc.arg(user_id)::text::uuid
ORDER BY g.name LIMIT sqlc.arg(limit_rows)::integer;

-- name: CheckGroupsColumns :exec
SELECT id, name, description, created_at, updated_at FROM groups LIMIT 0;

-- name: CheckGroupMembersColumns :exec
SELECT group_id, user_id, created_at, created_by FROM group_members LIMIT 0;
