-- +goose Up
-- A group name shares the username grammar and its UUID exclusion, so a group
-- reference that is a UUID can never be a name. Names live in their own
-- namespace: a user and a group may share one.
CREATE TABLE groups (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9._-]{2,63}$'
        AND name !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Membership alone confers nothing, so it follows the group into the grave;
-- users are never deleted, so their side needs no cascade.
CREATE TABLE group_members (
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL REFERENCES users(id),
    PRIMARY KEY (group_id, user_id)
);

-- Effective access asks "which groups is this user in" on every request.
CREATE INDEX group_members_user ON group_members(user_id, group_id);

-- One grants table with exactly one recipient per row: one listing, one
-- delete-guard count and one insert path for both kinds. Existing rows all
-- name a user, so they satisfy the check unchanged.
ALTER TABLE grants DROP CONSTRAINT grants_pkey;
ALTER TABLE grants ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE grants ADD COLUMN group_id uuid REFERENCES groups(id);
ALTER TABLE grants ADD CONSTRAINT grants_one_recipient CHECK ((user_id IS NULL) <> (group_id IS NULL));
CREATE UNIQUE INDEX grants_user_connection ON grants(user_id, connection_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX grants_group_connection ON grants(group_id, connection_id) WHERE group_id IS NOT NULL;
