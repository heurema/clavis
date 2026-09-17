-- +goose Up
-- Sessions issued under the fixed lifetime carry no absolute cap, so every
-- one of them is revoked and everybody signs in once more after the upgrade.
UPDATE sessions SET revoked_at = clock_timestamp() WHERE revoked_at IS NULL;

-- expires_at stays the idle expiry and max_expires_at is the absolute cap.
-- The idle expiry never passes the cap, so every existing predicate on
-- expires_at alone stays correct.
ALTER TABLE sessions ADD COLUMN max_expires_at timestamptz;
UPDATE sessions SET max_expires_at = expires_at;
ALTER TABLE sessions ALTER COLUMN max_expires_at SET NOT NULL;
ALTER TABLE sessions ADD CONSTRAINT sessions_idle_within_cap CHECK (expires_at <= max_expires_at);

-- Bounded cleanup deletes the oldest expired sessions first.
CREATE INDEX sessions_expires_at ON sessions(expires_at);

-- A CLI authorization exists only after an explicit browser approval. Only the
-- digest of its one-time code is stored, bound to the approving user and the
-- CLI's PKCE challenge.
CREATE TABLE cli_authorizations (
    code_digest bytea PRIMARY KEY CHECK (octet_length(code_digest) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge bytea NOT NULL CHECK (octet_length(challenge) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX cli_authorizations_expiry ON cli_authorizations(expires_at);
