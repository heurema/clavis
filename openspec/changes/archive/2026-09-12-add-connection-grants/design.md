## Context

`add-connections` left a connection record, an encrypted credential store, administrator-only connection operations behind `administer` (advisory key, actor lock, recheck, guards, one event, savepoint dry run), nine bearer-only routes, an agent-first `connections` CLI group and read-only admin tables. Users are addressed by UUID only. Nothing links a user to a connection, and the `connections` read routes refuse members.

This change adds grants, member visibility and the authorization operation the provider changes will call. It reuses every pattern from the previous two changes and adds one new query family.

## Goals / Non-Goals

**Goals:**
- One authoritative "may this session use this connection now" answer, cheap enough to run on every request.
- Grants that survive renames and blocking, are idempotent for retrying agents, and are audited with both parties.
- Members discover exactly what they may use, and nothing else, through the commands they already have.
- Usernames usable wherever UUIDs are, without ambiguity.

**Non-Goals:**
- Groups, query execution, per-connection managers, expiry, bulk operations, `describe`, audit inspection.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| `administer` transaction shape, advisory key per domain, savepoint dry run, hints re-attached | archived `add-connections` design decision 3 | Retained; grants use a fifth advisory key `grantMutationLock` (`0x434c415649530005`) |
| Bearer-only JSON routes, strict decoding, `no-store`, adapter rejections once, service outcomes once | archived `add-connections` design decision 4 | Retained for `/api/admin/grants`; the two connection `GET` routes drop the administrator requirement |
| Agent-first CLI rules: one vocabulary, names or ids, `--dry-run`, hints, listing bounds | archived `add-connections` design | Retained; the "names or ids" rule is now applied to users too |
| Users addressed by UUID | user-administration "Administrator-only user operations" | Explicitly changed (owner decision 2026-09-12): UUID or username; usernames refuse the UUID shape |
| Connection name never UUID-shaped | connection-management | Retained; the same rule now covers usernames |
| Event columns: actor, target, session; allowlists as check constraints; forward migrations | local-authentication | Explicitly extended: optional `connection_id` column so grant events carry user and connection; migration `004` |
| Delete guard: disabled only, grants "later" | archived `add-connections` design decision 2 | Completed here: zero grants required, count in the hint |
| Read-only admin page tables | user-administration, connection-management | Retained; grants table added |
| Members see disabled granted connections with `enabled: false`; use refused with `CONNECTION_DISABLED` | owner decisions 2026-09-12 | Implemented here for reads; the refusal lives in the authorization operation |
| Administrators use any connection without a grant | owner decision 2026-09-12 | Implemented in the authorization operation |
| `whoami` is identity only | cli-authentication "Authoritative identity" | Explicitly extended: granted connection names |

No unresolved departure requires owner approval.

## Decisions

### 1. Contracts

`internal/auth` gains:

```go
type GrantParty struct { ID string `json:"id"`; Name string `json:"name"` }
type Grant struct {
    User       GrantParty `json:"user"`        // name is the username
    Connection GrantParty `json:"connection"`
    CreatedAt  time.Time  `json:"createdAt"`
    CreatedBy  GrantParty `json:"createdBy"`   // administrator UUID and username
}
type GrantList struct { Grants []Grant `json:"grants"`; Truncated bool `json:"truncated"` }
type GrantRequest struct { User string `json:"user"`; Connection string `json:"connection"` } // refs
type GrantMutation struct { Grant Grant `json:"grant"`; Created bool `json:"created"`; DryRun bool `json:"dryRun"` }
type GrantRevocation struct { User, Connection GrantParty; Revoked bool; DryRun bool }
type GrantFilter struct { User, Connection string; Limit int }

type Grants interface {
    ListGrants(ctx, Session, GrantFilter) (GrantList, error)
    CreateGrant(ctx, Session, GrantRequest, dryRun bool) (GrantMutation, error)
    RevokeGrant(ctx, Session, GrantRequest, dryRun bool) (GrantRevocation, error)
    AuthorizeConnection(ctx, Session, ref string) (Connection, error)
}
```

`CreatedBy` is a `GrantParty` rather than a bare UUID (slice 1 decision): the listing query already joins the granting administrator's username for the web table, and agents reading a grant should not need a second lookup to name who granted it. `Identity` gains `Connections []string` and `ConnectionsTruncated bool` (JSON `connections`, `connectionsTruncated`), filled by `whoami` only; login responses leave them empty. `ValidUserRef(v) = ValidUserID(v) || ValidUsername(v)`; `ValidUsername` additionally refuses the UUID shape from this change on (bootstrap and create use it). New code `CONNECTION_DISABLED` (409, "The connection is disabled"). New actions `grant.create`, `grant.revoke`, `grants.list`; new outcome `connection_disabled`. Paths `GrantsPath = /api/admin/grants`, `GrantRevokePath = /api/admin/grants/revoke`.

Member projection: a separate `ConnectionSummary` struct (`id`, `name`, `title`, `description`, `scope`, `provider`, `labels`, `enabled`, `lastCheck`) is returned to members, so a member response can never carry a target by accident; `Connection` is not reused with blanked fields. The connection `GET` routes return `Connection` for administrators and `ConnectionSummary` for members, decided server-side from the current role, and the CLI validates whichever shape arrives (both strict; `target` and bounds absent is the summary). The CLI text rendering omits the target and bound lines for a summary.

### 2. Schema (migration 004)

```sql
CREATE TABLE grants (
    user_id uuid NOT NULL REFERENCES users(id),
    connection_id uuid NOT NULL REFERENCES connections(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL REFERENCES users(id),
    PRIMARY KEY (user_id, connection_id)
);
CREATE INDEX grants_connection ON grants(connection_id);
ALTER TABLE auth_events ADD COLUMN connection_id uuid;
ALTER TABLE users DROP CONSTRAINT users_username_check;
ALTER TABLE users ADD CONSTRAINT users_username_check CHECK (username ~ '^[a-z][a-z0-9._-]{2,63}$'
    AND username !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
-- action and outcome constraints replaced with the widened lists
```

No cascade on delete: users are never deleted, and connection delete is guarded to zero grants, so a foreign key without cascade is the honest choice. `CheckGrantsColumns` joins the readiness column checks; `CheckAuthEventsColumns` gains the new column.

Queries: `InsertGrant` (`ON CONFLICT DO NOTHING` returning the row, plus a `FindGrant` for the existing case), `DeleteGrant :execrows`, `FindGrant`, `ListGrants` with nullable user/connection filters, `CountConnectionGrants`, `ListGrantedConnections(user, contains, excludes, keys, limit)`, `FindGrantedConnection(user, id)`, `ListGrantedConnectionNames(user, limit)`, `FindUserByUsername`. `InsertAuthEvent` gains a nullable `connection_id` parameter; the `audit` helper gains a connection argument that existing callers pass as empty.

### 3. Service

`grants.go` on `LocalAuth` implements `auth.Grants`. Mutations run through `administer` with `grantMutationLock`, resolving the user (UUID first, then `FindUserByUsername`) and the connection (existing resolver) inside the transaction with row locks on both (`LockLoginUser` and `LockConnection`), so a concurrent block or delete serializes. Create: existing row → return it with `Created: false` and no event (the body returns a sentinel outcome that `administer` treats as "no event"; add that as a documented return value `outcomeNone`); otherwise insert, event `grant.create` with target user and connection column. Revoke: delete rows; zero → `Revoked: false`, no event; one → event `grant.revoke`. Denials: `USER_NOT_FOUND`, `CONNECTION_NOT_FOUND` (both with hints), `FORBIDDEN` for members with a `grants.list`-style denial action for the attempted mutation.

`ListGrants`: administrators any filter; members forced to their own user id (the filter's user must be absent or themselves, otherwise `FORBIDDEN` with an event). Order username, connection name; limit+1 for truncation; no success event.

`AuthorizeConnection(session, ref)`: read transaction, `recheck`; administrators → the connection via the existing resolver; members → `FindGrantedConnection` (join on grants) → `CONNECTION_NOT_FOUND` when absent; then `enabled` false → `CONNECTION_DISABLED` with hint. No event on success; no event on member `CONNECTION_NOT_FOUND`. Unauthenticated → `UNAUTHENTICATED` with an event as elsewhere.

Member reads: `ListConnections` and `GetConnection` gain a role branch: administrators unchanged; members use `ListGrantedConnections`/`FindGrantedConnection` and return `ConnectionSummary`. The delete guard calls `CountConnectionGrants` and formats the count into the hint.

`whoami` identity: the server's identity handler calls `ListGrantedConnectionNames` for members (bounded, truncated flag) and leaves administrators empty.

### 4. HTTP

| Method/path | Body | Success |
|---|---|---|
| `GET /api/admin/grants?user=&connection=&limit=` | none | 200 `GrantList` (members: own only) |
| `POST /api/admin/grants[?dryRun=true]` | `{user, connection}` refs | 201 `GrantMutation` (`created: true`), 200 when it existed or on dry run |
| `POST /api/admin/grants/revoke[?dryRun=true]` | `{user, connection}` | 200 `GrantRevocation` |

Rejection mapping: `grants.list`, `grant.create`, `grant.revoke`. Connection `GET` routes: `cliSession` stays; the service decides by role. `whoami` extension is in the identity handler. `HandlerWithAuth` gains the `Grants` dependency; the `LocalAuth` value satisfies it.

### 5. CLI

`grants` group: `list [--user] [--connection] [--limit]`, `create --user --connection [--dry-run]`, `revoke --user --connection [--dry-run]`. `--user` validated by `ValidUserRef`; `users` and `sessions revoke` switch their validation to `ValidUserRef` and send the reference unchanged (server resolves). Text: grant `Grant: alice → payments-prod-reporting`, `Granted: <time> by <username>`; list one line per grant `username connection createdAt`; revoke `Revoked: true|false`. `whoami` text gains `Connections: a, b` for members. Route allowlist: `USER_NOT_FOUND` and `CONNECTION_NOT_FOUND` on grant mutations; connection `GET` validators accept the summary shape.

### 6. Web

Grants table: username, connection, granted at (UTC), granted by (username, resolved in the listing query by a join). Loaded after the connections list in `adminBrowser`; fail closed.

### 7. Smoke

After the connection section: create a member, grant the postgres connection by username, member `whoami` lists it, member `connections list`/`get` show the summary without target, member `connections check` and `grants create` → `FORBIDDEN`, `connections delete` dry run on the granted connection → `CONNECTION_IN_USE` with the count, revoke, member listing empty, revoke again `revoked: false`, delete succeeds after disable, event counts (`grant.create` 1, `grant.revoke` 1, no success events for reads), `users block --user <username>` works by name.

## Risks / Trade-offs

- [Two response shapes on the connection read routes] → the shape is decided by the server from the current role and both are strictly validated by the CLI; a member can never receive a target because the summary type has no such field.
- [Username lookups add one query] → indexed unique column; negligible.
- [Authorization runs per request in later changes] → one indexed join; no advisory key; no event.
- [Foreign keys without cascade] → intended; deletes are guarded and users are never deleted.
- [Event column addition changes the audit helper signature] → mechanical; existing callers pass empty.

## Migration Plan

1. Deploy; migration `004` applies once. Existing usernames cannot be UUID-shaped in practice (the smoke and dev data never were); if one exists the migration fails closed and the operator renames it first, which is the safe outcome.
2. Administrators and ungranted members can keep an older CLI; a member holding grants needs the new CLI because `whoami` gains fields the old strict decoder refuses. Nothing is in production, so no compatibility shim is added.
3. Rollback as before: previous binary and backup; `004` is forward-only.

## Open Questions

None.
