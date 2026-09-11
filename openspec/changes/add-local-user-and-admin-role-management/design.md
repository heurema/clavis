## Context

The archived local-authentication change left one transport-neutral `auth.Service` (login, authenticate, logout, revoke-all), a `database.LocalAuth` implementation that owns transactions, row locking and audit writes, an `authHTTP` adapter in `internal/server` with JSON bearer routes and browser form routes, an `internal/web` admin template that only shows the signed-in username, and CLI commands built on `runAuth`, the per-origin session cache and `authTransport`. Users have `role` (`admin`/`member`) and `disabled`, but the only production writer of user rows is bootstrap. Tests and smoke seed members with fixture SQL.

`auth_events` uses check constraints as its action/outcome allowlist, so extending it needs a forward Goose migration. Applied migrations are immutable. Application SQL must go through sqlc-generated methods; the AST boundary check rejects handwritten application queries.

This change adds the management operations without changing the frozen authentication contracts.

## Goals / Non-Goals

**Goals:**
- Give administrators a production path to create, block, unblock, reset and change the role of local users through the CLI and JSON API.
- Keep every mutation transactional, current-role checked, serialized against session issuance and audited with secret-free events.
- Make it impossible to remove the last enabled administrator by accident or by racing administrators.
- Show the current user list on the protected page without adding browser mutation surfaces.
- Replace fixture SQL for members in smoke with the real CLI.

**Non-Goals:**
- Self-service password change, account recovery, deletion of users, groups, connection grants, Google/OIDC, audit browsing, pagination beyond a documented bound, browser forms for management, username-based targeting.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Username `[a-z][a-z0-9._-]{2,63}`, password 15-1,024 UTF-8 bytes without NUL/CR/LF, no normalization | local-authentication "Local credential verification"; archived design §3 | Retained; create and reset reuse `auth.ValidUsername`/`auth.ValidPassword` |
| Argon2id `m=65536,t=3,p=1`, versioned encoded hash, two-hash concurrency budget, non-cancelable hash cannot issue after cancellation | archived design §5 | Retained; create/reset derive through the same `derive` path and budget; a busy budget returns `RATE_LIMITED` with `Retry-After` |
| Five-second operation deadline covering body, readiness, locks, queries, events | local-authentication "Explicit authentication transports" | Retained for all administration routes via the existing `operation` middleware and service-level timeout |
| Current session/role re-read inside the mutation transaction; cached role never authorizes | local-authentication "Expiring server-side sessions" | Retained; administration reuses `LockMutationUsers` + `recheck` |
| Session issuance and revoke-all serialize on the target user row | archived design §5 | Retained; block and reset take the same row lock before revoking |
| Events: allowlisted action/outcome, UUIDs only, commit with mutation, adapter records pre-service rejections once | local-authentication "Secret-free authentication events" | Explicitly extended: new actions/outcomes, new migration; adapter rejection path extended to the new routes |
| Bootstrap closed after initialization regardless of remaining administrators | platform-initialization "Bootstrap is not credential reconciliation" | Retained and complemented by the last-administrator guard; the guard is prevention, bootstrap remains closed |
| JSON routes: bearer only, no cookies, configured-origin check, 8 KiB body, strict JSON, `no-store`, no redirects | archived design §6 | Retained for the new routes |
| CLI: no passwords in args/env, hidden prompt or `--password-stdin`, schemaVersion 1, exit 0/1/2, per-origin cache | cli-authentication | Retained; `users create`/`reset-password` reuse the login input path |
| sqlc-only application persistence, Goose-only migrations, immutable applied migrations | platform-initialization; project-bootstrap | Retained; migration `002` and new named queries |
| `auth.Service` and `AuthViews` are frozen coordinator-owned contracts | archived design §8 | Explicitly changed: a separate `auth.Administration` interface is added rather than widening `Service`; `AuthViews.Admin` keeps its signature while `web.AdminModel` gains fields |
| Admin page shows identity and sign-out only, "no placeholder management screens" | archived tasks 4.2 | Explicitly changed: a read-only user list is added; still no management forms |
| Members seeded through fixture SQL, "production mutation paths for users/roles are not exposed yet" | archived design §2 | Superseded by this change; smoke fixture SQL for members is removed |

No unresolved departure requires owner approval beyond the assumptions listed in the proposal.

## Decisions

### 1. A separate administration contract beside the frozen authentication service

Add to `internal/auth`:

```go
type UserRecord struct {
    ID        string    `json:"id"`
    Username  string    `json:"username"`
    Role      Role      `json:"role"`
    Disabled  bool      `json:"disabled"`
    CreatedAt time.Time `json:"createdAt"`
}
type UserList struct { Users []UserRecord `json:"users"`; Truncated bool `json:"truncated"` }
type CreateUserRequest struct { Username string `json:"username"`; Password Secret `json:"password"` }
type ResetPasswordRequest struct { Password Secret `json:"password"` }
type SetRoleRequest struct { Role Role `json:"role"` }
type UserMutation struct { User UserRecord `json:"user"`; SessionsRevoked bool `json:"sessionsRevoked"` }

type Administration interface {
    ListUsers(context.Context, Session) (UserList, error)
    CreateUser(context.Context, Session, CreateUserRequest) (UserRecord, error)
    SetUserDisabled(context.Context, Session, string, bool) (UserMutation, error)
    ResetPassword(context.Context, Session, string, Secret) (UserMutation, error)
    SetRole(context.Context, Session, string, Role) (UserMutation, error)
}
```

`database.LocalAuth` implements `Administration`; `HandlerWithAuth` receives it as an additional dependency and fails construction when it is nil, exactly as it does for the recorder. Keeping `auth.Service` unchanged preserves every existing fixture and contract test. `Secret` on request DTOs keeps passwords out of formatted output; DTOs with `Secret` fields never enter CLI results.

New error codes in `auth.LookupFailure`: `USERNAME_TAKEN` (409, "Username is already in use"), `LAST_ADMINISTRATOR` (409, "At least one enabled administrator must remain") and `SELF_TARGET` (409, "Administrators cannot block or demote their own account"). Existing `USER_NOT_FOUND`, `FORBIDDEN`, `UNAUTHENTICATED`, `INVALID_ARGUMENT`, `RATE_LIMITED` and `SERVICE_UNAVAILABLE` are reused. The CLI transport's allowlist accepts the two new codes.

Alternative: widening `auth.Service`. Rejected because it forces every fake service in server/CLI tests to change and blurs the sign-in boundary with management.

### 2. One mutation transaction shape, serialized by row locks plus one advisory key

Every mutation follows `mutate` in `database/auth.go`:

1. `context.WithTimeout(auth.OperationTimeout)`; readiness check; `Begin`.
2. `LockTransaction(adminMutationLock)` with a new fixed advisory key distinct from the bootstrap and throttle keys. This serializes all block/unblock/role/reset/create operations across instances so the last-administrator count cannot race. Listing and login do not take it.
3. `LockMutationUsers(actor, target)` in id order (existing query), then `recheck(session)`; unauthenticated → deny event `unauthenticated`; role ≠ admin → deny event `forbidden`.
4. Target checks: `FindUser` → `user_not_found` (one round trip also yields the role and disabled state the guards need). For block and demote, in this order: target equals the actor → `self_target` deny event; then `CountEnabledAdministrators` would reach zero after the change → `last_administrator` deny event. Idempotent no-op states still succeed and record `success`. This is the GitLab group owner model (owner decision of 2026-09-11): administrators are peers, the last enabled one is protected, and nobody can remove themself. No root tier exists.
5. Mutation via generated queries: `InsertUser`, `SetUserDisabled`, `SetUserRole`, `SetUserPasswordHash` (each updates `updated_at`), plus `RevokeUserSessions(target)` for block and reset.
6. `audit(actor, target, actorSession, action, "success")`; `Commit`.

Create does step 2 as well (cheap, keeps one code path), checks `UsernameExists` for a clean `username_taken` denial without fetching a hash, and additionally maps a `23505` unique violation on insert to `USERNAME_TAKEN` for the unlocked race with bootstrap fixtures. Password hashing for create and reset happens before `Begin` (like login) so the lock is not held during Argon2 work; the hash is then written under the lock. Deny events for create carry no target (the user does not exist); success events carry the new UUID as target.

`ListUsers` runs `recheck` inside a read transaction (no advisory lock), records `users.list`/`forbidden` on denial via `deny`, and otherwise runs `ListUsers LIMIT 1001` and sets `Truncated` when 1,001 rows return, dropping the extra row. It records no success event. Order follows the database collation of `username`; byte order would need `COLLATE "C"` and its own index, which is not required by the spec.

Alternative: `SELECT ... FOR UPDATE` on all admin rows instead of an advisory key. Rejected: the row set changes under promotion, making the guard porous.

### 3. Migration `002_user_administration.sql`

```sql
-- +goose Up
ALTER TABLE auth_events DROP CONSTRAINT auth_events_action_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_action_check CHECK (action IN (
  'bootstrap','login','logout','revoke',
  'user.create','user.block','user.unblock','user.reset_password','user.promote','user.demote','users.list'));
ALTER TABLE auth_events DROP CONSTRAINT auth_events_outcome_check;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_outcome_check CHECK (outcome IN (
  'success','invalid_argument','invalid_credentials','unauthenticated','forbidden','user_not_found','rate_limited',
  'username_taken','last_administrator','self_target'));
CREATE INDEX users_username_order ON users (username);
```

Constraint names are PostgreSQL's defaults for the inline checks in `001`; the migration names the replacements explicitly so `003` need not guess. Existing rows satisfy the wider constraint, so the migration is metadata-only and transactional. No down migration (forward-only policy). `internal/database/migration_manifest_test.go` and the checksum ledger cover it; `CheckAuthEventsColumns` is unchanged since columns do not change. The `users_username_order` index supports ordered listing; the existing unique index already covers it in practice, so the index is optional and dropped from scope if the planner uses the unique index (verify with `EXPLAIN` during implementation and delete the line rather than keep a redundant index).

`auth.Event.Valid` and the recorder's allowlist gain the new actions; `auditRejection` maps the new paths to `user.*` actions by route pattern rather than by string prefix on `URL.Path`, using `chi.RouteContext(r.Context()).RoutePattern()`.

### 4. HTTP contract

| Method/path | Body | Success | Errors |
|---|---|---|---|
| `GET /api/admin/users` | none | 200 `{users:[...],truncated}` | 401, 403, 503 |
| `POST /api/admin/users` | `{username,password}` | 201 `{id,username,role,disabled,createdAt}` | 400, 401, 403, 409 `USERNAME_TAKEN`, 429, 503 |
| `POST /api/admin/users/{userID}/block` | empty | 200 `{user,sessionsRevoked:true}` | 400, 401, 403, 404, 409 `LAST_ADMINISTRATOR`, 503 |
| `POST /api/admin/users/{userID}/unblock` | empty | 200 `{user,sessionsRevoked:false}` | 400, 401, 403, 404, 503 |
| `POST /api/admin/users/{userID}/password` | `{password}` | 200 `{user,sessionsRevoked:true}` | 400, 401, 403, 404, 429, 503 |
| `POST /api/admin/users/{userID}/role` | `{role}` | 200 `{user,sessionsRevoked:false}` | 400, 401, 403, 404, 409 `LAST_ADMINISTRATOR`, 503 |

All routes are mounted through `a.operation`, use `cliSession` (bearer only, origin check, no cookies), `emptyBody` or a `decodeJSON` generalization of `decodeLogin` (8 KiB limit, `DisallowUnknownFields`, single document, strict content type), and `serviceOwnsEvent` before invoking the service. Path constants join the existing ones in `internal/auth/contracts.go` so CLI and server share them. `RevokePath` is untouched.

### 5. Browser user list

`web.AdminModel` gains `Users []auth.UserRecord` and `Truncated bool`. `adminBrowser` calls `ListUsers` after the role check; an error maps through `AdminOutcome` to the existing safe 503 error document. The template renders a table with username, role badge, "Enabled"/"Blocked" and UTC creation time, a truncation notice, and keeps the sign-out form. No htmx, no forms, no JavaScript. Rendering tests cover admin with users, empty list, truncation and a member 403; the HTTP test asserts 503 when the fake administration service fails.

Because listing during `GET /admin` is a read on a validated session, it does not record a success event, matching the API.

### 6. CLI

`users` becomes a command group beside `sessions` in `authCommands`, sharing `flags()` and `runAuth`. `runAuth` gains operations `users.list`, `users.create`, `users.block`, `users.unblock`, `users.reset-password`, `users.set-role`. Validation before any I/O: UUID via `auth.ValidUserID`, role ∈ {admin, member}, username via `auth.ValidUsername`; password input reuses the `login` branch (hidden prompt or `--password-stdin`, same `TIMEOUT`/`INVALID_ARGUMENT` results). Commands require a cached session; absent cache → `UNAUTHENTICATED` exit 1 without a request, as `sessions revoke` does.

`authTransport.request` gains a documented 201 success status for create. A full listing of 1,000 maximum-length usernames is about 210 KiB and cannot fit the general 64 KiB `MaxResponseBody`, so `GET UsersPath` alone reads up to `auth.MaxListingBody` (256 KiB); every other route keeps the general bound. Server-side, the listing handler in slice 3 must not exceed that ceiling. Text rendering adds `auth.UserRecord`, `auth.UserList` and `auth.UserMutation` cases. Subprocess tests cover prompt/stdout separation for `users create`, exit codes and no password in output; unit tests use the existing fake HTTP server.

### 7. Smoke and fixtures

`scripts/smoke.mjs` replaces the `fixture-member`, `fixture-disable`, `fixture-demote` and `fixture-restore-role` SQL statements with `users create`, `users block`, `users unblock`, `users set-role` and `users reset-password` through the copied binary, asserting sign-in outcomes, `FORBIDDEN` for the member, `LAST_ADMINISTRATOR` for demoting the bootstrap admin while alone, successful demotion after promoting the member, and the event counts by action. The `fixture-expire` statement stays because expiry has no product API. Database tests keep fixture SQL for fault injection and independent assertions only.

## Risks / Trade-offs

- [Advisory lock serializes all administration] → Administration is rare and bounded to five seconds; login is unaffected because it does not take the key.
- [Argon2 during create/reset shares the two-slot budget with login] → Callers receive `RATE_LIMITED` with `Retry-After` rather than unbounded work; document that bulk creation should be sequential.
- [An administrator resets a password and the member cannot change it] → Recorded in the proposal as an explicit follow-up; the reset revokes sessions so a leaked interim password has bounded use.
- [Dropping and recreating check constraints assumes default constraint names] → The migration test applies `001` then `002` on a fresh database and asserts the new allowlist; a mismatch fails migration safely without partial application.
- [Listing bound of 1,000] → `truncated` is explicit; pagination is a later change if a pilot exceeds it.
- [Concurrent mutual demotion] → Both queue on the advisory key; the loser re-reads its already-removed role and is denied `FORBIDDEN` (or `UNAUTHENTICATED` after a block). Self-block and self-demotion are refused outright with `SELF_TARGET`, so a single administrator cannot lock themself out.
- [Changed handwritten size will exceed the 400-line/6-file rescoping signal] → The tasks split the work into slices with independent review; the proposal keeps coupled behavior (mutation, audit, guard) together deliberately.

## Migration Plan

1. Deploy the new server binary; on start it applies `002` once under the shared migration lock. Readiness stays 503 `INITIALIZING` until it commits. No data rewrite.
2. Older CLI binaries keep working for login/whoami/logout/revoke; only the new `users` commands need the new CLI.
3. Rollback: stop the new release and restore a tested compatible binary and database backup, as documented for the previous change. The previous binary's `InsertAuthEvent` writes only old actions, so it runs against the wider constraint, but the operator procedure remains backup-based, not down migration.

## Open Questions

None blocking. The proposal's recorded assumptions (administrator-supplied passwords, UUID targeting, no self-service change) are the review points.
