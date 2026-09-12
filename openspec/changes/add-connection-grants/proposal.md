## Why

Connections exist and administrators can manage them, but no member can see or be allowed to use one, and nothing in the platform can yet answer "may this user use this connection now". Every provider change needs that answer before it forwards a single query, and the readiness criteria on connection isolation and access revocation cannot be tested without grants (PRD ACCESS-03, ACCESS-04, ACCESS-05, CLI-02, CLI-06, 7.7).

## What Changes

- Add grants: an administrator grants a connection to a user and revokes it; grants are idempotent, carry no expiry, reference UUIDs so renames never move access, survive blocking, and are audited as `grant.create` and `grant.revoke` with the granting administrator recorded.
- Add one authorization function, "may this session use this connection now", that rechecks the session, requires a grant for members (administrators pass), refuses disabled connections with `CONNECTION_DISABLED`, and hides ungranted connections from members as `CONNECTION_NOT_FOUND`. Later provider changes call it before forwarding anything.
- Let members list and get the connections granted to them through the existing `connections list` and `connections get`, with a reduced projection: identity, descriptive text, provider, labels, enabled flag and last check outcome, never target settings, bounds or secrets.
- Address users by UUID or username in every command (`grants` and the existing `users` and `sessions revoke` commands), additively; refuse UUID-shaped usernames at creation so the lookup stays unambiguous.
- Add the `grants` CLI group (`list`, `create`, `revoke`) with the shared conventions: dry run, hints, one envelope; results carry both identifiers and names.
- Extend `whoami` with the names of the caller's granted connections, so an agent's first call already says what it may use.
- Extend the connection delete guard to require zero grants, with the remaining count in the hint.
- Add JSON routes under `/api/admin/grants`, a forward migration `004` (grants table, a connection column on audit events, widened allowlists, the username shape guard), a read-only grants table on the admin page, and smoke coverage of grant, member visibility, revocation and the guard.

## Capabilities

### New Capabilities

- `connection-grants`: grant records and lifecycle, member visibility of granted connections, the per-request authorization check, grant routes and the read-only browser table.

### Modified Capabilities

- `connection-management`: listing and getting connections are no longer administrator-only; members receive the reduced projection of their granted connections; the delete guard counts grants.
- `user-administration`: targets are addressed by UUID or username; usernames may not be UUID-shaped.
- `cli-authentication`: `--user` accepts a UUID or username everywhere; `whoami` reports granted connection names; the `grants` command group.
- `local-authentication`: the event allowlist gains the grant actions and the `connection_disabled` outcome; events gain an optional connection identifier column so grant events carry both the user and the connection.

## Impact

- Backend: `internal/auth` (grant DTOs, `Grants` and `Authorizer` interfaces, codes, actions), `internal/database` (migration `004`, grant and authorization queries, `grants.go`, user reference resolution, audit helper gaining a connection identifier), `internal/server` (grant routes, member scope on connection reads, `whoami` extension).
- UI: `internal/web` grants table and regenerated templ.
- Client: `internal/cli` grants commands, user reference validation, `whoami` rendering.
- Tooling/docs: `scripts/smoke.mjs`, README, PRD section 12 status.
- Dependencies: none.

## Owner decisions (2026-09-12 grilling session)

- Users addressable by username as well as UUID everywhere; usernames are unique and never UUID-shaped.
- `grants` as its own command group; no bulk revoke.
- Idempotent create and revoke without duplicate events; results include ids and names; grants record who granted.
- Members see `lastCheck` but never target settings; ungranted connections are absent and `get` says not found; disabled ones are listed as disabled.
- Administrators use any connection without a grant; grants to administrators are allowed.
- Successful authorization and member `get` denials record no event; denied administration attempts do.
- Grants survive blocking; renames keep grants; delete requires zero grants.
- `whoami` gains granted connection names.
- One change in four slices.

## Non-goals

Groups, query execution, per-connection manager permissions, grant expiry, bulk operations, `clavis describe`, audit inspection commands.
