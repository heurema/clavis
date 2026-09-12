## Why

Clavis can initialize one personal administrator and sign that account in through the browser and CLI, but there is no production path to add a second account, block a compromised or departed user, replace a lost local password or change who holds the administrator role. Every later MVP capability (connection grants, groups, provider access, connection isolation in the readiness criteria) needs real member accounts and a current administrator role, so this is the smallest slice that unblocks the rest of the roadmap (PRD AUTH-05, AUTH-07, ACCESS-01, ACCESS-07, CLI-06, 7.7, 7.8).

## What Changes

- Add an administrator-only user-administration service beside the existing authentication service: list users, create a local user (member by default), block and unblock a user, reset a user's local password, and grant or revoke the administrator role. Every mutation rechecks the actor's current session and role inside one transaction, as revocation does today.
- Blocking a user and resetting a password revoke all of that user's existing browser and CLI sessions in the same transaction. Unblocking does not restore sessions.
- Refuse any block or demotion that would leave the installation without an enabled administrator, using a serialized check so concurrent administrators cannot race past it. Bootstrap stays closed, as platform-initialization already requires.
- Extend the safe authentication event allowlist with user-administration actions and outcomes through a new forward Goose migration. Successful mutations commit with their events; denied and failed attempts are recorded when storage is available. Events never contain passwords, hashes or submitted unknown text.
- Mount documented JSON administration endpoints under the existing `/api/admin/users` prefix for CLI bearer sessions only, with the same origin, body-size, content-type, deadline and no-cookie rules as the current authentication routes.
- Add CLI `users` commands (`list`, `create`, `block`, `unblock`, `reset-password`, `set-role`) that reuse the stored session, the password input rules of `login` (hidden prompt or `--password-stdin`), and the schemaVersion 1 result envelope. Passwords never appear in arguments, environment or output.
- Extend the protected administrator page with a read-only user list (username, role, status, creation time). No browser mutation forms are added in this change.
- Replace fixture-seeded member accounts in the real-database smoke run with accounts created through the CLI, and cover block, reset, promotion, demotion and the last-administrator guard end to end.

## Capabilities

### New Capabilities

- `user-administration`: administrator-only listing, creation, blocking/unblocking, password reset and role assignment for local users, including transactional session revocation, the last-administrator guard, HTTP contracts and the read-only browser user list.

### Modified Capabilities

- `local-authentication`: the secret-free event requirement gains the user-administration action/outcome allowlist and a bounded event-schema migration; the protected browser requirement's administrator page now shows the current user list and fails closed during an outage.
- `cli-authentication`: the CLI gains administrative user commands with the same credential-input, origin, transport and output conventions as the existing authentication commands.

## Impact

- Backend: `internal/auth` (administration contracts, error codes, event allowlist), `internal/database` (migration `002`, new sqlc queries and generated methods, administration service), `internal/server` (JSON handlers, admin page data).
- UI: `internal/web` admin model/template and regenerated templ Go.
- Client: `internal/cli` user commands, text rendering and subprocess tests.
- Tooling/docs: `scripts/smoke.mjs`, README command table and CLI section, PRD implementation-status sentence, `.env.example` unchanged.
- Dependencies: none added. Password hashing, session storage and generated-query tooling are reused.

## Inherited requirements and assumptions

Inherited and retained: username/password rules, Argon2id hashing and the two-hash concurrency budget, five-second operation deadline, opaque revocable sessions, current-role checks on every mutation, admin/member roles only, secret-free events, sqlc-only application persistence and immutable applied migrations.

Owner decisions confirmed on 2026-09-11 during exploration:

- The MVP uses local username/password identity only. Google and OIDC sign-in move to a later stage, so the user table keeps its required local password hash and no credential split is introduced here.
- There is no self-service password change in the MVP. Administrators set the initial password and perform every reset; a member keeps the password an administrator chose. Documentation states this as the MVP behavior, not as pending work.
- The administrator supplies the initial password and the reset password through hidden terminal input or `--password-stdin`, exactly like `login`. The server does not generate or print temporary passwords, because results must never carry passwords.

Assumptions recorded for review (change them here before implementation if wrong):

- Targets are identified by user UUID, consistent with `sessions revoke --user`. `users list` exposes IDs. Username lookup flags are a later convenience, not a contract.
- Users are never deleted in this change; blocking is the retirement mechanism. Groups, connection grants, Google/OIDC, account recovery and audit browsing remain out of scope.
