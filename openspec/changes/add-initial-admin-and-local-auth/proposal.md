## Why

Clavis now serves a verified, self-contained setup UI, but has no persisted users or authenticated access. The next usable product slice is an installation that automation can initialize once, followed by local sign-in through the browser and CLI without granting privileges to the first website visitor.

## What Changes

- Add embedded, versioned PostgreSQL schema migrations and startup initialization that do not withhold HTTP liveness or the public setup document during database outages.
- Accept an initial administrator username and a password-file path through deployment configuration. Create the account and durable initialization marker atomically, once per platform database. Subsequent starts ignore bootstrap inputs; redeployment is not password rotation or account recovery.
- Add local password authentication, opaque server-side sessions, sign-out, expiry, current identity and administrator revocation of a user's sessions. Check the current account state and administrator role on each protected request.
- Extend the existing setup page with actual initialization states and a sign-in link. Add local sign-in and a minimal protected administrator shell; do not add browser-based account creation.
- Add CLI login, logout, current identity and session revocation with safe credential input, origin-bound local session storage and the existing structured-output conventions.
- Record minimal, secret-free authentication and session-administration events, not a general audit browser.
- **BREAKING**: readiness means the database, schema and installation are ready, not merely that PostgreSQL responds to a ping. Preserve existing success and database-outage representations while adding documented setup/initialization failures to HTML readiness and `clavis doctor`.
- Define shared contracts before parallel backend, web and CLI implementation, with one owner for shared wiring, dependency metadata and integration.

## Capabilities

### New Capabilities

- `platform-initialization`: embedded schema lifecycle, unattended bootstrap, durable one-time initialization and safe retries.
- `local-authentication`: password verification, browser sign-in, server-side sessions, protected administrator access, revocation and safe authentication events.
- `cli-authentication`: local CLI sign-in/out, current identity, protected session persistence and administrative session revocation.

### Modified Capabilities

- `project-bootstrap`: extend readiness and doctor diagnostics to distinguish incomplete initialization from database failure; extend the setup/status view without weakening its bounded retry behavior.
- `embedded-web`: preserve standalone serving and representation isolation while adding initialization fragments and authentication pages.

## Impact

- Backend: `cmd/server`, `internal/config`, `internal/database`, `internal/server` and new initialization/authentication packages and embedded SQL.
- UI: `internal/web` templates and generated Go, maintained browser assets and browser fixtures/tests.
- Client: `internal/cli`, the client entry point where needed for terminal input, and authentication transport/storage tests.
- Tooling: real-database smoke fixtures must initialize isolated installations, and documentation must distinguish one-time bootstrap inputs from ongoing credentials.
- Dependencies: retain pgx, chi, templ and urfave/cli; add pinned password-hashing and terminal-input libraries as needed. No new runtime service is required.

## Non-goals

Google/OIDC, account linking, self-registration, browser-based first-admin creation, password recovery/rotation, full user/group/role administration, connection authorization, providers and general audit inspection are later changes, not removed from MVP scope. This change does not introduce a default/shared administrator password, a mandatory bootstrap command, a deployment-specific manifest, or a second web server.
