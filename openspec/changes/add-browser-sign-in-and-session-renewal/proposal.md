## Why

Beta users hit two problems that remain after profiles shipped in `v0.1.0-rc.6`. First, every session dies eight hours after sign-in, even while it is in use, so an agent working through the evening is cut off mid-task and the person types a password again. Second, signing in from the CLI means typing a password into the terminal. The owner wants one place where a password is ever entered: the sign-in page in the browser. This is change 3 of `docs/plans/2026-09-16-cli-sign-in-profiles-release.md`, simplified on September 17, 2026 by the owner after a design review for an installation with a handful of users. It is the last change in that plan and ships as `v0.1.0`.

## What Changes

- **Session renewal.** Every session, browser or CLI, has an idle expiry and an absolute cap. A request made with a valid session pushes the idle expiry forward, but never past the cap. Revocation, blocking and role changes still take effect on the next request.
- **BREAKING**: `CLAVIS_SESSION_TTL` (8h, 5m to 24h) is replaced by `CLAVIS_SESSION_IDLE_TIMEOUT` (default `168h`) and `CLAVIS_SESSION_MAX_LIFETIME` (default `720h`), with `5m ≤ idle ≤ max ≤ 2160h`. The chart value `server.sessionTTL` is replaced by `server.sessionIdleTimeout` and `server.sessionMaxLifetime`. A leftover `server.sessionTTL` fails chart rendering through the existing strict schema. A leftover environment variable is ignored, and the release note says so.
- **BREAKING**: the migration revokes every existing session, so everyone signs in once more after the upgrade.
- Expired sessions are deleted in bounded batches whenever a session is issued, so thirty-day sessions do not grow the table without limit.
- **Browser sign-in for the CLI.** `clavis login` listens on `127.0.0.1` and opens `/authorize` in the browser. The person signs in there if needed and clicks Approve. The server redirects to the CLI's loopback callback with a one-time code, and the CLI exchanges the code together with its PKCE verifier for an ordinary CLI session. `--no-browser` prints the link without trying to open a browser. The link is always printed, and the CLI waits up to five minutes.
- A one-time code exists only after an explicit Approve click. It is stored as a digest, bound to the approving user and the PKCE challenge, lives two minutes and can be used once.
- **BREAKING**: sign-in happens only in the browser. `login` loses `--username`, `--password-stdin` and the terminal password prompt. `users create` and `users reset-password` keep both ways of reading the password they set.
- **BREAKING**: the server removes the JSON password route `POST /api/auth/login`. The browser form at `/login` is the only place a password is checked, with the same login limits as today. CLIs older than this release can no longer sign in and must be upgraded.
- The skill tells agents never to sign in. On `UNAUTHENTICATED` the agent asks the person to run `clavis login`.
- The smoke, image smoke and kind scripts sign in by running `clavis login --no-browser`, reading the link from stderr, and doing the browser's part with `fetch`: the `/login` form and Approve. The real sign-in flow is therefore exercised end to end.
- The browser login page accepts a return target only when it has the exact shape of an authorize link. A member who approves a CLI therefore never lands on the administrator-only `/admin/users`.
- `login` and `whoami` return `expiresAt` (the absolute cap, as before) and a new `idleExpiresAt`. Text output prints both.

## Departures from the plan (owner, 2026-09-17)

- **No start route and no pending row.** The plan created a pending authorization row before the browser opened. Here, opening the authorize link creates nothing, and a row is written only when Approve is clicked. This removes a route, the state where a row has no user yet, and the cap and cleanup that unauthenticated writes would have needed.
- **No local cap check in the CLI.** The plan had the CLI report `UNAUTHENTICATED` before any network call once the cached cap passed. The server's answer on the next request is authoritative, and a check against the laptop clock would bring back clock-drift failures.
- **`--no-browser` is added.** It covers a browser that fails to open, or a person who wants to paste the link into a browser of their choice on the same machine.
- **Browser-only sign-in.** The plan kept `--password-stdin` for agents and CI. Here, agents use the session the person created, scripts drive the browser flow, and the terminal prompt, `--password-stdin` on `login` and the JSON password route are all removed. A remote shell without a local browser uses `--no-browser` with `ssh -L`, and device flow stays deferred.
- **No terminal requirement.** `login` runs without a terminal so scripts can drive it. Agents are kept from signing in by the skill, and an unattended `login` ends after five minutes.
- **No Deny button.** Nothing exists until Approve is clicked, so closing the tab is the denial.
- **No startup check for the removed variable.** The chart already rejects the old value, and the release note covers the environment variable.
- **The token route has no rate limit.** The code carries 256 bits and is consumed on its first presentation.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-authentication`: "Local credential verification" checks passwords only through the browser form. "Expiring server-side sessions" replaces the fixed lifetime with idle and absolute expiry, renewal on use and bounded cleanup. "Protected browser authentication" allows renewal on GET and adds the shaped return target on `/login`. "Explicit authentication transports" drops JSON password login. A new requirement, "CLI authorization through the browser", covers the authorize page, approval, the one-time code and its exchange.
- `cli-authentication`: "Safe local CLI sign-in" becomes browser-only sign-in with `--no-browser`. "Authoritative identity and explicit sign-out" and "Authentication preserves CLI output conventions" report both expiries. "Administrative user commands" states its own password input rules instead of pointing at `login`. "Server resolution" rewrites its `login` scenarios.
- `agent-skill`: "Embedded skill content" teaches that sessions renew on use, that the agent never signs in, and that `UNAUTHENTICATED` means asking the person to run `clavis login`.

`deployment-packaging` has no delta: its chart requirement already says every exposed setting maps to its documented `CLAVIS_*` variable, which the renamed session values still satisfy.

## Impact

- **Database:** migration `008` revokes all sessions and adds `sessions.max_expires_at` with a check that `expires_at ≤ max_expires_at`, an index on `sessions(expires_at)`, and the `cli_authorizations` table with its expiry index. New and changed queries in `internal/database/queries/auth.sql` and `limits.sql`, with sqlc regenerated.
- **Server:** `internal/database/auth.go` (renewal, cleanup, code issuance and exchange, the `NewLocalAuth` signature), `internal/auth/contracts.go` (the session duration constants, `LoginPath` replaced by the token path, the `IdleExpiresAt` field, the service methods), `internal/config/config.go`, `internal/server/auth.go` (authorize page, approve POST, token route, `next` on login, `loginJSON` removed), `internal/web` (authorize and approved templates, the login model's return target).
- **CLI:** `internal/cli/auth_commands.go` (browser login flow, flags, validation), `auth_transport.go` (the login path special case), a new loopback callback and browser opener, `result.go` (idle expiry in text), and every test that signs in with a password.
- **Chart:** `values.yaml`, `values.schema.json`, `_helpers.tpl`, `deployment.yaml`, `ci/full.yaml`, the chart README.
- **Docs:** `.env.example`, `README.md`, `internal/skill/clavis/SKILL.md` with its drift test, `docs/PRD.md` (the browser sign-in decision row and status text).
- **Scripts:** `scripts/smoke.mjs`, `smoke-image.mjs` and `verify-kind.mjs` sign in through a shared helper that drives `clavis login --no-browser` and the browser form with `fetch`.
- **Users:** everyone signs in once more with an upgraded CLI. An older CLI cannot sign in against the new server because `POST /api/auth/login` is gone. Its commands with an existing session would keep working, but the migration revokes every session.
- No new Go dependencies. The browser is opened with `open` on macOS and `xdg-open` on Linux.
