## Context

A session today is one `sessions` row with a single `expires_at`, set at issuance to the current time plus `CLAVIS_SESSION_TTL` (8h by default, 5m to 24h, checked in `internal/config/config.go:96` and again in `NewLocalAuth`, `internal/database/auth.go:28`). `AuthenticateSession` and `RecheckSession` (`internal/database/queries/auth.sql:20-34`) only read the session, so nothing ever extends it. The browser cookie expires with the session (`internal/server/auth.go:250`). The CLI stores the `auth.LoginResponse` next to the origin (`internal/cli/auth_commands.go:17`), and `profiles list` shows its `expiresAt` as "Stored session".

CLI sign-in takes a password from a hidden terminal prompt or `--password-stdin` (`readPassword`, `auth_commands.go:131`) and posts it to `POST /api/auth/login` (`loginJSON`, `auth.go:507`). The smoke, image smoke and kind scripts sign in the same way with `--password-stdin`. Browser sign-in posts a same-origin form to `/login` and always redirects to `/admin/users` (`loginBrowser`, `auth.go:721`), which answers 403 to members (`adminPage`, `auth.go:826`). Login limits (`internal/database/limits.go:23`) use a locked transaction, a bounded cleanup of 100 expired rows and a row cap.

The installation has a handful of beta users, breaking changes are allowed, and the owner asked for the simplest design that keeps the security properties already in place.

## Goals / Non-Goals

**Goals:**
- A session that is in use does not expire, up to a hard cap.
- A person signs the CLI in by clicking Approve in a browser where they are already signed in.
- A password is entered in exactly one place, the browser sign-in form.
- Revocation, blocking and role changes keep taking effect on the next request.
- No new Go dependency, no background goroutine, no new rate-limit table.

**Non-Goals:**
- Device flow or sign-in from a remote shell without a local browser. `ssh -L` covers that for now.
- Refresh tokens, token rotation on renewal, per-kind lifetimes.
- A member landing page. A member who signs in at `/login` without a return target still reaches the 403 at `/admin/users`. That behaviour exists today and is left as is.
- Windows.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| One policy for browser and CLI sessions: idle expiry and absolute cap, renewed on use | Plan, "One session policy"; PRD §12 September 16 table | Retained |
| Defaults of seven days idle and thirty days cap, both configurable | Plan, "One session policy" | Retained |
| Renewal is one conditional update, only when less than half the idle window remains, extending to the lesser of the idle window and the cap | Plan, "One session policy" | Retained, with an added guard that skips sessions already at their cap |
| Revocation takes effect immediately, so refresh tokens add nothing | Plan, "Loopback sign-in"; `2026-09-11-add-initial-admin-and-local-auth` design §5 | Retained |
| The cookie and the CLI cache carry only the absolute cap; idle expiry stays server-side | Plan, "One session policy" | Changed: the CLI cache also keeps `idleExpiresAt` as the server returned it, unused |
| The CLI reports `UNAUTHENTICATED` locally once the cached cap has passed | Plan, "One session policy" | Changed (owner, 2026-09-17): dropped |
| Bounded cleanup of expired sessions and an index on `expires_at` | Plan, "One session policy" | Retained |
| Loopback callback on `127.0.0.1`, PKCE, explicit Approve click, one-time code stored as a digest, redirect built from the integer port only | Plan, "Loopback sign-in" | Retained |
| A start route inserts a pending authorization row before the browser opens | Plan, "Loopback sign-in" step 2 | Changed (owner, 2026-09-17): the row is created on Approve |
| The login page accepts a return target only in the literal shape of the authorize page, never a free URL | Plan, "Loopback sign-in" step 3; auth design §6 "No arbitrary return URL" | Retained |
| The token route consumes the row in one delete-returning statement, re-reads the user under the login row lock and issues a CLI session | Plan, "Loopback sign-in" step 5 | Retained |
| `--password-stdin` remains for agents and CI | Plan, "Loopback sign-in" | Changed (owner, 2026-09-17): removed from `login`; agents use the person's session and scripts drive the browser flow |
| Device flow deferred | Plan, "Loopback sign-in" | Retained |
| Interactive password prompt for `login` | `cli-authentication` "Safe local CLI sign-in" | Changed (owner, 2026-09-17): removed |
| JSON password login `POST /api/auth/login` | `2026-09-11-add-initial-admin-and-local-auth` design §6 | Changed (owner, 2026-09-17): removed |
| `users create` and `users reset-password` read the password by prompt or `--password-stdin` | `cli-authentication` "Administrative user commands" | Retained |
| `--no-browser` | Not in the plan | Added (owner, 2026-09-17) |
| GET requests never mutate sessions | `local-authentication` "Protected browser authentication" | Changed: a GET may renew a valid session's idle expiry |
| Ships as v0.1.0 or a further candidate | Plan, "Change 3" | Resolved: `v0.1.0` |
| Existing sessions at upgrade | Not in the plan | Added (owner, 2026-09-17): the migration revokes them all |

## Decisions

### 1. Two columns, one invariant

Keep `expires_at` as the idle expiry and add `max_expires_at timestamptz NOT NULL` with `CHECK (expires_at <= max_expires_at)`. Because the idle expiry never exceeds the cap, every existing predicate `s.expires_at > clock_timestamp()` stays correct unchanged, and cleanup needs only one predicate. `CreateSession` takes the two durations and sets `expires_at = now + idle` and `max_expires_at = now + max`. `auth.Identity.ExpiresAt` becomes the cap, so the cookie, the CLI cache and `profiles list` keep their meaning, and `IdleExpiresAt` is added beside it.

Alternative: a `last_used_at` column with the idle expiry computed in every query. It spreads the arithmetic into every predicate and makes cleanup harder to index.

### 2. Renewal inside `Authenticate`

`Authenticate` first runs a `RenewSession` update:

```sql
UPDATE sessions s
SET expires_at = LEAST(clock_timestamp() + @idle * interval '1 second', s.max_expires_at)
FROM users u
WHERE u.id = s.user_id AND s.token_digest = @digest AND s.kind = @kind
  AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() AND NOT u.disabled
  AND s.expires_at < clock_timestamp() + (@idle / 2) * interval '1 second'
  AND s.expires_at < s.max_expires_at
RETURNING ...same columns as AuthenticateSession...
```

When it returns no row, the unchanged `AuthenticateSession` select runs. The steady state is one read per request and one write per session per half idle window, whatever the agent's request rate. Under READ COMMITTED, an update waiting on a row that `RevokeUserSessions` is changing re-evaluates `revoked_at IS NULL` after the lock is released and skips the row, so renewal cannot bring a revoked session back. The guard `expires_at < max_expires_at` stops a capped session from being rewritten on every request in its last half window. `RecheckSession ... FOR UPDATE` and `recheck()` keep their predicates and their lock and only report the second expiry as well: every mutation already passed `Authenticate` moments earlier, so nothing renews inside the locked transaction.

Alternative: renew on every request. It writes once per request, which an agent loop turns into constant row churn for no benefit.

### 3. Settings

`CLAVIS_SESSION_IDLE_TIMEOUT` (`168h`) and `CLAVIS_SESSION_MAX_LIFETIME` (`720h`), validated as `5m ≤ idle ≤ max ≤ 2160h`. A bad idle value, or idle above max, names the idle variable; a bad max value names the max variable. `NewLocalAuth` takes both durations and repeats the check with constants in `internal/auth/contracts.go` that replace `DefaultSessionTTL`, `MinSessionTTL` and `MaxSessionTTL`. The chart exposes `server.sessionIdleTimeout` and `server.sessionMaxLifetime`, and `_helpers.tpl` checks the same rule with `clavis.durationSeconds`. `values.schema.json` already sets `additionalProperties: false` on `server`, so a leftover `sessionTTL` refuses to render. The server does not look for the removed `CLAVIS_SESSION_TTL`; the release note tells operators to remove it.

Alternative: fail at startup when the old variable is set. It adds a check that lives forever for a one-time upgrade of a handful of installations.

### 4. Cleanup where sessions are issued

`CleanupSessions` (`DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 100)`) and `CleanupCLIAuthorizations` with the same shape. Sessions are cleaned in `reserve()` next to `CleanupLoginLimits` (every password sign-in, all of which now come through the browser form) and in the token exchange transaction. Authorizations are cleaned in the approve transaction and the token exchange. Revoked sessions age out through the same predicate because their `expires_at` still passes. There is no ticker and no cap on the sessions table: sessions are created only after a successful authentication, so no anonymous caller can grow it.

### 5. No start route: the row is created on Approve

The CLI opens `GET /authorize?port=P&challenge=C&state=S`. The GET validates the three values and renders either the login document with the link as its return target or the authorize document. It writes nothing. The authorize document holds a same-origin form that posts the same three values as hidden fields to `POST /authorize`. The POST runs the browser mutation checks (`originAllowed(r, true)`, form content type), authenticates the cookie, and in one transaction deletes a bounded batch of expired authorizations and inserts:

```sql
CREATE TABLE cli_authorizations (
    code_digest bytea PRIMARY KEY CHECK (octet_length(code_digest) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge bytea NOT NULL CHECK (octet_length(challenge) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX cli_authorizations_expiry ON cli_authorizations(expires_at);
```

`challenge` stores the 32 decoded bytes of the base64url value. The port is not stored: the 303 `Location` is built from the parsed integer port and two values already validated as base64url, encoded through `url.Values`. The authorize document sets `frame-ancestors 'none'` like every authentication document, so Approve cannot be clickjacked. There is no Deny button: closing the tab leaves nothing behind.

Ports below 1024 are refused because an unprivileged CLI never binds them. The document shows the port so a person who did not start a sign-in can notice.

Alternative: the plan's start route. It needs an unauthenticated write with a cap and cleanup, a row without a user, and an id indirection in the link. None of that adds protection: an attacker who can make a victim open a link with the attacker's challenge still needs the victim's Approve click and the attacker's own loopback listener on the victim's machine to receive the code.

### 6. Return target on `/login`

`web.LoginModel` gains a `Next` value, rendered as a hidden field only when it is a valid authorization link. `loginBrowser` parses the posted `next` as a relative URL with path exactly `/authorize` and the three parameters valid, and on success redirects to a link rebuilt from the parsed values. Anything else redirects to `/admin/users` as today. The rebuild means the server never echoes submitted text into a `Location` header.

### 7. Token exchange

`POST /api/auth/token` takes over the preconditions `loginJSON` enforces today, before that handler is deleted: JSON content type, 8 KiB body, strict decoding, no cookie or Authorization header. In one transaction:

1. `DELETE FROM cli_authorizations WHERE code_digest = sha256(code) AND expires_at > clock_timestamp() RETURNING user_id, challenge`
2. `subtle.ConstantTimeCompare(sha256(verifier), challenge)`
3. `LockLoginUser` and a check that the user is enabled
4. `CreateSession` with kind `cli`, and `CleanupSessions`
5. commit, and return `auth.LoginResponse`

Every failure returns 401 `INVALID_CREDENTIALS`. A wrong verifier still commits the delete, so a code is consumed on its first presentation. There is no rate limit: guessing a 256-bit code is hopeless, and login limits are keyed by username and peer, which this route does not have.

### 8. CLI browser login

`login` takes only the shared flags and `--no-browser`:

1. Resolve the server and open the session store (fail early on unsafe storage). No terminal is required, so a script can run `login --no-browser` and read the link from stderr.
2. Generate `verifier` and `state` from 32 random bytes each, base64url without padding. The challenge is the base64url SHA-256 of the verifier string.
3. `net.Listen("tcp", "127.0.0.1:0")` and serve with an `http.Server` whose handler accepts only `GET /callback` with a matching `state` (compared in constant time) and a 43-character `code`. Other requests get 400 or 404 and the CLI keeps waiting.
4. Print `Open this link to sign in:` and the link to stderr. Unless `--no-browser`, run `open` (darwin) or `xdg-open` (linux) with the link as a single argument, without a shell, and ignore its failure.
5. Wait for the callback, five minutes or an interrupt. Answer the callback with a static page, shut the listener down, then post the code and verifier to `/api/auth/token` under the usual whole-request `--timeout`.
6. Store the session with the existing locked write, taking the per-origin lock only for the write and not across the wait: atomic write, best-effort revocation of the new session on storage failure, best-effort revocation of the replaced session.

The browser opener is injected through `IO` so tests drive the whole flow: a fake opener performs the GET and the Approve POST with a browser cookie against an `httptest` server backed by the real database.

`--username` and `--password-stdin` are removed from `login`. `readPassword` stays for `users create` and `users reset-password`, with its prompt and `--password-stdin`.

Alternative: keep `--password-stdin` for agents and CI. Agents already work with the session the person created, the scripts can drive the real flow, and keeping it would also keep a second password route on the server.

### 9. Browser-only passwords

`loginJSON`, `auth.LoginPath` and the CLI transport's login-path special case (`auth_transport.go:764`) are deleted, so a password reaches the server only through `POST /login`. The service's `Login` then only issues browser sessions, so its `Kind` input is removed; CLI sessions come only from the token exchange. A request to the old path gets the router's 404.

The smoke, image smoke and kind scripts share one helper: spawn `clavis login --no-browser`, read the link from its stderr, `POST /login` with the username, password, Origin and the link as `next`, follow the redirect to `GET /authorize` with the cookie, `POST /authorize` with Origin and cookie, then `GET` the `Location` it returns so the CLI's callback receives the code, and wait for the CLI's result. The first administrator comes from bootstrap as today; other users are created with `users create --password-stdin` from that administrator's session.

Alternative: keep the JSON route for scripts only. It is a password route an attacker can reach without a browser, which is what the owner wants gone.

### 10. Output

`auth.Identity` carries `expiresAt` and `idleExpiresAt`. Text output for `login` and `whoami` prints `Expires:` and `Idle until:`. `sessions revoke`, `profiles list` and the admin pages do not change: there is no session listing to extend.

## Risks / Trade-offs

- [A malicious page links a signed-in user to an authorize link with an attacker's challenge] → The user must click Approve on a page naming the port, and the code goes to `127.0.0.1` on the user's own machine, which the attacker cannot read without already running code there.
- [Another local process listens on the callback port before the CLI] → The operating system assigns the port and the CLI already holds it. A process running as the same user can already read `~/.clavis/sessions`, so this adds no exposure.
- [A signed-in user scripts many Approve posts and grows `cli_authorizations`] → Each post needs a valid session and passes the origin check, rows expire after two minutes, and every approve deletes a batch of expired ones. Accepted for a handful of users.
- [A session lives up to thirty days on a stolen laptop] → Administrator revocation and blocking remain immediate, and the cap is configurable down to five minutes.
- [People on a remote shell cannot sign in without a local browser] → `ssh -L <port>:127.0.0.1:<port>` with `--no-browser` works; device flow can follow if someone needs it.
- [An older CLI or a script using `login --password-stdin` stops working] → The release note says to upgrade the CLI and sign in with `clavis login`. Breaking changes are allowed in the beta.
- [An agent runs `login` anyway and waits five minutes] → The skill forbids it and the command ends with `TIMEOUT`; nothing is issued without the person's Approve click.
- [Renewal adds a write to the authenticate path] → At most one write per session per half idle window. The select path is unchanged when no renewal is due.

## Migration Plan

Migration `008_session_renewal_and_cli_authorization.sql`, up only (the ledger is forward-only):

1. `UPDATE sessions SET revoked_at = clock_timestamp() WHERE revoked_at IS NULL`
2. `ALTER TABLE sessions ADD COLUMN max_expires_at timestamptz`, `UPDATE sessions SET max_expires_at = expires_at`, `SET NOT NULL`, the check constraint
3. `CREATE INDEX sessions_expires_at ON sessions(expires_at)`
4. `CREATE TABLE cli_authorizations` with its index
5. extend the readiness schema check in `initialize.sql` for the new column and table

Release as `v0.1.0`, with notes that every user signs in again; that `CLAVIS_SESSION_TTL` and `server.sessionTTL` are replaced by the two new settings; that `clavis login` now signs in only through the browser, `--username` and `--password-stdin` are gone from `login`, and older CLIs cannot sign in; and that agents reinstall the skill. Rollback across the migration is unsupported, as for every earlier migration; an older image fails its readiness schema check rather than running against the new schema.

## Open Questions

None.
