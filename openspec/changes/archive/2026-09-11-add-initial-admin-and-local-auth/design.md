## Context

At the start of this change, the server opens a lazy pgx pool, starts HTTP without waiting for PostgreSQL, and exposes ping-based readiness alongside a public templ/htmx setup page. There is no schema, user store, authentication middleware or session cache. `internal/server.Handler` owns route registration; `internal/web` owns buffered HTML rendering and generated templates. The CLI has one output/exit boundary, bounded doctor requests and no input abstraction.

The original stack decision already selected sqlc targeting pgx v5 and Goose v3 for integration with the first persisted schema. Those choices remain binding; pgx is the driver, not a substitute for query generation or a migration engine. Versions rechecked for this change remain sqlc 1.31.1 and Goose 3.28.0.

The user selected automated installation as the default: deployment configuration supplies a personal initial administrator username and a password file; normal server startup initializes once. No manual bootstrap command, public first-admin endpoint or browser setup secret is required.

This is an identity foundation, not completion of the PRD's authentication or administration scope. The settings below are the approved defaults for this milestone.

## Goals / Non-Goals

**Goals:**
- Make a fresh installation usable without interactive deployment steps.
- Preserve copied-binary serving, bounded requests/shutdown and public diagnostics during dependency failure.
- Establish one account/session service shared by browser and CLI adapters.
- Make bootstrap, expiry, blocking and revocation safe under concurrency and restarts.
- Provide stable contracts and exclusive ownership so three implementation threads can work independently.

**Non-Goals:**
- Browser-based account creation, a bootstrap command, self-registration, password reset/recovery or password rotation.
- Google/OIDC, account linking, groups, connection grants, provider operations or broad user management.
- A production deployment manifest, a general audit interface, external secret-manager integration or a background agent.

## Decisions

### 1. Initialize in the running server, not through a second mandatory command

`cmd/server` remains the normal entry point. Start the listener and a cancellation-aware initialization worker under the same process context. The worker applies embedded migrations and attempts bootstrap independently of HTTP requests. GET requests never apply migrations, read bootstrap secrets or create users.

Use one bounded attempt at a time (30 seconds maximum), with jittered retry backoff from one to 30 seconds for dependency/lock contention. Incomplete setup and invalid bootstrap inputs remain safely unready; recheck at most once per 30 seconds so a repaired mounted secret can be noticed. Invalid/nonmatching schema requires operator repair and is not automatically rewritten. Shutdown cancels the worker before closing the pool and shares the existing overall shutdown budget.

Alternatives: a separate initialization job gives deployment tools a useful completion boundary, but adds a required installation step; browser setup introduces another privileged endpoint and proof-of-ownership secret. Neither is necessary for the selected unattended default.

### 2. Use Goose migrations and sqlc application queries

Add immutable, numbered Goose SQL files under `internal/database/migrations`, embedded in the server. Goose 3.28.0's provider owns parsing, ordering, execution, version tracking and transaction commit/rollback, using pgx's `database/sql` adapter. Call the library from the existing bounded initialization worker; no external Goose executable or extra operator command is required. The later-approved automatic startup flow changes the original deployment-step timing, not the selected tools.

Use `goose_db_version` as the sole migration ledger. A small decorator around Goose's default PostgreSQL store adds/stamps the embedded migration checksum in the same Goose-owned transaction. Do not retain a parallel custom migration engine or `schema_migrations` ledger. Reject unknown/newer versions, checksum mismatches and a legacy experimental custom ledger instead of adopting or repairing them silently. Forward transactional migrations only; no automatic down migration.

A Goose session locker holds the fixed PostgreSQL advisory key for the provider operation; native bootstrap transactions acquire that same key with a transaction-scoped lock. The two scopes conflict on the same database key, serializing migration and bootstrap across processes. Re-read committed version state after locking. Lock acquisition counts against the attempt deadline; release/discard must prevent returning a locked connection to a pool after cancellation.

Goose uses one transient dedicated `database/sql` connection cloned from the application's pgx connection configuration, with one maximum open connection, no idle connections and closure at attempt end. It does not borrow a session from the application pool: database/sql cancellation can discard a wrapper before a custom locker gets a chance to close the underlying pooled session. A dedicated connection avoids returning a session-scoped migration lock to application traffic and preserves the same DSN/startup parameters without a custom connector framework.

All application persistence SQL lives in named files under `internal/database/queries`. Root `sqlc.yaml` generates the checked-in `internal/database/sqlc` package using pgx v5 and the Goose migrations as schema input. Handwritten authentication, initialization, audit and throttle code calls generated typed methods through native pgx transaction bindings. Keep Begin/Commit/Rollback orchestration in the service, but do not retain inline application SQL, generic raw-query wrappers or manual application-row scanning alongside sqlc. Direct fixture SQL remains confined to tests against disposable databases.

The only handwritten migration-control SQL exception is the explicit Goose metadata adapter in `internal/database/migration_metadata.go`: ledger presence/version/checksum operations and provider advisory locking. It cannot query or mutate `users`, `sessions`, `installation`, `auth_events` or `login_limits`, and cannot expose a generic query escape hatch. This implements Goose's supported store/locker extension points, not an alternative application persistence layer.

Pin the sqlc development tool in `.sqlc-version`; `make generate-db` explicitly regenerates output, while `make check-db-generated` compares the complete generated file set from an isolated input copy without rewriting source or generated Go. Setup installs the exact tool; server builds/checks fail on missing, stale or unexpected generated output. CLI-only compilation remains Go-only. A Go-AST contract check rejects direct query/scan paths in maintained application persistence code, with narrowly inventoried migration-metadata allowances rather than a blanket file exemption. It is a maintainability guard, not a security sandbox. Mutation targets retain handwritten database/authentication logic and exclude generated sqlc code.

The initial platform schema contains:

| Table | Responsibility |
|---|---|
| `goose_db_version` | Goose-owned applied version history with transactional checksum metadata |
| `installation` | Singleton with a durable `initialized_at`, independent of the number of remaining administrators |
| `users` | Random stable UUID, unique username, password hash, `admin`/`member` role, disabled flag and timestamps |
| `sessions` | Token digest, user UUID, `browser`/`cli` kind, creation/expiry and revocation timestamps |
| `auth_events` | Safe event identifier, actor/target UUIDs when known, session row identifier, action, timestamp and outcome category |
| `login_limits` | Expiring throttle counters; no submitted password or raw request payload |

Production mutation paths for users/roles are not exposed yet. Tests seed member/disabled users through fixtures, not a hidden public registration API.

### 3. Treat bootstrap inputs as one-time installation inputs

Proposed server settings:

| Setting | Meaning |
|---|---|
| `CLAVIS_BOOTSTRAP_USERNAME` | Initial personal administrator username |
| `CLAVIS_BOOTSTRAP_PASSWORD_FILE` | Absolute path to a deployment-managed password file |
| `CLAVIS_PUBLIC_URL` | Canonical external origin for authentication and browser origin checks |
| `CLAVIS_SESSION_TTL` | Fixed session lifetime, default `8h`, allowed `5m` through `24h` |

Ordinary required configuration is validated before listening, as today. Bootstrap fields are optional and their contents are validated only after the database proves installation is uninitialized. An initialized installation does not open the password file or reject obsolete/missing bootstrap inputs. Configuration loading must not eagerly read the file or enforce the bootstrap pair before that check.

Under the bootstrap transaction lock, re-read the marker. If initialized, return without changes. Otherwise require both inputs, validate/read/hash the password and atomically insert the administrator, its creation event and the marker. Reject unexpected existing user rows without a marker rather than adopting a user or guessing that an existing database is fresh. Concurrent replicas converge on the winner's account without comparing or changing its credentials.

Password files must resolve to a regular file, be bounded to 1,026 bytes before removing at most one terminal LF or CRLF, and not be group/world accessible on the supported POSIX runtime. Deployment-managed symlinks are permitted, with type/size/permission checks on the opened target; do not reject projected secret mounts merely because their paths use symlinks. Do not accept directories, FIFOs or block indefinitely opening a special file. Do not log the file's path or contents. Keep the plaintext only for the hashing operation and do not promise cryptographic memory erasure in Go.

Usernames are 3-64 lowercase ASCII characters matching `[a-z][a-z0-9._-]{2,63}`; do not silently normalize aliases or email addresses. Passwords are valid UTF-8, 15-1,024 bytes, with no NUL, CR or LF. Preserve all other whitespace. The same validation applies to file/stdin/browser input after the documented file/stdin terminal-newline removal.

Changing/removing bootstrap settings after initialization does not rotate a password, revoke a session or reopen setup. Account loss requires a future explicit recovery procedure, not deleting the marker or rerunning bootstrap.

### 4. Readiness becomes installation readiness

The shared readiness service performs a fresh, bounded database/schema/marker check and projects one result into JSON, HTML and CLI diagnostics. In-memory worker state is advisory, never proof that a currently unreachable or incompatible database is ready. It does not expose user counts, credential paths, SQL errors or passwords.

| Condition | `/health/ready` | Error code | Doctor database state |
|---|---|---|---|
| Database unreachable or check timed out | 503 | `DEPENDENCY_UNAVAILABLE` | `unavailable` |
| Database reachable; migrations/bootstrap still progressing | 503 | `INITIALIZING` | `ready` |
| Fresh schema; bootstrap inputs absent or incomplete | 503 | `SETUP_REQUIRED` | `ready` |
| Fresh schema; supplied bootstrap inputs invalid/unreadable | 503 | `BOOTSTRAP_FAILED` | `ready` |
| Migration failed, checksum mismatch or unsupported schema | 503 | `SCHEMA_ERROR` | `ready` |
| Database reachable, supported schema, durable initialized marker | 200 | none | `ready` |

Keep `{"status":"ready"}` and the existing database-outage JSON unchanged. New failures use the same `{"status":"not_ready","error":{"code":"...","message":"..."}}` structure with application-owned messages. `doctor` preserves schemaVersion 1, `data.api`/`data.database`, and 0/1/2 exit conventions; it allowlists the new failures rather than echoing response messages. No new required data field is added to doctor.

Credential-processing endpoints and protected resources fail closed with safe 503 results while the installation is unready. Public document/asset GETs are explicitly outside that middleware: `/`, `/login`, assets and liveness remain public and render without waiting for database access, even with stale or malformed authentication cookies. `GET /ui/readiness` reflects the expanded states using the existing status/content-type/fragment-marker gate, five-second deadline, cancellation and explicit-retry behavior. The worker's retry loop is not browser polling.

### 5. Use opaque, revocable sessions instead of stateless JWTs

Use Argon2id from pinned `golang.org/x/crypto`, starting with 64 MiB memory, three iterations, parallelism one, independent 16-byte random salts and a 32-byte derived key. Store a versioned encoded hash. Bound parameters when parsing stored hashes and benchmark on the supported test machine without weakening the baseline silently.

Every credential-processing or protected request gets a five-second operation context covering body reads, readiness, pool acquisition, queries, transaction/row-lock waits, session/event writes and response preparation. All database calls use that context and incomplete transactions roll back on cancellation; return safe 503 `SERVICE_UNAVAILABLE` when the operation times out before response publication. Configure HTTP read/write deadlines to permit this bounded response rather than mistaking socket deadlines for handler cancellation. Argon2 cannot be interrupted mid-call: its fixed-size work retains the two-hash budget slot until completion even after the request is canceled, and no canceled hash result can issue a session. Never abandon unlimited hashing goroutines to satisfy a response deadline. Verify operation recovery with deliberately held database locks and bounded KDF tests.

Issue independent 32-byte random opaque tokens encoded as base64url. Persist only their SHA-256 digests; tokens are high-entropy secrets, unlike passwords. Sessions have a fixed eight-hour default expiry, no sliding renewal and no refresh token. Browser and CLI sessions have distinct kinds and cannot be used through the other transport.

On every protected request, resolve the digest and current user from PostgreSQL, rejecting expired/revoked sessions and disabled users. Administrator checks read the current role, not a role copied into a token. Authentication alone grants no connection access. Logout revokes one session; administrator revocation revokes all current browser and CLI sessions for a specified user, including the actor's own sessions if targeted. Future successful logins are new sessions.

Serialize session issuance and all-user revocation on the target user row. A login committed before revocation is included; a login committed afterward is a new session. Revocation takes effect for subsequent requests, not as a promise to cancel responses already authorized in flight.

Use generic invalid-credentials results for nonexistent, disabled and wrong-password users, with a dummy hash verification for unknown users. Apply shared, expiring failure limits before expensive hashing: ten failed attempts per canonical username and 50 per source address in five minutes, plus a bounded two-hash concurrent worker budget per instance. Return a generic 429 and `Retry-After` rather than permanent account lockout. Source address is the actual socket peer; do not trust arbitrary forwarded headers. Bound throttle state and periodically delete expired counters in bounded batches. Behind a reverse proxy, the peer limit is shared; deployment tuning is a known limitation, not a reason to trust spoofable headers.

Record bootstrap, sign-in outcomes, logout and administrative revocation using safe event categories and known UUIDs only. Do not persist submitted unknown usernames, passwords, tokens, digests, cookies, CSRF values, bodies, query strings or raw driver errors. Successful credential/session mutations and their events commit together; inability to persist required events prevents successful mutation. If storage is unavailable, return safe unavailability and log only an application-owned category; do not claim a durable event was recorded.

An explicit `auth.EventRecorder` dependency covers sign-in/logout/revocation attempts rejected by HTTP adapters before service invocation: invalid or oversized input, origin checks and absent/malformed API mutation credentials. Keep `auth.Service` unchanged; the recorder accepts only allowlisted action/outcome values and optional validated actor/target/session UUIDs, with recorder-owned timestamps. Early anonymous rejections leave IDs absent rather than looking up a rejected credential. Use the same operation deadline; service-invoked operations own their existing events so one rejection is not recorded twice. Public document/health GETs and unmatched routes are outside this event boundary.

The valid-origin browser logout path with no cookie or a single malformed cookie remains idempotent local cleanup: clear the cookie and redirect without querying the database or writing an event. It is not a rejected authenticated mutation. Ambiguous browser credentials and rejected API mutations are not exempt. If persistence of a required rejection event fails, return safe 503 while preserving the original security effect: an invalid-origin request still cannot clear a cookie or revoke a session.

Alternatives: JWTs reduce reads but complicate immediate blocking and revocation; a shared browser/CLI token transport creates unnecessary cross-channel credential exposure. Neither fits this small PostgreSQL-backed service.

### 6. Freeze HTTP and browser contracts before splitting implementation

JSON authentication endpoints accept only documented JSON and bearer credentials; cookies do not authenticate these routes. Browser form routes accept cookies, not bearer credentials. Reject ambiguous/multiple credentials. Set `Cache-Control: no-store` on authentication responses and never redirect JSON clients.

| Method/path | Input | Successful result |
|---|---|---|
| `POST /api/auth/login` | `{username,password}` | 200 `{token,user,expiresAt}`; CLI-kind token only |
| `GET /api/auth/whoami` | CLI bearer token | 200 `{user,expiresAt}` |
| `POST /api/auth/logout` | CLI bearer token, empty body | 200 `{revoked:true}` |
| `POST /api/admin/users/{userID}/sessions/revoke` | Admin CLI bearer token, empty body | 200 `{revoked:true}` |
| `GET /login` | No credentials required | 200 buffered document with username/password fields |
| `POST /login` | Same-origin form username/password | 303 `/admin`, fresh browser cookie |
| `POST /logout` | Same-origin form and browser cookie | Revoke session, clear cookie, 303 `/login` |
| `GET /admin` | Browser cookie | Minimal admin-only document with identity and sign-out |

`user` contains only `{id,username,role}` and `expiresAt` is UTC RFC3339. API failures are `{error:{code,message}}`, with fixed safe messages: 400 `INVALID_ARGUMENT`, 401 `INVALID_CREDENTIALS` (login) or `UNAUTHENTICATED`, 403 `FORBIDDEN`, 404 `USER_NOT_FOUND` (admin-only lookup), 429 `RATE_LIMITED`, 503 one of the readiness codes or `SERVICE_UNAVAILABLE`. No health endpoint is moved into this schema. Missing, expired or revoked logout credentials return 401; the CLI treats that as confirmation there is no usable cached session.

Cap encoded credential requests at 8 KiB while separately enforcing the decoded 1,024-byte password limit; this accommodates worst-case JSON escaping without allowing a larger password. Reject unknown fields, trailing JSON and unsupported content types. JSON login does not enable CORS; reject cross-origin browser requests and do not accept form-encoded password requests on JSON routes.

Freeze browser failure outcomes as well as successes:

| Request/outcome | Status and rendering | Cookie effect |
|---|---|---|
| `POST /login`, invalid fields / credentials / Origin / throttling | 400 / 401 / 403 / 429 respectively; complete login document with allowlisted error; 429 also supplies `Retry-After` | No session issued or replaced |
| `POST /login`, unready or timed-out storage | 503 complete login document with safe error | No session issued or replaced |
| `POST /logout`, invalid/missing Origin or cross-site metadata | 403 complete error document | Do not clear a cookie or revoke a session |
| `POST /logout`, valid origin and absent/malformed/expired/revoked cookie | 303 `/login` after establishing there is no usable session; absence/malformed format needs no DB query | Clear the matching browser cookie |
| `POST /logout`, valid origin but remote revocation cannot be confirmed | 503 complete error document explicitly saying local sign-out occurred but remote revocation is unconfirmed | Clear the matching browser cookie; do not claim successful remote revocation |
| `GET /admin`, missing/invalid session / valid non-admin / unavailable storage | 303 `/login` / 403 complete error document / 503 complete error document | Do not rotate credentials |

Login error documents use empty password fields and a validated username only if safe to retain; no hidden password fields or arbitrary return URL. A valid non-admin login still redirects to `/admin`, which returns 403; a broader member landing page is not introduced in this milestone.

The foundation freezes the exported presentation signatures: `web.Login(web.LoginModel) templ.Component`, `web.Admin(web.AdminModel) templ.Component`, `web.AuthError(web.AuthErrorModel) templ.Component` and `web.Readiness(platform.Readiness) templ.Component`, all rendered through existing `web.Render`. `LoginModel` contains bounded `Username`, allowlisted `ErrorCode` and integer `RetryAfterSeconds`; `AdminModel` contains the safe user DTO; `AuthErrorModel` contains an allowlisted error code and `RemoteRevocationUnconfirmed` boolean. Templates map codes to application-owned text. No view model contains passwords, tokens, cookies or arbitrary response bodies. Backend selects HTTP status/headers and models; web owns their presentation. Preserve `web.Page()` as the public setup document.

`CLAVIS_PUBLIC_URL` is an origin only: no credentials, query, fragment or base path. Default to the actual bound literal loopback listener origin when possible (including the assigned port when configured with port zero); otherwise require explicit configuration. Resolve that local default before accepting HTTP requests. HTTP authentication is permitted only for a literal loopback origin/listener during local development. Non-loopback deployments require an HTTPS public origin, with TLS terminated by the deployment in front of the existing HTTP listener. The deployment must prevent direct untrusted access to that listener; a configured HTTPS URL alone does not encrypt backend traffic. Never infer the public origin or secure-cookie policy from untrusted Host/forwarded headers.

Browser sessions use a host-only HttpOnly, SameSite=Lax cookie with Path=/, Secure for HTTPS and expiry no later than server-side expiry. Use a `__Host-` cookie name in HTTPS mode and a separate development-only name on loopback HTTP. Rotate credentials at login; never place a session token in HTML, JavaScript storage or a URL.

Protect both login and authenticated mutations against CSRF using strict configured-origin validation: reject absent, `null`, multiple or mismatched Origin headers on browser POST, and reject cross-site Fetch Metadata when present. GETs can validate existing credentials but never issue, rotate or revoke credentials or mutate accounts/sessions. Use Go's cross-origin protection support where applicable, with the explicit configured-origin rule rather than treating the request Host as authority. This consciously targets modern browsers that send Origin on form POST; do not add a permissive missing-header fallback. This avoids pre-login database state and permits the public login document to render during outages.

Use ordinary full-document form POST/redirect for authentication; retain htmx only for existing readiness updates. A failed origin check never creates or revokes a session. Browser errors render application-owned messages without echoing password fields. Protect authentication documents against framing with `Content-Security-Policy: frame-ancestors 'none'`. If support for a client without Origin becomes necessary, design a session-bound CSRF-token fallback separately rather than weakening this check.

Unauthenticated `/admin` navigations redirect to `/login`; a valid non-admin session receives safe 403, and unready storage receives safe 503. The admin shell contains no fake users, connections or management capabilities. No arbitrary return URL is accepted.

### 7. Keep CLI credentials separate from command output

Add `login --username <name>`, `logout`, `whoami` and `sessions revoke --user <uuid>`, each with existing `--server`/`CLAVIS_SERVER_URL`, `--timeout` and `--output` conventions. Login reads a hidden terminal prompt or explicit `--password-stdin`; it never accepts password/token flags or environment variables. Noninteractive input without the stdin flag fails rather than hanging. Inject input/prompt dependencies at the CLI boundary; keep stdout exclusively for the result.

Authentication requires HTTPS except literal loopback HTTP. For this milestone, auth commands require a root-origin server URL; reject base paths rather than silently sharing credentials across deployments. Doctor's existing URL/base-path compatibility is unchanged. Canonicalize scheme, host, IPv6 and default port before choosing credentials; different origins never share tokens.

Reuse the doctor's no-redirect policy, 64 KiB response cap and one whole-request timeout including body consumption. Login/logout/revocation are not automatically retried. A login timeout can leave a valid but undelivered session until expiry; do not claim the request was rolled back.

Persist only token, canonical origin, safe user data and expiry below `os.UserConfigDir()/clavis/sessions/`, keyed by a digest of the canonical origin. On supported POSIX systems use a private 0700 directory and atomic 0600 regular-file writes; reject unsafe directories, symlinks, nonregular files, ownership/permission failures and malformed cache contents. A platform without equivalent protection must fail clearly rather than create an unprotected cache. Never use the project directory or browser storage.

Serialize credential-changing commands per origin with a bounded interprocess lock whose release follows process exit. Failed login does not replace a working cached session. Report success only after safe persistence; if persistence fails, attempt bounded best-effort revocation of the newly issued session and report `CREDENTIAL_STORAGE_FAILED` without printing its token. On successful replacement, best-effort revoke the prior cached session; do not claim that sessions on other devices were revoked.

Logout contacts the server and removes only the matching local session under the same origin lock. Remove the local credential even when the server is unreachable, but return exit 1 and a safe failure explaining that remote revocation was not confirmed. A 401 logout response and an absent local credential are successful no-session outcomes. A local deletion failure is not success. `whoami` queries the server and never treats cached identity as proof of an active session.

Results keep `{schemaVersion:1,ok,data,error}` and exit 0/1/2. Successful login/whoami expose only `{user,expiresAt}`; logout/revocation expose `{revoked:true}`. Local-only logout after network failure must not emit `revoked:true`. CLI errors include safe API categories plus existing `SERVER_UNREACHABLE`, `TIMEOUT`, `INVALID_RESPONSE`, and local `CREDENTIAL_STORAGE_FAILED`. Text formatting must explicitly support the new safe result types; neither format includes tokens or raw responses.

### 8. Establish a small common base, then three parallel lanes

The coordinator owns this plan/checklist, shared dependency metadata and final integration. Land a contract/foundation PR first: domain/DTO types, narrow service interfaces, route/error tables encoded in contract tests, injectable CLI I/O, and deterministic test fixtures. Define types in transport-neutral packages (`internal/auth` and `internal/platform`); HTTP stays in `internal/server`, SQL in database/store packages and presentation in `internal/web`. Avoid making CLI depend on the web package. Check that foundation fixtures do not accidentally expose unauthenticated production routes.

| Lane | Exclusive edit ownership | Can start after foundation |
|---|---|---|
| Backend | `internal/database`, initialization/auth service/store implementations, `internal/config`, `internal/server`, `cmd/server` | Real migrations, bootstrap, auth HTTP/form adapters and middleware against fixture views |
| Web | `internal/web` maintained/generated templates and non-browser Go view tests, `web/scripts`, `web/styles` | Setup states, sign-in and protected shell against fake services with the frozen contract |
| CLI | `internal/cli`, `cmd/clavis`, CLI-only test files | Commands, transport, cache and redaction against test HTTP servers |
| Coordinator/reviewer | `go.mod`/`go.sum`, `web/package.json`/`web/pnpm-lock.yaml` and other package/tool metadata, root scripts/Makefile, README/environment examples, OpenSpec checklist and real integration fixtures | Review, dependency updates and final wiring/checks |

Foundation contract types and exported view signatures become coordinator-owned after landing; web owns their template bodies, not independent signature changes. Backend owns route registration even when a handler renders a web-owned template. Each lane supplies its tests and generated artifacts for coordinator integration. Shared package/lockfile edits are requested from the coordinator, not independently merged. Use separate branches/checkouts and isolated ports, database names, temporary homes and report directories.

Backend, web and CLI are parallel implementation lanes, not independently complete features. Merge into an integration branch (or backend then clients with compatibility maintained); do not release a fixture-backed or half-authenticated application. Independent security review can run during implementation, but the final API/CLI and multi-process database tests must run on the integrated result.

Validation is browser-free at the user's request. Remove Playwright suites, browser-only fixtures and browser installation/execution from quality and smoke commands. Retain Go rendering tests, HTTP cookie/CSRF/authentication tests and real database/API/CLI integration. Smoke checks document/asset availability over HTTP, not DOM behavior, screenshots, appearance persistence or recovery in an already-loaded page. This changes automated test coverage, not the browser UI's behavior requirements.

## Risks / Trade-offs

- Startup DDL requires schema-owner privileges -> document this first-install requirement; serialize/bound migrations and fail closed. A separate least-privilege migration phase can be a later deployment enhancement.
- Readiness changes can surprise existing health consumers -> preserve old response shapes, explicitly add known initialization errors and update doctor/browser/smoke in the same integrated release.
- Files used for bootstrap are runtime secret inputs -> the copied executable remains self-contained for code/assets/SQL, not for deployment credentials; tests must distinguish those contracts.
- Eight-hour sessions require repeated CLI sign-in -> choose revocability and simple expiry first; no accidental forever-token or refresh subsystem.
- Shared peer throttling behind a proxy can limit legitimate users -> document/test the baseline and keep limits configurable in a later reviewed change; never silently trust spoofed forwarding headers.
- An operator with write access to the platform database can bypass application controls -> bootstrap protection is not a defense against a compromised database administrator.
- Removing or changing bootstrap inputs cannot recover an account -> preserve the password in the operator's secret manager and state clearly that recovery/rotation needs a separate design before a production pilot.
- Failed storage writes can prevent durable failure auditing -> return safe unavailability and a redacted operational category, never persist private request data as a fallback.

## Migration Plan

1. Build the embedded migration/auth release through the existing pinned tooling. Back up any platform database before its first schema migration; do not migrate arbitrary external/provider databases.
2. Supply a personal bootstrap username, a unique password through a protected mounted file and an HTTPS public origin for non-loopback deployments. Do not commit the password or include it in deployment command arguments.
3. Start the server normally. Liveness/setup remain reachable; readiness stays 503 until migrations and initialization finish. Automation waits for readiness and interprets setup/schema error categories instead of retrying forever without diagnosis.
4. Verify CLI sign-in, identity and sign-out. Remove bootstrap inputs from the running deployment when convenient; retain the credential securely for its owner until a future explicit rotation operation exists.
5. Roll out additional instances with the same platform database. They verify schema/marker without consuming bootstrap secrets.
6. Rollback does not run destructive down migrations or delete the initialization marker. Stop the new release and restore a tested compatible binary/database backup as an operator-controlled procedure. The pre-auth binary is not a security-equivalent rollback and must not be exposed as an authenticated deployment.

## Open Questions

No decision remains open within this milestone. The HTTP/configuration names, fixed lifetime and password/throttle defaults above are approved shared contracts, not independent choices for implementation threads. Account recovery, Google/OIDC, retention policy and broad management remain explicit follow-up changes; this milestone alone is not pilot readiness.
