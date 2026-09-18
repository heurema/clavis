# local-authentication Specification

## Purpose

Authenticate local users and enforce expiring, revocable browser and CLI sessions with current authorization.

## Requirements

### Requirement: Local credential verification


The system SHALL authenticate enabled local users by username and password only through the browser sign-in form at `/login`, storing only salted, versioned Argon2id hashes. There SHALL be no JSON or other non-browser route that accepts a password for sign-in. It SHALL bound request sizes, hash parameters and concurrent verification work. Unknown users, disabled users and wrong passwords SHALL receive the same safe invalid-credentials result. Shared expiring login limits SHALL apply across instances without a permanent account lockout or unbounded counter growth.

Usernames SHALL match `[a-z][a-z0-9._-]{2,63}` without silent normalization. Passwords SHALL contain 15-1,024 valid UTF-8 bytes, excluding NUL, CR and LF while preserving other whitespace. Encoded credential requests SHALL be bounded to 8 KiB independently of the decoded password limit, so permitted credentials remain usable across bootstrap and the browser form.

#### Scenario: Valid local credentials
- **WHEN** an enabled local user submits valid credentials through the browser form to a ready installation
- **THEN** the system issues a new browser session and returns only the safe identity in a fresh cookie

#### Scenario: Invalid or disabled account
- **WHEN** a login supplies a nonexistent username, a disabled user or an incorrect password
- **THEN** it fails with the same application-owned invalid-credentials response and does not disclose account existence

#### Scenario: Repeated or concurrent password attempts
- **WHEN** attempts exceed the documented shared failure limits or verification capacity
- **THEN** the server returns a bounded safe 429 response with retry guidance rather than allocating unbounded hashing work
- **AND** a replica change does not reset the shared failure counters

#### Scenario: A valid password requires maximum form encoding
- **WHEN** a valid maximum-length bootstrap password requires three percent-encoded bytes per decoded byte
- **THEN** the browser form accepts its encoded representation while still enforcing the decoded password limit

#### Scenario: JSON password login is gone
- **WHEN** a client posts `{username, password}` to `/api/auth/login`
- **THEN** the server answers 404 and verifies no password and issues no session
### Requirement: Expiring server-side sessions


The server SHALL generate high-entropy opaque session tokens, persist only token digests, and distinguish browser from CLI sessions. Every session SHALL have an idle expiry and an absolute expiry, set at issuance from `CLAVIS_SESSION_IDLE_TIMEOUT` (default `168h`) and `CLAVIS_SESSION_MAX_LIFETIME` (default `720h`), with the idle expiry never later than the absolute expiry. Configuration SHALL accept only `5m ≤ idle ≤ max ≤ 2160h` and SHALL otherwise fail before listening with `INVALID_DURATION` naming the offending variable. `CLAVIS_SESSION_TTL` SHALL NOT be read. A session SHALL be usable only while it is unrevoked, its user is enabled and the current time is before its idle expiry.

A successful authentication SHALL renew the session only when less than half the idle timeout remains before the idle expiry and the idle expiry is still before the absolute expiry. Renewal SHALL set the idle expiry to the earlier of the current time plus the idle timeout and the absolute expiry. Renewal SHALL be one conditional update that applies only to a session that is still unrevoked, unexpired and owned by an enabled user, so a renewal can never make a revoked, expired or disabled session usable again. The absolute expiry SHALL never change.

Whenever a session is issued, the server SHALL delete at most a bounded batch of sessions whose idle expiry has passed, oldest first.

Every protected request SHALL verify current database session validity and account state. A cached token or cached role SHALL NOT substitute for current authorization. Results that report a session's expiry SHALL report the absolute expiry as `expiresAt` and the idle expiry as `idleExpiresAt`.

#### Scenario: Browser and CLI sessions coexist
- **WHEN** the same user signs in through both interfaces
- **THEN** independent, expiring sessions are created
- **AND** a browser token cannot authenticate a CLI bearer route or vice versa

#### Scenario: Expiry, revocation or disabled account
- **WHEN** a subsequent request uses a session past its idle expiry, a revoked session, or the account is disabled
- **THEN** it is denied without disclosing private session details

#### Scenario: Database outage after sign-in
- **WHEN** session validation storage becomes unavailable
- **THEN** protected requests fail safely rather than trusting a previously cached identity

#### Scenario: A used session renews
- **WHEN** a session issued with a seven-day idle timeout and a thirty-day cap is used four days after its last renewal
- **THEN** the request succeeds and the idle expiry moves to seven days after that request
- **AND** the absolute expiry is unchanged

#### Scenario: Frequent use does not write on every request
- **WHEN** a session is used again one hour after it was renewed
- **THEN** the request succeeds without changing the stored idle expiry

#### Scenario: Renewal stops at the cap
- **WHEN** a session is used two days before its absolute expiry
- **THEN** its idle expiry becomes the absolute expiry
- **AND** the session is denied once the absolute expiry passes, however often it is used

#### Scenario: Revocation races a renewal
- **WHEN** an administrator revokes a user's sessions while a request from one of those sessions is renewing it
- **THEN** the session stays revoked and every later request with it is denied

#### Scenario: Unused session expires
- **WHEN** a session is not used for longer than the idle timeout
- **THEN** the next request with it is denied even though its absolute expiry has not passed

#### Scenario: Invalid session settings
- **WHEN** the server starts with `CLAVIS_SESSION_IDLE_TIMEOUT=240h` and `CLAVIS_SESSION_MAX_LIFETIME=168h`
- **THEN** it fails before listening with `INVALID_DURATION` naming `CLAVIS_SESSION_IDLE_TIMEOUT`

#### Scenario: Expired sessions are cleaned up
- **WHEN** a login issues a session while expired sessions exist
- **THEN** a bounded batch of the oldest expired sessions is deleted and the login still succeeds

#### Scenario: Upgrade revokes existing sessions
- **WHEN** the server migrates a database holding sessions issued under the fixed lifetime
- **THEN** every one of those sessions is denied on its next request and a new login succeeds
### Requirement: Explicit logout and administrator revocation

The system SHALL allow users to revoke their current session and current administrators to revoke all existing sessions of a specified user through the documented administrative API. Revocation SHALL cover browser and CLI sessions and take effect on subsequent requests. Session issuance and all-user revocation SHALL have a defined transactional order. Non-administrators SHALL NOT revoke other users' sessions.

#### Scenario: Sign out one client
- **WHEN** a user signs out of one valid session
- **THEN** that session becomes unusable without implicitly revoking independent sessions

#### Scenario: Administrator revokes a user's sessions
- **WHEN** a current administrator revokes all sessions for a user
- **THEN** all that user's sessions committed before revocation are denied on subsequent requests
- **AND** a new login committed afterward creates a new session

#### Scenario: Role changes before a request
- **WHEN** an administrator's role is removed before a revocation request is authorized
- **THEN** the request is forbidden despite any previous session or client-side role value

### Requirement: Protected browser authentication


The same server SHALL provide a public sign-in document at `/login`, same-origin login/logout form actions and an administrator-only shell with one page per list at `/admin/users`, `/admin/groups`, `/admin/connections` and `/admin/grants`; `GET /admin` SHALL redirect to `/admin/users`. Successful browser sign-in SHALL redirect to `/admin/users`, except when the sign-in request carries a return target that is a valid CLI authorization link as defined in "CLI authorization through the browser"; the server SHALL then redirect to that link rebuilt from its parsed parameters, never to the submitted text, and SHALL ignore any other return target. The return target SHALL travel in the sign-in form's action URL, and every response to a refused sign-in SHALL render the sign-in document carrying the target the refused request carried. Browser sessions SHALL use host-only HttpOnly cookies, SameSite protection and Secure cookies on HTTPS, and a cookie's expiry SHALL be the session's absolute expiry. Authentication tokens SHALL NOT appear in URLs, rendered HTML, JavaScript storage or application logs. Browser mutations SHALL reject absent, null, multiple or nonmatching configured Origin headers and cross-site Fetch Metadata. A failed sign-in SHALL state its reason in one short application-owned sentence, without restating what the rendered form already shows. GET requests SHALL only validate existing credentials, which MAY renew a valid session's idle expiry, and SHALL never issue, rotate or revoke credentials or mutate accounts. Authentication documents SHALL reject framing. A document whose form a browser submits SHALL use a referrer policy that keeps the browser's `Origin` header on a same-origin submission while withholding the document's URL from other origins; a policy that makes a browser send an opaque origin SHALL NOT be used on such a document. Every administration page SHALL render inside the shell, which SHALL show the signed-in username and role, the sign-out form, the appearance control and the four navigation entries with their bounded counts; each page SHALL load all four bounded lists for those counts and SHALL fail closed when any of them cannot be loaded.

#### Scenario: Browser sign-in and protected navigation
- **WHEN** a user signs in through the same-origin form
- **THEN** the server sets a fresh browser session cookie and redirects to `/admin/users`
- **AND** an unauthenticated navigation to any administration page instead redirects to login

#### Scenario: Sign-in returns to a CLI authorization
- **WHEN** a member signs in through a login form carrying a valid CLI authorization link as its return target
- **THEN** the server sets a fresh browser session cookie and redirects to that authorization link instead of `/admin/users`

#### Scenario: Sign-in ignores any other return target
- **WHEN** a login form carries a return target that is an absolute URL, another path, or an authorization link with an invalid port, challenge or state
- **THEN** a successful sign-in redirects to `/admin/users`

#### Scenario: An authenticated member opens administration
- **WHEN** a valid non-admin session requests any administration page
- **THEN** the server returns safe 403 rather than granting administration merely because sign-in succeeded

#### Scenario: Cross-origin or missing-origin form submission
- **WHEN** a login or logout POST has an absent, null, multiple or incorrect Origin, or is marked cross-site
- **THEN** it fails before creating or revoking a session, even if cookies were included

#### Scenario: Safe browser rendering
- **WHEN** a form fails or a protected page renders user-supplied text
- **THEN** errors use application-owned messages, text is escaped and password fields are never echoed
- **AND** username/password labels, keyboard focus, submission and sign-out remain usable

#### Scenario: Public documents receive stale cookies during an outage
- **WHEN** the database is unavailable and GET `/` or `/login` includes an absent, malformed, expired or revoked session cookie
- **THEN** `/` redirects and `/login` renders without attempting database session validation

#### Scenario: Browser logout cannot confirm revocation
- **WHEN** a same-origin logout cannot confirm server-side revocation because storage is unavailable
- **THEN** the browser cookie is cleared and a safe 503 document distinguishes local sign-out from unconfirmed remote revocation

#### Scenario: Administration page cannot load a list
- **WHEN** an administrator's valid session requests an administration page but the user, group, connection or grant listing fails or times out
- **THEN** the server returns safe 503 rather than rendering the page or its counts without current data

#### Scenario: Old administration bookmark
- **WHEN** a browser requests `GET /admin`
- **THEN** the server redirects to `/admin/users` without reading the database

#### Scenario: A refused sign-in keeps the return target
- **WHEN** a sign-in request carrying a valid CLI authorization link is refused for a bad origin, an unsupported media type, duplicate session credentials, invalid input, wrong credentials, throttling, unavailable storage or an operation timeout
- **THEN** the rendered sign-in document carries that return target, rebuilt from its parsed parameters
- **AND** a successful sign-in submitted from that document redirects to the authorization link rather than `/admin/users`

#### Scenario: A browser posts the sign-in form from an authorization document
- **WHEN** a browser that withholds the referrer under a `no-referrer` policy submits the sign-in or approval form rendered by the authorization page
- **THEN** the request carries the document's own origin rather than an opaque one, and the submission is not refused for its origin
- **AND** the document's URL, with its challenge and state, is still not sent to another origin

#### Scenario: A refused sign-in states one short reason
- **WHEN** a sign-in fails for wrong credentials, a refused origin, throttling or unavailable storage
- **THEN** the document shows one short sentence for that failure and no further line describing the form's own state

### Requirement: Explicit authentication transports


JSON authentication endpoints SHALL use the route, status and body contracts in the design. They SHALL never accept a password, redirect to HTML, authenticate from browser cookies or expose arbitrary driver messages. Browser form routes SHALL NOT accept CLI bearer tokens. Credential transport SHALL require HTTPS outside literal loopback development; configured origin and TLS policy SHALL NOT be inferred from untrusted Host or forwarded headers. Authentication responses SHALL prevent caching.

Credential-processing and protected operations SHALL use a five-second context deadline covering body reads, database pool acquisition, queries, locks, session writes and response preparation. Cancellation SHALL propagate to database work, roll back incomplete transactions and prevent canceled work from issuing sessions. Non-cancelable password hashing SHALL remain within a fixed concurrency budget until completion. Public document and asset GETs SHALL be excluded from authentication/readiness middleware.

#### Scenario: A browser cookie reaches a JSON protected endpoint
- **WHEN** a JSON identity or administration request has only a browser cookie
- **THEN** it receives an unauthenticated JSON response rather than using ambient browser authentication

#### Scenario: Cross-origin JSON token request or malformed body
- **WHEN** a code exchange request is cross-origin, form-encoded, oversized or contains undocumented JSON fields or trailing data
- **THEN** it is rejected safely without issuing a token, consuming an authorization or reflecting submitted values

#### Scenario: Production and local development transport
- **WHEN** a non-loopback installation is configured for authentication
- **THEN** it requires an explicit HTTPS public origin and documented protected TLS termination
- **AND** plaintext authentication is allowed only for the documented literal-loopback development case

#### Scenario: Authentication waits on a database lock
- **WHEN** a transaction lock blocks login, code exchange, session validation or revocation past the operation deadline
- **THEN** the request returns safe unavailability within the bound, incomplete work rolls back and resources are released
- **AND** subsequent requests can succeed after the blocking transaction is released

### Requirement: CLI authorization through the browser


The server SHALL let a signed-in browser user approve a CLI sign-in and SHALL issue the CLI session only through a one-time code redeemed with a PKCE verifier.

A CLI authorization link SHALL be `GET /authorize?port=P&challenge=C&state=S`, where `P` is a decimal integer from 1024 to 65535, and `C` and `S` are each exactly 43 base64url characters. `C` SHALL be the unpadded base64url SHA-256 of the CLI's verifier. A GET of the link SHALL create, change or delete no row other than renewing the browser session. Without a valid browser session it SHALL render the login document carrying the link as its return target. With a valid browser session of any role it SHALL render a document that names the signed-in username and the requesting loopback port and offers one Approve action. An invalid link SHALL render a safe 400 document.

Approve SHALL be a same-origin form `POST /authorize` carrying the same three parameters, subject to the browser mutation Origin and Fetch Metadata rules and a valid browser session. On success the server SHALL store a new authorization with the SHA-256 digest of a fresh 32-byte random code, the approving user, the challenge and an expiry two minutes later. It SHALL also delete a bounded batch of expired authorizations. It SHALL answer with a 303 redirect to `http://127.0.0.1:P/callback?code=<code>&state=S`, built from the parsed integer port and the validated state only. Without a valid session it SHALL issue nothing and redirect to the login document carrying the link.

The code SHALL be redeemed through `POST /api/auth/token` with the JSON body `{code, verifier}` under the JSON authentication transport rules, where each value is exactly 43 base64url characters. In one transaction the server SHALL delete the unexpired authorization matching the code's digest, compare the SHA-256 of the verifier with its challenge in constant time, lock and re-read the user, and issue a CLI session with the same session policy as browser sign-in, returning `{token, user, expiresAt, idleExpiresAt}`. The authorization SHALL be consumed by its first redemption attempt, whatever the outcome. A missing, expired or already used code, a wrong verifier, and a disabled or deleted user SHALL all return 401 `INVALID_CREDENTIALS` without issuing a session. Codes SHALL NOT be logged, and only their digests SHALL be stored.

#### Scenario: A member approves a CLI sign-in
- **WHEN** a member with a valid browser session opens a valid authorization link and clicks Approve
- **THEN** the server redirects to `http://127.0.0.1:P/callback` with a code and the unchanged state
- **AND** redeeming that code with the matching verifier returns a CLI session for the member

#### Scenario: Opening the link creates nothing
- **WHEN** a browser with a valid session requests the authorization link any number of times without approving
- **THEN** no authorization exists and no code can be redeemed

#### Scenario: Signed-out browser
- **WHEN** a browser without a session opens a valid authorization link
- **THEN** the login document renders, and a successful sign-in returns to the authorization document rather than `/admin/users`

#### Scenario: Cross-site approval
- **WHEN** an Approve POST has an absent or foreign Origin or is marked cross-site
- **THEN** no authorization is stored and no redirect to the loopback callback occurs

#### Scenario: Invalid link parameters
- **WHEN** an authorization link or Approve POST has a port outside 1024-65535, a non-integer port, or a challenge or state that is not 43 base64url characters
- **THEN** the server answers a safe 400 document and stores nothing

#### Scenario: Code replay
- **WHEN** a code that was already redeemed is presented again with the correct verifier
- **THEN** the server returns 401 `INVALID_CREDENTIALS` and issues no session

#### Scenario: Wrong verifier consumes the code
- **WHEN** a valid code is presented first with a wrong verifier and then with the right one
- **THEN** both attempts return 401 `INVALID_CREDENTIALS`

#### Scenario: Expired code
- **WHEN** a code is redeemed more than two minutes after approval
- **THEN** the server returns 401 `INVALID_CREDENTIALS`

#### Scenario: User blocked after approval
- **WHEN** an administrator blocks the approving user between approval and redemption
- **THEN** the redemption returns 401 `INVALID_CREDENTIALS` and issues no session

#### Scenario: Browser credentials on the token route
- **WHEN** a token request carries a cookie or an Authorization header, is form-encoded, or has unknown fields
- **THEN** it is rejected under the JSON transport rules without consuming an authorization
