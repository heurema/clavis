# local-authentication Specification

## Purpose

Authenticate local users and enforce expiring, revocable browser and CLI sessions with current authorization and secret-free audit events.

## Requirements

### Requirement: Local credential verification

The system SHALL authenticate enabled local users by username and password, storing only salted, versioned Argon2id hashes. It SHALL bound request sizes, hash parameters and concurrent verification work. Unknown users, disabled users and wrong passwords SHALL receive the same safe invalid-credentials result. Shared expiring login limits SHALL apply across instances without a permanent account lockout or unbounded counter growth.

Usernames SHALL match `[a-z][a-z0-9._-]{2,63}` without silent normalization. Passwords SHALL contain 15-1,024 valid UTF-8 bytes, excluding NUL, CR and LF while preserving other whitespace. Encoded credential requests SHALL be bounded to 8 KiB independently of the decoded password limit, so permitted credentials remain usable across bootstrap, browser and CLI transports.

#### Scenario: Valid local credentials
- **WHEN** an enabled local user submits valid credentials to a ready installation
- **THEN** the system issues a new session and returns only the safe identity and the credentials appropriate to that transport

#### Scenario: Invalid or disabled account
- **WHEN** a login supplies a nonexistent username, a disabled user or an incorrect password
- **THEN** it fails with the same application-owned invalid-credentials response and does not disclose account existence

#### Scenario: Repeated or concurrent password attempts
- **WHEN** attempts exceed the documented shared failure limits or verification capacity
- **THEN** the server returns a bounded safe 429 response with retry guidance rather than allocating unbounded hashing work
- **AND** a replica change does not reset the shared failure counters

#### Scenario: A valid password requires maximum JSON escaping
- **WHEN** a valid maximum-length bootstrap password requires six encoded JSON bytes per decoded byte
- **THEN** CLI JSON login accepts its encoded representation while still enforcing the decoded password limit

### Requirement: Expiring server-side sessions

The server SHALL generate high-entropy opaque session tokens, persist only token digests, and distinguish browser from CLI sessions. Sessions SHALL have a fixed configured lifetime, defaulting to eight hours, without implicit renewal. Every protected request SHALL verify current database session validity and account state. A cached token or cached role SHALL NOT substitute for current authorization.

#### Scenario: Browser and CLI sessions coexist
- **WHEN** the same user signs in through both interfaces
- **THEN** independent, expiring sessions are created
- **AND** a browser token cannot authenticate a CLI bearer route or vice versa

#### Scenario: Expiry, revocation or disabled account
- **WHEN** a subsequent request uses an expired/revoked session or the account is disabled
- **THEN** it is denied without disclosing private session details

#### Scenario: Database outage after sign-in
- **WHEN** session validation storage becomes unavailable
- **THEN** protected requests fail safely rather than trusting a previously cached identity

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

The same server SHALL provide public setup and login documents, same-origin login/logout form actions and a minimal administrator-only page. Browser sessions SHALL use host-only HttpOnly cookies, SameSite protection and Secure cookies on HTTPS. Authentication tokens SHALL NOT appear in URLs, rendered HTML, JavaScript storage or application logs. Browser mutations SHALL reject absent, null, multiple or nonmatching configured Origin headers and cross-site Fetch Metadata. GET requests SHALL only validate existing credentials, never issue/rotate/revoke credentials or mutate accounts/sessions. Authentication documents SHALL reject framing.

#### Scenario: Browser sign-in and protected navigation
- **WHEN** a user signs in through the same-origin form
- **THEN** the server sets a fresh browser session cookie and redirects to the protected admin shell
- **AND** an unauthenticated navigation to that shell instead redirects to login

#### Scenario: An authenticated member opens administration
- **WHEN** a valid non-admin session requests the admin shell
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
- **THEN** the public document still renders without attempting database session validation

#### Scenario: Browser logout cannot confirm revocation
- **WHEN** a same-origin logout cannot confirm server-side revocation because storage is unavailable
- **THEN** the browser cookie is cleared and a safe 503 document distinguishes local sign-out from unconfirmed remote revocation

### Requirement: Explicit authentication transports

JSON authentication endpoints SHALL use the route, status and body contracts in the design. They SHALL never redirect to HTML, authenticate from browser cookies or expose arbitrary driver messages. Browser form routes SHALL NOT accept CLI bearer tokens. Credential transport SHALL require HTTPS outside literal loopback development; configured origin and TLS policy SHALL NOT be inferred from untrusted Host or forwarded headers. Authentication responses SHALL prevent caching.

Credential-processing and protected operations SHALL use a five-second context deadline covering body reads, database pool acquisition, queries, locks, session/event writes and response preparation. Cancellation SHALL propagate to database work, roll back incomplete transactions and prevent canceled work from issuing sessions. Non-cancelable password hashing SHALL remain within a fixed concurrency budget until completion. Public document and asset GETs SHALL be excluded from authentication/readiness middleware.

#### Scenario: A browser cookie reaches a JSON protected endpoint
- **WHEN** a JSON identity or administration request has only a browser cookie
- **THEN** it receives an unauthenticated JSON response rather than using ambient browser authentication

#### Scenario: Cross-origin JSON login or malformed body
- **WHEN** a request is cross-origin, form-encoded on a JSON route, oversized or contains undocumented JSON fields or trailing data
- **THEN** it is rejected safely without issuing a token or reflecting submitted values

#### Scenario: Production and local development transport
- **WHEN** a non-loopback installation is configured for authentication
- **THEN** it requires an explicit HTTPS public origin and documented protected TLS termination
- **AND** plaintext authentication is allowed only for the documented literal-loopback development case

#### Scenario: Authentication waits on a database lock
- **WHEN** a transaction lock blocks login, session validation or revocation past the operation deadline
- **THEN** the request returns safe unavailability within the bound, incomplete work rolls back and resources are released
- **AND** subsequent requests can succeed after the blocking transaction is released

### Requirement: Secret-free authentication events

The system SHALL persist safe bootstrap, sign-in and session-administration events, including denied/failed attempts when storage is available. Events SHALL contain only documented identifiers and outcome metadata, not submitted unknown usernames, passwords, session tokens/digests, cookies, request bodies or raw errors. Successful mutations and their events SHALL commit together. Storage failure SHALL NOT be represented as successful durable auditing.

Sign-in/logout/revocation rejections before service invocation SHALL use an explicit recorder with allowlisted action/outcome metadata and absent identifiers for anonymous requests. Service-owned outcomes SHALL NOT be recorded twice by the adapter. Valid-origin browser logout with no cookie or a single malformed cookie SHALL remain idempotent local cleanup without a database/audit dependency; rejected API mutations and ambiguous browser credentials SHALL NOT use that exemption.

#### Scenario: Successful or denied session administration
- **WHEN** a user attempts session revocation
- **THEN** the outcome is recorded with safe actor/target identifiers and an allowlisted action/result
- **AND** successful revocation is not committed without its event

#### Scenario: Authentication failure contains sensitive input
- **WHEN** a failed sign-in contains sentinel credentials or a dependency emits a raw error
- **THEN** neither authentication events nor operational output contain those values

#### Scenario: Bootstrap validation fails with usable storage
- **WHEN** a real bootstrap attempt rejects invalid inputs or unexpected users without an initialization marker
- **THEN** it records one safe anonymous bootstrap failure event without committing an administrator or initialized marker
- **AND** a later actual failed attempt records its own event; this milestone introduces no aggregation or retention policy

#### Scenario: Setup status is observed without a failed bootstrap attempt
- **WHEN** inputs are absent/incomplete, a read-only status request runs, or an already-initialized installation starts again
- **THEN** it does not manufacture failed-bootstrap events or read obsolete credentials

#### Scenario: Audit storage fails
- **WHEN** the required event cannot be persisted
- **THEN** no successful credential/session mutation is reported and output describes safe unavailability

#### Scenario: An authentication adapter rejects a request
- **WHEN** a sign-in or session-mutation request is rejected for invalid input, origin or API credentials before reaching the service and event storage is available
- **THEN** one safe rejection event is recorded without credential lookup or untrusted payload fields

#### Scenario: Idempotent local browser logout during an outage
- **WHEN** a valid-origin browser logout has no cookie or a single malformed cookie while the database is unavailable
- **THEN** the cookie is cleared and the browser is redirected to login without a database query or required event write

#### Scenario: Recording an origin rejection fails
- **WHEN** an invalid-origin mutation is rejected but its required event cannot be persisted
- **THEN** the response reports safe 503 without clearing cookies, revoking sessions or claiming durable auditing
