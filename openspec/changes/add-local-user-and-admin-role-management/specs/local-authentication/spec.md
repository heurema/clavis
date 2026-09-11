## MODIFIED Requirements

### Requirement: Protected browser authentication

The same server SHALL provide public setup and login documents, same-origin login/logout form actions and a minimal administrator-only page. Browser sessions SHALL use host-only HttpOnly cookies, SameSite protection and Secure cookies on HTTPS. Authentication tokens SHALL NOT appear in URLs, rendered HTML, JavaScript storage or application logs. Browser mutations SHALL reject absent, null, multiple or nonmatching configured Origin headers and cross-site Fetch Metadata. GET requests SHALL only validate existing credentials, never issue/rotate/revoke credentials or mutate accounts/sessions. Authentication documents SHALL reject framing. The administrator page SHALL include the read-only bounded user list defined by user-administration and SHALL fail closed when that list cannot be loaded.

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

#### Scenario: Administrator page cannot load the user list
- **WHEN** an administrator's valid session requests the admin shell but the user list query fails or times out
- **THEN** the server returns safe 503 rather than rendering the page without current data

### Requirement: Secret-free authentication events

The system SHALL persist safe bootstrap, sign-in, session-administration and user-administration events, including denied/failed attempts when storage is available. Events SHALL contain only documented identifiers and outcome metadata, not submitted unknown usernames, passwords, password hashes, session tokens/digests, cookies, request bodies or raw errors. Successful mutations and their events SHALL commit together. Storage failure SHALL NOT be represented as successful durable auditing.

The event action allowlist SHALL be `bootstrap`, `login`, `logout`, `revoke`, `user.create`, `user.block`, `user.unblock`, `user.reset_password`, `user.promote`, `user.demote` and `users.list`. The outcome allowlist SHALL add `username_taken` and `last_administrator` to the existing outcomes. Extending either allowlist SHALL use a new forward Goose migration that replaces the check constraints without rewriting applied migrations or existing rows. User-administration events SHALL record the actor UUID, the actor's session UUID and the target user UUID when known; a created user's UUID SHALL be the target of its creation event.

Sign-in/logout/revocation rejections before service invocation SHALL use an explicit recorder with allowlisted action/outcome metadata and absent identifiers for anonymous requests. Service-owned outcomes SHALL NOT be recorded twice by the adapter. Valid-origin browser logout with no cookie or a single malformed cookie SHALL remain idempotent local cleanup without a database/audit dependency; rejected API mutations and ambiguous browser credentials SHALL NOT use that exemption.

#### Scenario: Successful or denied session administration
- **WHEN** a user attempts session revocation
- **THEN** the outcome is recorded with safe actor/target identifiers and an allowlisted action/result
- **AND** successful revocation is not committed without its event

#### Scenario: Successful or denied user administration
- **WHEN** a user attempts to create, block, unblock, reset the password of or change the role of a user, or to list users
- **THEN** the outcome is recorded with the actor, actor session and target identifiers when known, using the allowlisted action/outcome
- **AND** a successful mutation is not committed without its event and a successful listing records no event

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

#### Scenario: Event schema is extended on an initialized installation
- **WHEN** a server with the extended event allowlist starts against a database migrated by the previous release
- **THEN** the new forward migration applies once under the shared lock, existing event rows are unchanged and readiness succeeds
