## MODIFIED Requirements

### Requirement: Secret-free authentication events

The system SHALL persist safe bootstrap, sign-in, session-administration, user-administration and connection-management events, including denied/failed attempts when storage is available. Events SHALL contain only documented identifiers and outcome metadata, not submitted unknown usernames, passwords, password hashes, connection secrets, target hosts, session tokens/digests, cookies, request bodies or raw errors. Successful mutations and their events SHALL commit together. Storage failure SHALL NOT be represented as successful durable auditing.

The event action allowlist SHALL be `bootstrap`, `login`, `logout`, `revoke`, `user.create`, `user.block`, `user.unblock`, `user.reset_password`, `user.promote`, `user.demote`, `users.list`, `connection.create`, `connection.update`, `connection.set_credentials`, `connection.enable`, `connection.disable`, `connection.delete`, `connection.check`, `connection.get` and `connections.list`. The outcome allowlist SHALL add `connection_exists`, `connection_not_found`, `connection_in_use`, `credentials_unavailable` and `check_failed` to the existing outcomes. Extending either allowlist SHALL use a new forward Goose migration that replaces the check constraints without rewriting applied migrations or existing rows. User-administration events SHALL record the actor UUID, the actor's session UUID and the target user UUID when known; a created user's UUID SHALL be the target of its creation event. Connection events SHALL record the actor UUID, the actor's session UUID and the connection UUID as the target when known; a created connection's UUID SHALL be the target of its creation event. Dry runs SHALL record no event.

Sign-in/logout/revocation rejections before service invocation SHALL use an explicit recorder with allowlisted action/outcome metadata and absent identifiers for anonymous requests. Service-owned outcomes SHALL NOT be recorded twice by the adapter. Valid-origin browser logout with no cookie or a single malformed cookie SHALL remain idempotent local cleanup without a database/audit dependency; rejected API mutations and ambiguous browser credentials SHALL NOT use that exemption.

#### Scenario: Successful or denied session administration
- **WHEN** a user attempts session revocation
- **THEN** the outcome is recorded with safe actor/target identifiers and an allowlisted action/result
- **AND** successful revocation is not committed without its event

#### Scenario: Successful or denied user administration
- **WHEN** a user attempts to create, block, unblock, reset the password of or change the role of a user, or to list users
- **THEN** the outcome is recorded with the actor, actor session and target identifiers when known, using the allowlisted action/outcome
- **AND** a successful mutation is not committed without its event and a successful listing records no event

#### Scenario: Successful or denied connection management
- **WHEN** a user attempts to create, update, re-credential, enable, disable, delete or check a connection, or to list connections
- **THEN** the outcome is recorded with the actor, actor session and connection identifiers when known, using the allowlisted action/outcome
- **AND** a successful mutation is not committed without its event, a successful listing records no event, and no event contains a secret or a target host

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
