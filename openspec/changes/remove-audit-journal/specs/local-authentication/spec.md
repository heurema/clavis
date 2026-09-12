## MODIFIED Requirements

### Requirement: Explicit authentication transports

JSON authentication endpoints SHALL use the route, status and body contracts in the design. They SHALL never redirect to HTML, authenticate from browser cookies or expose arbitrary driver messages. Browser form routes SHALL NOT accept CLI bearer tokens. Credential transport SHALL require HTTPS outside literal loopback development; configured origin and TLS policy SHALL NOT be inferred from untrusted Host or forwarded headers. Authentication responses SHALL prevent caching.

Credential-processing and protected operations SHALL use a five-second context deadline covering body reads, database pool acquisition, queries, locks, session writes and response preparation. Cancellation SHALL propagate to database work, roll back incomplete transactions and prevent canceled work from issuing sessions. Non-cancelable password hashing SHALL remain within a fixed concurrency budget until completion. Public document and asset GETs SHALL be excluded from authentication/readiness middleware.

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

## REMOVED Requirements

### Requirement: Secret-free authentication events

**Reason**: The owner removed the audit journal from the MVP on 2026-09-12 (PRD 7.7). No operation, administrative change, sign-in or denied attempt is recorded; a persistent journal is a later stage.

**Migration**: A forward migration drops the `auth_events` table; the event contracts, queries, recorder boundary and denial-event helpers are deleted; every mutation keeps its transaction shape, codes and guards and simply commits without an event. Nothing replaces the journal in the MVP.
