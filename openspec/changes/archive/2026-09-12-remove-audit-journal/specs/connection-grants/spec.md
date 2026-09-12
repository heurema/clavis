## MODIFIED Requirements

### Requirement: Grant records

A grant SHALL link one user to one connection, with the creation time and the UUID of the granting administrator, unique per pair, without expiry. Grants SHALL reference UUIDs so renaming a user or connection never changes access. Creating a grant SHALL require a current administrator session rechecked inside the operation and SHALL address the user by UUID or username and the connection by UUID or name. Creating a grant that already exists SHALL return the existing grant unchanged. Revoking a grant that does not exist SHALL succeed and report `revoked: false`. Grants SHALL survive blocking and unblocking of the user. Results SHALL carry the user's `id` and `username` and the connection's `id` and `name`. Every mutation SHALL support the dry run defined for connections.

#### Scenario: Grant and read back
- **WHEN** an administrator grants `payments-prod-reporting` to `alice` by name
- **THEN** the grant is committed with both UUIDs and the actor's UUID, and the result shows both identifiers and names

#### Scenario: Repeated grant and revoke
- **WHEN** the same grant is created twice, then revoked twice
- **THEN** the second creation returns the existing grant with 200, the first revocation deletes it, and the second reports `revoked: false`

#### Scenario: Unknown user or connection
- **WHEN** a grant names a user or connection that does not exist
- **THEN** it fails with `USER_NOT_FOUND` or `CONNECTION_NOT_FOUND` and a hint, and nothing is written

#### Scenario: Blocked user keeps grants
- **WHEN** a granted user is blocked and later unblocked
- **THEN** the grant is unchanged and access resumes without re-granting

### Requirement: Member visibility of granted connections

Listing and getting connections SHALL be available to members for the connections they hold a grant on, in the reduced projection `id`, `name`, `title`, `description`, `scope`, `provider`, `labels`, `enabled` and `lastCheck`, never target settings, resource bounds or secrets. Connections without a grant SHALL be absent from a member's listing and SHALL produce `CONNECTION_NOT_FOUND` on get, so their existence is not disclosed. Disabled connections with a grant SHALL be listed with `enabled: false`. Selectors, ordering and bounds SHALL behave as for administrators.

#### Scenario: Member lists connections
- **WHEN** a member with two grants lists connections with a selector matching one of them
- **THEN** exactly that connection is returned in the reduced projection and no target, bound or secret field is present

#### Scenario: Member asks for an ungranted connection
- **WHEN** a member gets a connection they hold no grant on
- **THEN** the response is `CONNECTION_NOT_FOUND`, identical to a nonexistent connection

#### Scenario: Grant revoked mid-session
- **WHEN** a member's grant is revoked while their session is valid
- **THEN** their next listing omits the connection and their next get fails with `CONNECTION_NOT_FOUND`

### Requirement: Per-request connection authorization

The system SHALL provide one authorization operation that, for a session and a connection reference, rechecks the session and current role, loads the connection and returns it only if the connection is enabled and the caller is an administrator or holds a grant. It SHALL fail with `CONNECTION_NOT_FOUND` for a member without a grant or an unknown reference, and with `CONNECTION_DISABLED` and a hint to contact an administrator for a disabled connection the caller may otherwise use. Administrators SHALL NOT need a grant. Every later operation that forwards a request to an external source SHALL call this operation first and SHALL NOT contact the source when it fails.

#### Scenario: Member with a grant on an enabled connection
- **WHEN** authorization runs for a member holding a grant on an enabled connection
- **THEN** it returns the connection

#### Scenario: Disabled connection
- **WHEN** authorization runs for a granted member or an administrator on a disabled connection
- **THEN** it fails with `CONNECTION_DISABLED` and a hint, and no source is contacted

#### Scenario: Grant removed before the request
- **WHEN** a grant is revoked and the member's session then requests authorization
- **THEN** it fails with `CONNECTION_NOT_FOUND` despite the valid session

### Requirement: Grant routes and listing

The server SHALL expose `GET /api/admin/grants`, `POST /api/admin/grants` and `POST /api/admin/grants/revoke` for CLI bearer sessions with the transport rules of the connection routes, including dry runs and hints. Administrators SHALL list every grant, filterable by user and by connection; members SHALL list only their own grants and SHALL receive `FORBIDDEN` for create and revoke. Listing SHALL be bounded to 1,000 grants ordered by username then connection name with a `truncated` flag and the listing byte budget. `GET /api/auth/whoami` SHALL include the names of the caller's granted connections in name order, bounded to 1,000 with a `truncated` flag; for administrators the list SHALL be empty and `truncated` false, since administrators need no grants.

#### Scenario: Create through the API
- **WHEN** an administrator's bearer request posts a valid grant body with a username and a connection name
- **THEN** the response is 201 with the grant, or 200 when it already existed

#### Scenario: Member lists grants
- **WHEN** a member lists grants
- **THEN** only their own grants are returned

#### Scenario: Identity reports usable connections
- **WHEN** a member calls `whoami`
- **THEN** the response lists the names of connections they hold a grant on
