# connection-grants Specification

## Purpose

Let administrators grant connections to users, let members discover what they may use, and give every later operation one authoritative answer to "may this user use this connection now".

## Requirements

### Requirement: Grant records

A grant SHALL link one user to one connection, with the creation time and the UUID of the granting administrator, unique per pair, without expiry. Grants SHALL reference UUIDs so renaming a user or connection never changes access. Creating a grant SHALL require a current administrator session rechecked inside the operation and SHALL address the user by UUID or username and the connection by UUID or name. Creating a grant that already exists SHALL return the existing grant without a new event. Revoking a grant that does not exist SHALL succeed, report `revoked: false` and record no event. Grants SHALL survive blocking and unblocking of the user. Results SHALL carry the user's `id` and `username` and the connection's `id` and `name`. Every mutation SHALL support the dry run defined for connections.

#### Scenario: Grant and read back
- **WHEN** an administrator grants `payments-prod-reporting` to `alice` by name
- **THEN** the grant is committed with both UUIDs and the actor's UUID, a `grant.create` event records the actor, session, user and connection, and the result shows both identifiers and names

#### Scenario: Repeated grant and revoke
- **WHEN** the same grant is created twice, then revoked twice
- **THEN** the second creation returns the existing grant with 200 and no event, the first revocation deletes it with a `grant.revoke` event, and the second reports `revoked: false` with no event

#### Scenario: Unknown user or connection
- **WHEN** a grant names a user or connection that does not exist
- **THEN** it fails with `USER_NOT_FOUND` or `CONNECTION_NOT_FOUND` and a hint, and nothing is written

#### Scenario: Blocked user keeps grants
- **WHEN** a granted user is blocked and later unblocked
- **THEN** the grant is unchanged and access resumes without re-granting

### Requirement: Member visibility of granted connections

Listing and getting connections SHALL be available to members for the connections they hold a grant on, in the reduced projection `id`, `name`, `title`, `description`, `scope`, `provider`, `labels`, `enabled` and `lastCheck`, never target settings, resource bounds or secrets. Connections without a grant SHALL be absent from a member's listing and SHALL produce `CONNECTION_NOT_FOUND` on get, so their existence is not disclosed. Disabled connections with a grant SHALL be listed with `enabled: false`. Selectors, ordering and bounds SHALL behave as for administrators. Member reads SHALL record no event on success; a member's denied `get` SHALL record no event either.

#### Scenario: Member lists connections
- **WHEN** a member with two grants lists connections with a selector matching one of them
- **THEN** exactly that connection is returned in the reduced projection and no target, bound or secret field is present

#### Scenario: Member asks for an ungranted connection
- **WHEN** a member gets a connection they hold no grant on
- **THEN** the response is `CONNECTION_NOT_FOUND`, identical to a nonexistent connection, and no event is recorded

#### Scenario: Grant revoked mid-session
- **WHEN** a member's grant is revoked while their session is valid
- **THEN** their next listing omits the connection and their next get fails with `CONNECTION_NOT_FOUND`

### Requirement: Per-request connection authorization

The system SHALL provide one authorization operation that, for a session and a connection reference, rechecks the session and current role, loads the connection and returns it only if the connection is enabled and the caller is an administrator or holds a grant. It SHALL fail with `CONNECTION_NOT_FOUND` for a member without a grant or an unknown reference, and with `CONNECTION_DISABLED` and a hint to contact an administrator for a disabled connection the caller may otherwise use. Administrators SHALL NOT need a grant. Successful authorization SHALL record no event of its own. Every later operation that forwards a request to an external source SHALL call this operation first and SHALL NOT contact the source when it fails.

#### Scenario: Member with a grant on an enabled connection
- **WHEN** authorization runs for a member holding a grant on an enabled connection
- **THEN** it returns the connection and records nothing

#### Scenario: Disabled connection
- **WHEN** authorization runs for a granted member or an administrator on a disabled connection
- **THEN** it fails with `CONNECTION_DISABLED` and a hint, and no source is contacted

#### Scenario: Grant removed before the request
- **WHEN** a grant is revoked and the member's session then requests authorization
- **THEN** it fails with `CONNECTION_NOT_FOUND` despite the valid session

### Requirement: Grant routes and listing

The server SHALL expose `GET /api/admin/grants`, `POST /api/admin/grants` and `POST /api/admin/grants/revoke` for CLI bearer sessions with the transport rules of the connection routes, including dry runs and hints. Administrators SHALL list every grant, filterable by user and by connection; members SHALL list only their own grants and SHALL receive `FORBIDDEN` with a denial event for create and revoke. Listing SHALL be bounded to 1,000 grants ordered by username then connection name with a `truncated` flag and the listing byte budget, and SHALL record no success event. `GET /api/auth/whoami` SHALL include the names of the caller's granted connections in name order, bounded to 1,000 with a `truncated` flag; for administrators the list SHALL be empty and `truncated` false, since administrators need no grants.

#### Scenario: Create through the API
- **WHEN** an administrator's bearer request posts a valid grant body with a username and a connection name
- **THEN** the response is 201 with the grant, or 200 when it already existed

#### Scenario: Member lists grants
- **WHEN** a member lists grants
- **THEN** only their own grants are returned and no event is recorded

#### Scenario: Identity reports usable connections
- **WHEN** a member calls `whoami`
- **THEN** the response lists the names of connections they hold a grant on

### Requirement: Read-only grants table in the browser

The protected administrator page SHALL list grants with username, connection name, granted time in UTC and the granting administrator's username, escaped and bounded like the other tables, with a truncation notice and no forms. It SHALL fail closed when the list cannot be loaded.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests the administration page
- **THEN** the grants table renders below the connections table with the documented columns

#### Scenario: Grant list unavailable
- **WHEN** the grant listing fails
- **THEN** the page returns safe 503 rather than rendering without current data
