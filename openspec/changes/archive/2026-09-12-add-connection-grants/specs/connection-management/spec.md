## MODIFIED Requirements

### Requirement: Administrator-only connection operations

Creating, updating, replacing credentials, enabling, disabling, deleting and checking connections SHALL require a current administrator session rechecked inside the operation, following the transaction shape, deadline, readiness gate and denial-event rules of user administration. Members SHALL receive `FORBIDDEN` with a denial event and no mutation for those operations. Listing and getting connections SHALL be available to administrators in full and to members in the reduced projection defined by connection-grants. Update SHALL change only the supplied fields. Replacing credentials SHALL clear the last check result. Disabling SHALL be idempotent. Delete SHALL succeed only when the connection is disabled and holds no grants, otherwise fail with `CONNECTION_IN_USE` and a hint naming the blocking condition, including the number of remaining grants. Every mutation SHALL support a dry run that performs validation, authorization and guards inside a transaction that is rolled back, returning the same result shape marked `dryRun: true` and recording no event. Listing SHALL be bounded to 1,000 connections ordered by name with a `truncated` flag, SHALL support label selectors with equality, inequality and existence terms combined with AND, and SHALL record no success event. Getting one connection SHALL likewise record no success event; denied administrative list and get attempts SHALL be recorded as `connections.list` and `connection.get` respectively, and an unknown reference on get SHALL fail with `CONNECTION_NOT_FOUND` without an event.

#### Scenario: Update a subset of fields
- **WHEN** an administrator updates only the statement timeout
- **THEN** every other field, the credentials and the last check are unchanged and one `connection.update` event is recorded

#### Scenario: Guarded delete
- **WHEN** delete targets an enabled connection, or a disabled one that still has grants
- **THEN** it fails with `CONNECTION_IN_USE`, the hint says to disable it or revoke its remaining grants and states how many remain, and nothing is removed
- **AND** delete of a disabled, grant-free connection removes the row and records `connection.delete` with the UUID and name

#### Scenario: Dry run
- **WHEN** any mutation runs with `--dry-run`
- **THEN** it returns the outcome it would have had, including denials and guard failures, commits nothing and records no event

#### Scenario: Filter by selector
- **WHEN** an administrator lists with `env=prod,service!=legacy,team`
- **THEN** only connections carrying `env=prod`, not carrying `service=legacy`, and having any `team` label are returned in name order

#### Scenario: Member attempts a mutation or a check
- **WHEN** a member session invokes create, update, credential replacement, enable, disable, delete or check
- **THEN** it is refused with `FORBIDDEN`, a denial event is recorded and nothing changes

### Requirement: JSON connection routes

The server SHALL expose the operations as JSON routes under `/api/admin/connections` for CLI bearer sessions only, following the transport rules of the user-administration routes: bearer-only sessions, configured-origin check, strict bounded JSON bodies, no cookies, no redirects, `Cache-Control: no-store`, adapter-recorded pre-service rejections and service-owned outcomes. The two `GET` routes SHALL accept member sessions and return the reduced projection; every other route SHALL remain administrator-only. Error bodies MAY carry an optional `hint` string alongside `code` and `message`; hints SHALL be application-owned text and never echo submitted values. Secrets SHALL arrive only in request bodies for create and credential replacement and SHALL be bounded like passwords. Dry runs SHALL be requested with a documented query parameter. The listing response SHALL stay under the listing body limit shared with users.

#### Scenario: Create through the API
- **WHEN** an administrator's bearer request posts a valid connection body
- **THEN** the response is 201 with the record and no secret field

#### Scenario: Error with hint
- **WHEN** a request fails with `CONNECTION_EXISTS`, `CONNECTION_IN_USE`, `INVALID_ARGUMENT` or `CONNECTION_NOT_FOUND`
- **THEN** the error object carries `code`, `message` and a `hint` that names the next action or valid values without reflecting submitted data

#### Scenario: Cookie on a connection route
- **WHEN** a connection request carries only a browser session cookie
- **THEN** it receives an unauthenticated JSON response and no mutation occurs

#### Scenario: Member reads through the API
- **WHEN** a member's bearer request lists or gets connections
- **THEN** the response contains only granted connections in the reduced projection, and a `POST` on any connection route with the same session is 403
