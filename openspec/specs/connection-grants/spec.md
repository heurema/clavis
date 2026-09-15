# connection-grants Specification

## Purpose

Let administrators grant connections to users, let members discover what they may use, and give every later operation one authoritative answer to "may this user use this connection now".

## Requirements

### Requirement: Grant records

A grant SHALL link one recipient, a user or a group, to one connection, with the creation time and the UUID of the granting administrator, unique per recipient and connection pair, without expiry. Grants SHALL reference UUIDs so renaming a user, group or connection never changes access. Creating a grant SHALL require a current administrator session rechecked inside the operation and SHALL address the user by UUID or username, the group by UUID or name and the connection by UUID or name; a request SHALL name exactly one of a user or a group, otherwise fail with `INVALID_ARGUMENT` and a hint. Creating a grant that already exists SHALL return the existing grant unchanged. Revoking a grant that does not exist SHALL succeed and report `revoked: false`. Grants SHALL survive blocking and unblocking of a user. Results SHALL carry a `recipient` with `kind` (`user` or `group`), `id` and `name`, and the connection's `id` and `name`. Every mutation SHALL support the dry run defined for connections.

#### Scenario: Grant and read back
- **WHEN** an administrator grants `payments-prod-reporting` to `alice` by name
- **THEN** the grant is committed with both UUIDs and the actor's UUID, and the result shows a `user` recipient with both identifiers and names

#### Scenario: Grant to a group
- **WHEN** an administrator grants `payments-prod-reporting` to the group `finance-managers`
- **THEN** the grant is committed with the group's UUID, the result shows a `group` recipient, and a direct grant to a member of that group on the same connection remains a distinct grant

#### Scenario: Repeated grant and revoke
- **WHEN** the same grant is created twice, then revoked twice
- **THEN** the second creation returns the existing grant with 200, the first revocation deletes it, and the second reports `revoked: false`

#### Scenario: Unknown or ambiguous recipient
- **WHEN** a grant names a user, group or connection that does not exist, or names both a user and a group
- **THEN** it fails with `USER_NOT_FOUND`, `GROUP_NOT_FOUND`, `CONNECTION_NOT_FOUND` or `INVALID_ARGUMENT` and a hint, and nothing is written

#### Scenario: Blocked user keeps grants
- **WHEN** a granted user is blocked and later unblocked
- **THEN** the grant is unchanged and access resumes without re-granting

### Requirement: Member visibility of granted connections

Listing and getting connections SHALL be available to members for the connections they effectively hold, where effective access is the union of the member's direct grants and the grants of every group they belong to, in the reduced projection `id`, `name`, `title`, `description`, `scope`, `provider`, `labels`, `enabled` and `lastCheck`, never target settings, resource bounds or secrets. A connection reached through more than one path SHALL appear once. Connections outside the member's effective access SHALL be absent from a member's listing and SHALL produce `CONNECTION_NOT_FOUND` on get, so their existence is not disclosed. Disabled connections within effective access SHALL be listed with `enabled: false`. Selectors, ordering and bounds SHALL behave as for administrators.

#### Scenario: Member lists connections
- **WHEN** a member with one direct grant and one group grant lists connections with a selector matching the group-granted one
- **THEN** exactly that connection is returned in the reduced projection and no target, bound or secret field is present

#### Scenario: Same connection through two paths
- **WHEN** a member holds a direct grant and a group grant on the same connection
- **THEN** the listing shows it once, and revoking the direct grant leaves it listed

#### Scenario: Member asks for an ungranted connection
- **WHEN** a member gets a connection outside their effective access
- **THEN** the response is `CONNECTION_NOT_FOUND`, identical to a nonexistent connection

#### Scenario: Membership removed mid-session
- **WHEN** a member's only path to a connection is a group and they are removed from the group while their session is valid
- **THEN** their next listing omits the connection and their next get fails with `CONNECTION_NOT_FOUND`

### Requirement: Per-request connection authorization

The system SHALL provide one authorization operation that, for a session and a connection reference, rechecks the session and current role, loads the connection and returns it only if the connection is enabled and the caller is an administrator or holds effective access through a direct grant or a group membership. It SHALL fail with `CONNECTION_NOT_FOUND` for a member without effective access or an unknown reference, and with `CONNECTION_DISABLED` and a hint to contact an administrator for a disabled connection the caller may otherwise use. Administrators SHALL NOT need a grant or a membership. Every later operation that forwards a request to an external source SHALL call this operation first and SHALL NOT contact the source when it fails.

#### Scenario: Member with a group grant on an enabled connection
- **WHEN** authorization runs for a member whose only path to an enabled connection is a group grant
- **THEN** it returns the connection

#### Scenario: Disabled connection
- **WHEN** authorization runs for a member with effective access or an administrator on a disabled connection
- **THEN** it fails with `CONNECTION_DISABLED` and a hint, and no source is contacted

#### Scenario: Last path removed before the request
- **WHEN** a member's only remaining path to a connection is removed, by revoking that grant or by leaving that group, and the member's session then requests authorization
- **THEN** it fails with `CONNECTION_NOT_FOUND` despite the valid session, and no source is contacted

#### Scenario: One of several paths removed
- **WHEN** a member reaches a connection through a direct grant and a group, or through two groups, and one of those paths is removed
- **THEN** authorization still returns the connection, and only removing the last path denies it

#### Scenario: Direct grant revoked before the request
- **WHEN** a member with a direct grant and no membership has that grant revoked and then requests authorization
- **THEN** it fails with `CONNECTION_NOT_FOUND` despite the valid session

### Requirement: Grant routes and listing

The server SHALL expose `GET /api/admin/grants`, `POST /api/admin/grants`, `POST /api/admin/grants/revoke` and `GET /api/admin/grants/effective` for CLI bearer sessions with the transport rules of the connection routes, including dry runs and hints. Administrators SHALL list every grant, filterable by user, by group and by connection; members SHALL list only their own direct grants, SHALL receive `FORBIDDEN` for a `group` filter before any group lookup, and SHALL receive `FORBIDDEN` for create and revoke. An unknown filter reference SHALL yield an empty list. The grant listing SHALL be bounded to 1,000 grants ordered by recipient kind, recipient name then connection name with a `truncated` flag and the listing byte budget.

The effective listing SHALL report grant paths, not usability: it SHALL take an optional user reference and an optional connection filter, and the server SHALL resolve the subject after rechecking the session, defaulting an omitted user to the caller for members, refusing any other user for members with `FORBIDDEN`, and refusing an omitted user for administrators with `INVALID_ARGUMENT` and a hint. It SHALL return the subject's safe user record (`id`, `username`, `role`, `disabled`) and one entry per connection and path, each carrying the connection's `id` and `name`, a `source` of `direct` or `group`, the group's `id` and `name` when the source is a group, and the grant's creation time, ordered by connection name then source then group name, bounded to 1,000 with a `truncated` flag and the listing byte budget. An administrator subject SHALL show zero entries unless grants name them, because their access does not come from grants; a blocked or disabled state SHALL be visible on the record rather than change the entries; whether the subject can use a connection now is answered only by the authorization operation.

`GET /api/auth/whoami` SHALL include the names of the caller's effectively accessible connections, each once, in name order, bounded to 1,000 with `connectionsTruncated`, and the names of the caller's groups in name order, bounded to 1,000 with a separate `groupsTruncated` flag; for administrators the connection list SHALL be empty and `connectionsTruncated` false, since administrators need no grants, while their group names SHALL still be reported.

#### Scenario: Create through the API
- **WHEN** an administrator's bearer request posts a valid grant body with a group name and a connection name
- **THEN** the response is 201 with the grant, or 200 when it already existed

#### Scenario: Member lists grants
- **WHEN** a member lists grants
- **THEN** only their own direct grants are returned

#### Scenario: Administrator inspects grant paths
- **WHEN** an administrator requests the effective listing for a member who holds a direct grant and a group grant on the same connection and another connection through a second group
- **THEN** the member's record and three entries are returned in connection order, one `direct`, two `group` with their group names, and revoking the direct grant leaves two

#### Scenario: Administrator as subject
- **WHEN** the effective listing names an administrator who holds no grants but belongs to a group with grants
- **THEN** the record shows `role: admin` and the group entries are listed, and after that administrator is demoted the same entries describe the access they now inherit

#### Scenario: Member inspects their own paths
- **WHEN** a member requests the effective listing without a user, or naming themselves by UUID or username
- **THEN** their own record and paths are returned, and naming any other user answers `FORBIDDEN`

#### Scenario: Member filters grants by group
- **WHEN** a member lists grants with a group filter, existing or not
- **THEN** the response is `FORBIDDEN` and no group is looked up

#### Scenario: Identity reports usable connections and groups
- **WHEN** a member of two groups calls `whoami`
- **THEN** the response lists the names of every connection they can effectively use, each once, and the two group names, with independent truncation flags

### Requirement: Read-only grants table in the browser

The administration shell SHALL provide a Grants page at `/admin/grants` that lists grants with the recipient kind and name, connection name, granted time in UTC and the granting administrator's username, escaped and bounded like the other tables, with a truncation notice and no forms. The sidebar entry SHALL show the number of listed grants, suffixed with `+` when truncated. The page SHALL fail closed when the list cannot be loaded.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests `/admin/grants`
- **THEN** the grants table renders with the documented columns, a group grant is distinguishable from a user grant, and the Grants entry is marked current

#### Scenario: Grant list unavailable
- **WHEN** the grant listing fails
- **THEN** the page returns safe 503 rather than rendering without current data
