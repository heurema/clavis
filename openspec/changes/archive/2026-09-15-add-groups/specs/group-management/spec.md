## ADDED Requirements

### Requirement: Group records

A group SHALL have a random stable UUID, a unique name following the username grammar and never UUID-shaped, an optional description bounded like a connection description, and creation and update times. Groups SHALL be addressed by UUID or name, trying UUID syntax first; an unknown reference SHALL produce `GROUP_NOT_FOUND` with a hint. Creating a group whose name exists SHALL fail with `GROUP_EXISTS` and a hint. Update SHALL change only the supplied fields; renaming a group SHALL keep its memberships and grants, because both reference the group's UUID. Group records SHALL carry `id`, `name`, `description`, `createdAt`, `updatedAt`, the number of members and the number of grants the group holds. Listing SHALL be bounded to 1,000 groups ordered by name with a `truncated` flag and the listing byte budget.

#### Scenario: Create and read back
- **WHEN** an administrator creates `finance-managers` with a description
- **THEN** the record is committed with a UUID, zero members and zero grants, and `groups get` by UUID and by name return the same record

#### Scenario: Duplicate or malformed name
- **WHEN** creation names an existing group, a UUID-shaped name or a name outside the grammar
- **THEN** it fails with `GROUP_EXISTS` or `INVALID_ARGUMENT` and a hint, and nothing is written

#### Scenario: Rename keeps access
- **WHEN** a group with members and grants is renamed
- **THEN** its members still inherit the same connections and the grants list shows the new name
- **AND** renaming to a name another group holds fails with `GROUP_EXISTS` and changes nothing, including `updatedAt`

#### Scenario: Description bound and clearing
- **WHEN** a description of exactly 2,000 multibyte characters is submitted, then one of 2,001, then an empty string on update
- **THEN** the first is stored, the second fails with `INVALID_ARGUMENT` before any write, and the third clears the description

#### Scenario: Same name as a user
- **WHEN** a group is created with the name of an existing user and both receive a grant on one connection
- **THEN** both are created, the two grants are distinct, and `--user` and `--group` address each without ambiguity

### Requirement: Group membership

Adding a member SHALL link one user to one group, recording the time and the adding administrator's UUID, unique per pair and idempotent: adding an existing member SHALL return the membership unchanged with `added: false`, and removing a user who is not a member SHALL succeed with `removed: false`. Users SHALL be addressed by UUID or username. Memberships SHALL survive blocking and unblocking of the user and renaming of the user or group. Administrators MAY be members; membership has no effect on their access. Listing a group's members SHALL return each member's safe user record with the time they were added and the adding administrator's username, ordered by username, bounded to 1,000 with a `truncated` flag and the listing byte budget.

#### Scenario: Add and list
- **WHEN** an administrator adds `alice` to `finance-managers` by name and lists the members
- **THEN** the membership shows both UUIDs and names, the list contains alice's safe record with the added time and the administrator's username, and the group's member count is one

#### Scenario: Repeated add and remove
- **WHEN** the same member is added twice, then removed twice
- **THEN** the second add returns `added: false` with 200, the first removal reports `removed: true` and the second `removed: false`

#### Scenario: Unknown group or user
- **WHEN** a membership mutation names a group or user that does not exist
- **THEN** it fails with `GROUP_NOT_FOUND` or `USER_NOT_FOUND` and a hint, and nothing is written

#### Scenario: Blocked member keeps membership
- **WHEN** a member is blocked and later unblocked
- **THEN** the membership is unchanged and inherited access resumes without re-adding
- **AND** a blocked user can be added to a group, taking effect once unblocked

#### Scenario: Administrator member is demoted
- **WHEN** an administrator who belongs to a group with grants is demoted to member
- **THEN** their access is exactly what the group's grants and their direct grants confer, on their next request

### Requirement: Administrator-only group operations and guarded delete

Every group operation, including listing and reading, SHALL require a current administrator session rechecked inside the operation, following the transaction shape, deadline and readiness gate of user administration; members SHALL receive `FORBIDDEN` and no mutation. Every mutation SHALL support the dry run defined for connections. Delete SHALL succeed only when the group holds no grants, otherwise fail with `GROUP_IN_USE` and a hint stating how many grants remain; a successful delete SHALL remove the group's memberships with it and report the group's UUID and name. Deleting an unknown group SHALL fail with `GROUP_NOT_FOUND`.

#### Scenario: Guarded delete
- **WHEN** delete targets a group that still holds two grants
- **THEN** it fails with `GROUP_IN_USE`, the hint says to revoke the remaining grants and states two remain, and nothing is removed
- **AND** delete of a grant-free group with members removes the group and its memberships and reports its UUID and name
- **AND** a group created afterwards with the same name has no members and no grants

#### Scenario: Member attempts a group operation
- **WHEN** a member session lists, reads, creates, updates or deletes a group or changes membership
- **THEN** it is refused with `FORBIDDEN` and nothing changes

#### Scenario: Dry run
- **WHEN** any group mutation runs with `--dry-run`
- **THEN** it returns the outcome it would have had, including denials and guard failures, and commits nothing

### Requirement: Group routes

The server SHALL expose `GET /api/admin/groups`, `POST /api/admin/groups`, `GET /api/admin/groups/{groupID}`, `POST /api/admin/groups/{groupID}/update`, `POST /api/admin/groups/{groupID}/delete`, `GET /api/admin/groups/{groupID}/members`, `POST /api/admin/groups/{groupID}/members/add` and `POST /api/admin/groups/{groupID}/members/remove` for CLI bearer sessions with the transport rules of the connection routes, including dry runs and hints, where `{groupID}` is a UUID or a name. Create SHALL answer 201; an idempotent add SHALL answer 201 when the membership was created and 200 when it existed or on a dry run.

#### Scenario: Create through the API
- **WHEN** an administrator's bearer request posts a valid group body
- **THEN** the response is 201 with the group record and no undocumented field

#### Scenario: Browser cookie on a group route
- **WHEN** a group request carries only a browser session cookie
- **THEN** it receives an unauthenticated JSON response and no mutation occurs

### Requirement: Read-only groups table in the browser

The administration shell SHALL provide a Groups page at `/admin/groups` that lists groups with name, description, member count, grant count and creation time in UTC, escaped and bounded like the other tables, with a truncation notice and no forms. The sidebar entry SHALL show the number of listed groups, suffixed with `+` when truncated. The page SHALL fail closed when the list cannot be loaded.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests `/admin/groups`
- **THEN** the groups table renders with the documented columns and the Groups entry is marked current

#### Scenario: Group list unavailable
- **WHEN** the group listing fails
- **THEN** the page returns safe 503 rather than rendering without current data
