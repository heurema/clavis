# user-administration Specification

## Purpose

Let current administrators manage local user accounts and the administrator role through audited, transactional operations that never lock the installation out or expose secrets.

## Requirements

### Requirement: Administrator-only user operations

The system SHALL provide user-administration operations for listing users, creating a local user, blocking and unblocking a user, resetting a user's local password and setting a user's role to `admin` or `member`. Every operation SHALL recheck the actor's current session and current `admin` role inside its own transaction before reading or mutating accounts; a cached role SHALL NOT substitute for the current one. Members SHALL receive a safe forbidden result without any mutation. Operations SHALL use the same five-second operation deadline, readiness gate and fail-closed behavior as authentication.

Created users SHALL have the `member` role, a random stable UUID, the submitted username and only a salted versioned Argon2id password hash. Usernames and passwords SHALL follow the local-authentication rules without normalization, and a username SHALL NOT be UUID-shaped, so that a user reference is never ambiguous. A username that already exists SHALL produce a safe `USERNAME_TAKEN` result without disclosing other account details. Targets SHALL be addressed by user UUID or by username, trying UUID syntax first; an unknown reference SHALL produce `USER_NOT_FOUND`. There is no distinguished root account: the bootstrap administrator is an ordinary administrator once initialization completes.

#### Scenario: Administrator creates a member
- **WHEN** a current administrator creates a user with a valid username and password
- **THEN** the account is committed with the `member` role and an enabled state
- **AND** the new user can sign in through the browser and CLI with that password after the operation returns

#### Scenario: Duplicate username
- **WHEN** creation is attempted with a username that already exists in any case-exact form
- **THEN** the operation fails with `USERNAME_TAKEN` and no account or hash is written

#### Scenario: UUID-shaped username
- **WHEN** creation or bootstrap supplies a username matching the UUID pattern
- **THEN** it fails with `INVALID_ARGUMENT` and a hint, and nothing is written

#### Scenario: Address a user by username
- **WHEN** an administrator blocks a user by username
- **THEN** the same account is affected as when addressed by UUID, and the result carries both

#### Scenario: A member attempts administration
- **WHEN** a valid session whose current role is `member` invokes any user-administration operation, including listing
- **THEN** the operation returns a forbidden result, records a denied event and performs no mutation

#### Scenario: Role removed before the request
- **WHEN** an administrator's role is changed to `member` by another administrator before their next administrative request is authorized
- **THEN** that request is forbidden despite the previously issued session

#### Scenario: Administration during a database outage
- **WHEN** account storage is unavailable
- **THEN** every operation returns safe unavailability without reporting a mutation

### Requirement: Blocking and password reset revoke sessions

Blocking a user SHALL set the account disabled and revoke all of that user's existing browser and CLI sessions in the same transaction. Resetting a password SHALL replace the stored hash and revoke all existing sessions in the same transaction. Unblocking SHALL re-enable the account without restoring revoked sessions. Session issuance, revocation and these mutations SHALL serialize on the target user row so a login committed before the mutation is revoked and a login committed afterward is a new session evaluated against the new state. Blocking or unblocking an already blocked or enabled user SHALL succeed idempotently and still record an event. An administrator SHALL NOT block their own account; such a request SHALL fail with `SELF_TARGET` without mutation. An administrator MAY reset their own password.

#### Scenario: Block a signed-in user
- **WHEN** an administrator blocks a user with active browser and CLI sessions
- **THEN** subsequent requests with those sessions are denied
- **AND** a later login for that user fails with the generic invalid-credentials result

#### Scenario: Unblock a user
- **WHEN** an administrator unblocks a blocked user
- **THEN** the user can sign in again with the existing password
- **AND** sessions revoked by the block remain unusable

#### Scenario: Reset a password
- **WHEN** an administrator resets a user's password with a valid new password
- **THEN** the old password no longer signs in, the new password does, and all sessions issued before the reset are denied
- **AND** the hash is derived within the shared hashing concurrency budget and no plaintext or hash enters events, logs or responses

#### Scenario: Administrator resets their own password
- **WHEN** an administrator resets the password of their own account
- **THEN** the mutation succeeds and the actor's current session is revoked with the rest

#### Scenario: Administrator blocks their own account
- **WHEN** an administrator blocks their own account, even while other enabled administrators exist
- **THEN** the operation fails with `SELF_TARGET`, records a denied event and performs no mutation

### Requirement: Explicit administrator role assignment with a lockout guard

Setting a role to `admin` SHALL grant administrator authority for that user's subsequent requests, including existing sessions, because authority is read from the current account state. Setting a role to `member` SHALL remove it likewise. Administrators are peers: any current administrator MAY block, unblock, reset or change the role of any other administrator, as in the GitLab group owner model. Two guards apply. An administrator SHALL NOT demote their own account; such a request SHALL fail with `SELF_TARGET`. The system SHALL refuse any block or demotion that would leave zero enabled administrators, returning `LAST_ADMINISTRATOR` without mutation; that check SHALL be serialized across concurrent administrators so two simultaneous operations cannot both pass it. The actor's current role SHALL be rechecked under the same serialization before either guard runs. Setting a role the user already has SHALL succeed idempotently and record an event.

#### Scenario: Promote a member
- **WHEN** an administrator sets a member's role to `admin`
- **THEN** that user's next administrative request with an existing valid session is authorized

#### Scenario: Demote an administrator
- **WHEN** an administrator sets another enabled administrator's role to `member` while at least one other enabled administrator remains
- **THEN** the target's subsequent administrative requests are forbidden while ordinary identity requests continue to work

#### Scenario: Last enabled administrator
- **WHEN** the only enabled administrator is targeted by a block or demotion
- **THEN** the request is refused (`SELF_TARGET`, because only that administrator could have issued it), no mutation is committed and bootstrap remains closed
- **AND** the serialized `LAST_ADMINISTRATOR` guard remains in place as a defense in depth and SHALL be verified directly, since the self-target rule makes it unreachable through the public operations

#### Scenario: Self-demotion
- **WHEN** an administrator sets their own role to `member`
- **THEN** the operation fails with `SELF_TARGET`, records a denied event and the role is unchanged

#### Scenario: Concurrent mutual demotion or block
- **WHEN** the only two enabled administrators demote or block each other at the same time
- **THEN** exactly one operation succeeds and exactly one enabled administrator remains
- **AND** the other request is denied because its actor's authority was re-read after the first committed: `FORBIDDEN` after a demotion, `UNAUTHENTICATED` after a block; no `LAST_ADMINISTRATOR` outcome is recorded

### Requirement: Bounded user listing

Listing SHALL return each user's UUID, username, role, disabled state and creation time, ordered by username, without password hashes or session data. The list SHALL be bounded to a documented maximum of 1,000 users and SHALL report a `truncated` flag when more exist rather than presenting a partial list as complete. Listing SHALL NOT mutate state or record a success event; denied attempts SHALL be recorded.

#### Scenario: List users
- **WHEN** a current administrator lists users
- **THEN** every account appears once in username order with only the documented safe fields and `truncated: false`

#### Scenario: More users than the bound
- **WHEN** more users exist than the documented maximum
- **THEN** the response contains the first users in order and `truncated: true`

### Requirement: JSON administration transport

The server SHALL expose the operations as JSON routes under `/api/admin/users` for CLI bearer sessions only, using the route, body and status table in the design. They SHALL follow the existing JSON authentication transport rules: no cookie authentication, configured-origin checks, 8 KiB bounded credential bodies, strict content type, rejection of undocumented fields or trailing data, no redirects, `Cache-Control: no-store` and application-owned error bodies. Mutations SHALL be `POST`; listing SHALL be `GET` and SHALL NOT mutate. Rejections before service invocation SHALL be recorded through the existing adapter event boundary.

#### Scenario: Create through the API
- **WHEN** an administrator's CLI bearer request posts a valid create body
- **THEN** the response is 201 with the safe user record and no password field

#### Scenario: Browser cookie on an administration route
- **WHEN** an administration request carries only a browser session cookie
- **THEN** it receives an unauthenticated JSON response and no mutation occurs

#### Scenario: Malformed administration body
- **WHEN** a create or reset body is oversized, form-encoded, contains unknown fields or an invalid password
- **THEN** the request fails with `INVALID_ARGUMENT` without reflecting submitted values and without hashing

### Requirement: Read-only administrator user list in the browser

The protected administrator page SHALL render the bounded user list with username, role, status and creation time using escaped text, and SHALL show a truncation notice when applicable. The page SHALL NOT offer browser forms that create, block, reset or change roles in this change. If the list cannot be loaded, the page SHALL fail closed with safe unavailability rather than rendering stale or partial data as current.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests the administration page
- **THEN** the page lists all users with their role and enabled or blocked state

#### Scenario: Username contains markup-like characters
- **WHEN** a listed username is rendered
- **THEN** it appears as escaped text within the documented username character set
