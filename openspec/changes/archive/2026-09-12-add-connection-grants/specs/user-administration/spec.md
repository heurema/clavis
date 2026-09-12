## MODIFIED Requirements

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
