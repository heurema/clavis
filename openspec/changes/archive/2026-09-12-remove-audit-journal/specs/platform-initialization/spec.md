## MODIFIED Requirements

### Requirement: sqlc-backed application persistence

Application SQL for users, sessions, installation, connections, grants, readiness schema checks and login limits SHALL live in named SQL files. The pinned sqlc tool SHALL generate typed native pgx v5 methods using the Goose SQL migrations as schema input. Handwritten persistence code SHALL use those methods with the existing transaction/context boundaries, not inline application SQL, generic raw-query helpers or manual application-row scanning.

Goose's narrowly scoped ledger/checksum/advisory-lock adapter SHALL remain separate from application queries and SHALL NOT access application tables or provide an unrestricted query interface. Test fixture SQL SHALL remain isolated from production data-access paths.

#### Scenario: Bootstrap and authentication share generated transaction queries
- **WHEN** bootstrap, authentication, revocation or throttle persistence runs
- **THEN** application queries execute through sqlc-generated methods bound to the intended pgx transaction
- **AND** rollback, deadlines and authorization behavior remain intact

#### Scenario: Handwritten application queries are reintroduced
- **WHEN** maintained application persistence code adds a direct query/scan path outside generated code
- **THEN** the repository contract check fails instead of accepting a second persistence implementation
- **AND** the Goose adapter does not provide a blanket exemption for application SQL

### Requirement: Atomic unattended administrator bootstrap

On an uninitialized installation, normal server startup SHALL accept `CLAVIS_BOOTSTRAP_USERNAME` and `CLAVIS_BOOTSTRAP_PASSWORD_FILE` as deployment inputs. It SHALL create one personal administrator account and a durable initialization marker in one transaction after validating both inputs. Invalid inputs or unexpected users SHALL fail safely without writing anything. Initialization SHALL require neither an interactive prompt, a separate bootstrap command nor an HTTP administrator-creation endpoint. Existing user rows without a valid installation marker SHALL cause a safe failure rather than automatic adoption.

#### Scenario: Automation supplies initial credentials
- **WHEN** automation starts a fresh installation with a valid username and password file
- **THEN** one administrator and the initialized marker are committed together
- **AND** the credentials can be used for normal sign-in after readiness succeeds

#### Scenario: Competing bootstrap credentials
- **WHEN** two instances attempt bootstrap simultaneously using different valid credentials
- **THEN** only the transaction that initializes the installation creates an account
- **AND** the other instance observes initialization without modifying or adding accounts

#### Scenario: Bootstrap transaction is interrupted
- **WHEN** the process or database fails before bootstrap commits
- **THEN** no partial administrator/marker combination is committed
- **AND** a subsequent attempt can complete initialization once

#### Scenario: Unexpected users exist before initialization
- **WHEN** users exist but a valid initialized marker does not
- **THEN** bootstrap fails safely and does not promote a user or create another administrator
