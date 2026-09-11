## Purpose

Initialize the platform schema and first administrator automatically, atomically and once, while preserving safe public diagnostics and recovery from transient failures.

## ADDED Requirements

### Requirement: Embedded transactional schema initialization

The server SHALL embed ordered, checksummed Goose SQL migrations and apply them through the pinned Goose v3 library without external migration executables. Goose SHALL own migration execution and version tracking, with one ledger rather than a parallel custom migration engine. Concurrent instances SHALL serialize migration and bootstrap on the same database advisory key and recheck committed versions after locking. Each successful version and checksum SHALL commit atomically with its Goose migration record. Failed, changed or unsupported migrations SHALL NOT be treated as a ready schema or automatically rolled back through destructive down migrations.

#### Scenario: Start a copied executable on a fresh platform database
- **WHEN** the server starts with a fresh configured platform database and valid deployment inputs
- **THEN** it applies its embedded schema without reading SQL from the working directory or invoking another executable

#### Scenario: Concurrent migration attempts
- **WHEN** two instances start against the same unmigrated database
- **THEN** each schema version is applied once and both instances observe the same committed version

#### Scenario: A migration fails or does not match
- **WHEN** transactional SQL fails, an applied checksum differs or the database schema is newer than supported
- **THEN** readiness remains unavailable with a safe schema category
- **AND** failed SQL does not leave a successfully recorded version or partial committed migration

#### Scenario: Reject an incompatible experimental ledger
- **WHEN** a database contains the former custom migration ledger rather than the supported Goose ledger
- **THEN** initialization fails closed without silently adopting, deleting or rebaselining application data

### Requirement: sqlc-backed application persistence

Application SQL for users, sessions, installation, audit events, readiness schema checks and login limits SHALL live in named SQL files. The pinned sqlc tool SHALL generate typed native pgx v5 methods using the Goose SQL migrations as schema input. Handwritten persistence code SHALL use those methods with the existing transaction/context boundaries, not inline application SQL, generic raw-query helpers or manual application-row scanning.

Goose's narrowly scoped ledger/checksum/advisory-lock adapter SHALL remain separate from application queries and SHALL NOT access application tables or provide an unrestricted query interface. Test fixture SQL SHALL remain isolated from production data-access paths.

#### Scenario: Bootstrap and authentication share generated transaction queries
- **WHEN** bootstrap, authentication, revocation, audit or throttle persistence runs
- **THEN** application queries execute through sqlc-generated methods bound to the intended pgx transaction
- **AND** rollback, deadlines, authorization and atomic audit behavior remain intact

#### Scenario: Handwritten application queries are reintroduced
- **WHEN** maintained application persistence code adds a direct query/scan path outside generated code
- **THEN** the repository contract check fails instead of accepting a second persistence implementation
- **AND** the Goose adapter does not provide a blanket exemption for application SQL

### Requirement: Reproducible checked-in query generation

The repository SHALL pin sqlc and commit generated Go with its SQL/configuration inputs. Explicit generation SHALL update the output; routine consistency checks and server builds SHALL reject missing, stale or unexpected generated files without rewriting maintained or generated source. Generated sqlc files SHALL be excluded from mutation targets while handwritten persistence behavior remains eligible. CLI-only builds SHALL remain Go-only and independent of sqlc and SQL source files.

#### Scenario: Check generated query consistency
- **WHEN** a query, migration or generation configuration changes without matching generated Go, or a generated file is missing/extra
- **THEN** the check and server build fail nonzero without repairing the checkout implicitly

#### Scenario: Reproduce query output
- **WHEN** explicit generation runs using pinned inputs
- **THEN** it produces the matching generated file set and a subsequent non-mutating check succeeds

#### Scenario: Build the CLI without database-generation tools
- **WHEN** the CLI-only build runs without sqlc or SQL inputs
- **THEN** it succeeds using only the Go toolchain and its client dependencies

### Requirement: Atomic unattended administrator bootstrap

On an uninitialized installation, normal server startup SHALL accept `CLAVIS_BOOTSTRAP_USERNAME` and `CLAVIS_BOOTSTRAP_PASSWORD_FILE` as deployment inputs. It SHALL create one personal administrator account, a safe creation event and a durable initialization marker in one transaction after validating both inputs. Initialization SHALL require neither an interactive prompt, a separate bootstrap command nor an HTTP administrator-creation endpoint. Existing user rows without a valid installation marker SHALL cause a safe failure rather than automatic adoption.

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
- **THEN** no partial administrator/marker/event combination is committed
- **AND** a subsequent attempt can complete initialization once

#### Scenario: Unexpected users exist before initialization
- **WHEN** users exist but a valid initialized marker does not
- **THEN** bootstrap fails safely and does not promote a user or create another administrator

### Requirement: Bootstrap is not credential reconciliation

The durable initialization marker SHALL be independent of the current count of administrators. Once initialized, the server SHALL ignore bootstrap inputs without opening the password file, validating obsolete bootstrap values, rotating credentials or recreating accounts. Removing accounts, restarting replicas or changing environment inputs SHALL NOT reopen setup.

#### Scenario: Restart without a bootstrap file
- **WHEN** an initialized installation restarts with the file removed, an unreadable obsolete path, changed values or no bootstrap settings
- **THEN** the existing account password and role remain unchanged and initialization does not require the file

#### Scenario: No administrator remains usable
- **WHEN** all administrator accounts are disabled or removed after initialization
- **THEN** bootstrap remains closed and deployment settings cannot silently recreate access

### Requirement: Safe bounded bootstrap secret handling

The server SHALL read only a bounded regular password file with protected POSIX permissions. Deployment-managed symlinks SHALL be supported while the opened target is validated. Directories, FIFOs, oversized input and unsafe permissions SHALL fail without blocking indefinitely. File/stdin input SHALL remove at most one terminal LF or CRLF and preserve other whitespace. Bootstrap SHALL share the username/password rules specified by local-authentication. Only a versioned password hash SHALL be stored; secret contents and paths SHALL be absent from public output and logs.

#### Scenario: A projected secret is supplied
- **WHEN** the configured path is a symlink to a protected regular file containing a valid password and one terminal newline
- **THEN** bootstrap uses the password without that terminal newline and does not reject the path solely for being a symlink

#### Scenario: Credentials are unavailable or unsafe
- **WHEN** an uninitialized installation lacks one or both inputs, or the supplied file is invalid or unreadable
- **THEN** no administrator is created and readiness distinguishes missing setup from failed bootstrap using safe application-owned text

#### Scenario: Secret data occurs in an internal error
- **WHEN** reading or hashing a bootstrap input fails with internal details containing a sentinel secret or file path
- **THEN** neither logs, HTTP responses nor CLI diagnostics contain those details

### Requirement: Initialization does not withhold public diagnostics

The server SHALL start public HTTP diagnostics and documents independently of initialization. Initialization attempts, lock waits, retries and cleanup SHALL be bounded and cancellation-aware. Transient database recovery SHALL permit initialization without restarting the process. Read-only HTTP requests SHALL NOT cause migrations or administrator creation. Readiness and authenticated operations SHALL fail closed until schema and installation state are usable.

#### Scenario: Start while PostgreSQL is unavailable
- **WHEN** valid server configuration is supplied but the database cannot be reached
- **THEN** liveness, setup/login documents and embedded assets remain available
- **AND** readiness and authentication report safe unavailability

#### Scenario: Database and mounted secret recover
- **WHEN** the database becomes available or an invalid mounted secret is repaired while the process is running
- **THEN** bounded worker retries can finish initialization and a subsequent readiness request observes the committed result

#### Scenario: Shut down during a blocked initialization attempt
- **WHEN** termination arrives while migration, bootstrap or retry is pending
- **THEN** the worker is canceled and the process exits within the existing overall shutdown budget
