## ADDED Requirements

### Requirement: Embedded transactional schema initialization

The server SHALL embed ordered, checksummed platform SQL migrations and apply them without external migration executables. Concurrent instances SHALL serialize migrations and recheck the applied version under a database lock. Each successful version SHALL commit atomically with its migration record. Failed, changed or unsupported migrations SHALL NOT be treated as a ready schema or automatically rolled back through destructive down migrations.

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
