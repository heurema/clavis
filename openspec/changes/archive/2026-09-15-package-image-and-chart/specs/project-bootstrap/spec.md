## MODIFIED Requirements

### Requirement: Independent liveness and readiness

The server SHALL expose `GET /livez`, `GET /readyz` and `GET /healthz`. Liveness (`/livez`) SHALL return HTTP 200 with `{"status":"alive"}` while the process can serve requests. Readiness (`/readyz`) SHALL complete within a documented timeout and return HTTP 200 with `{"status":"ready"}` only when the configured platform database is reachable, its schema is supported and installation is initialized. Database failure or timeout SHALL return HTTP 503 with status `not_ready` and error code `DEPENDENCY_UNAVAILABLE`. With a reachable database, incomplete initialization SHALL return safe HTTP 503 using `INITIALIZING`, `SETUP_REQUIRED`, `BOOTSTRAP_FAILED` or `SCHEMA_ERROR` as documented in the initialization design. The aggregate (`/healthz`) SHALL return HTTP 200 with `{"status":"ok","version":<build version>,"checks":{"live":<liveness body>,"ready":<readiness body>}}` when the process is live and ready, and HTTP 503 with `status` `unhealthy` and the same shape otherwise; it SHALL run the same readiness check under the same timeout and SHALL expose the build version only, not the commit or date. The former `/health/live` and `/health/ready` paths SHALL NOT be served. Responses SHALL exclude connection strings, credential paths and internal error details.

#### Scenario: The database is available
- **WHEN** a client requests readiness and the configured database responds within the timeout with a supported schema and initialized installation
- **THEN** the server returns HTTP 200 with status `ready` from `/readyz` and HTTP 200 with status `ok` and the build version from `/healthz`

#### Scenario: The database stops responding
- **WHEN** a client requests readiness while the database is unavailable or exceeds the timeout
- **THEN** `/readyz` returns HTTP 503 with status `not_ready` and code `DEPENDENCY_UNAVAILABLE` within the documented bound and `/healthz` returns HTTP 503 with status `unhealthy` carrying that readiness body under `checks.ready`
- **AND** `/livez` continues to return HTTP 200 while the process can serve requests

#### Scenario: The database recovers
- **WHEN** the database becomes reachable after a readiness failure and its schema/installation are usable
- **THEN** a subsequent readiness request succeeds without restarting the server

#### Scenario: Initialization is incomplete
- **WHEN** PostgreSQL responds but migration/bootstrap is pending, setup inputs are missing/invalid or the schema is incompatible
- **THEN** readiness returns the corresponding safe initialization error instead of claiming application readiness
- **AND** liveness and public setup documents remain available

#### Scenario: A former health path is requested
- **WHEN** a client requests `/health/live` or `/health/ready`
- **THEN** the server returns its not-found response

### Requirement: Required encryption key configuration

Server configuration SHALL include `CLAVIS_ENCRYPTION_KEY_FILE`, an absolute path to a protected regular file containing 64 hexadecimal characters and at most one terminal newline. The setting SHALL be required from this change onward; configuration loading SHALL fail before listening with a predictable error naming the setting and one of `REQUIRED`, `INVALID_PATH`, `UNREADABLE`, `UNSAFE_PERMISSIONS` or `INVALID_KEY`, without printing the path contents or the key. A protected file is one whose permissions grant nothing to others and nothing but read to its group, and whose group, when group-read is set, is the process's effective group or one of its supplementary groups; an owner-only file is always protected. The key SHALL be read once at startup and held in memory; the file MAY be removed afterwards without affecting the running process. `.env.example` SHALL document the setting and the generation command. The CLI SHALL NOT require or read the key.

#### Scenario: Missing or unsafe key file
- **WHEN** the server starts without the setting, with a file readable by others, with a group-writable file, with a group-readable file owned by a group the process does not belong to, or with a file of the wrong length
- **THEN** it exits nonzero with the documented configuration error before opening the listener or the database

#### Scenario: Key file shared with the process group
- **WHEN** the server starts with a key file of mode `0440` whose group is the process's effective or a supplementary group, as a Kubernetes Secret volume mounted under `fsGroup` produces
- **THEN** the key is loaded and the server starts

#### Scenario: Key file removed after start
- **WHEN** the file is deleted while the server runs
- **THEN** connection operations keep working with the key held in memory and the next restart fails with `REQUIRED` or `UNREADABLE` until the file is restored

#### Scenario: Development setup
- **WHEN** a developer follows the README quick start
- **THEN** the documented command generates a key file with owner-only permissions and `make dev` starts with it

### Requirement: Repeatable quality and smoke checks

The project SHALL provide documented non-interactive commands for formatting checks, static analysis, generated-source consistency, non-browser tests, builds, chart lint and schema validation, and an end-to-end bootstrap smoke check. Static analysis SHALL include a whole-program dead-code check that fails when any Go function is unreachable from the project's executables, with tests not counted as roots, so that code only tests reach is reported; the tool SHALL be pinned and installed by the setup command like the other Go tools, as SHALL Helm, kind and kubeconform. A failing check SHALL return a nonzero exit status. The smoke check SHALL exercise the real local server and database, verify API and CLI behavior against the same server origin, and clean up only the temporary resources it creates. Setup, quality and smoke commands SHALL NOT install or require a browser runtime.

Smoke verification SHALL run the built server from a separate working directory without companion web assets and SHALL verify document/asset availability through HTTP alongside CLI diagnostics and authentication. It SHALL cover database outage/recovery and server stop/restart through fresh HTTP and CLI requests. Automated browser behavior, DOM, screenshot and already-loaded-page checks are outside the current test scope. The image smoke and the kind verification defined by `deployment-packaging` SHALL be separate documented commands that require Docker and clean up only what they create.

#### Scenario: Validate the project from a clean installation
- **WHEN** a contributor runs the quality and smoke commands with the documented prerequisites
- **THEN** the checks verify that the application builds, generated sources are consistent, the chart renders and validates, and API/CLI requests observe real server/database behavior
- **AND** no browser installation or browser automation is invoked

#### Scenario: Unreachable code is introduced
- **WHEN** a function that no executable reaches is added to a production package, including one only tests call
- **THEN** the dead-code check exits unsuccessfully and names the function and its location

#### Scenario: Verify the deployable artifact
- **WHEN** the copied server executable runs in an otherwise empty directory with valid configuration
- **THEN** direct HTTP requests retrieve its public documents and required embedded assets, and the CLI obtains readiness/authentication results without a companion asset directory

#### Scenario: Verify server recovery through clients
- **WHEN** the smoke runner stops the server and restarts it at the same address
- **THEN** HTTP and CLI requests distinguish the outage and succeed after the server becomes ready again

#### Scenario: A required check fails
- **WHEN** a test, static check, generated-source check, chart lint, build, or smoke assertion fails
- **THEN** the corresponding command exits unsuccessfully and identifies the failing stage

#### Scenario: Smoke cleanup leaves developer resources intact
- **WHEN** the smoke check, the image smoke or the kind verification completes or fails
- **THEN** it terminates its own processes and temporary database, container or cluster resources without removing the contributor's normal development database volume
