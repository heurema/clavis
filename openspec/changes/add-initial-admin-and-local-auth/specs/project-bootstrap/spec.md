## MODIFIED Requirements

### Requirement: Independent liveness and readiness

The server SHALL expose `GET /health/live` and `GET /health/ready`. Liveness SHALL return HTTP 200 with `{"status":"alive"}` while the process can serve requests. Readiness SHALL complete within a documented timeout and return HTTP 200 with `{"status":"ready"}` only when the configured platform database is reachable, its schema is supported and installation is initialized. Database failure or timeout SHALL return HTTP 503 with status `not_ready` and error code `DEPENDENCY_UNAVAILABLE`. With a reachable database, incomplete initialization SHALL return safe HTTP 503 using `INITIALIZING`, `SETUP_REQUIRED`, `BOOTSTRAP_FAILED` or `SCHEMA_ERROR` as documented in the initialization design. Responses SHALL exclude connection strings, credential paths and internal error details.

#### Scenario: The database is available
- **WHEN** a client requests readiness and the configured database responds within the timeout with a supported schema and initialized installation
- **THEN** the server returns HTTP 200 with status `ready`

#### Scenario: The database stops responding
- **WHEN** a client requests readiness while the database is unavailable or exceeds the timeout
- **THEN** readiness returns HTTP 503 with status `not_ready` and code `DEPENDENCY_UNAVAILABLE` within the documented bound
- **AND** liveness continues to return HTTP 200 while the process can serve requests

#### Scenario: The database recovers
- **WHEN** the database becomes reachable after a readiness failure and its schema/installation are usable
- **THEN** a subsequent readiness request succeeds without restarting the server

#### Scenario: Initialization is incomplete
- **WHEN** PostgreSQL responds but migration/bootstrap is pending, setup inputs are missing/invalid or the schema is incompatible
- **THEN** readiness returns the corresponding safe initialization error instead of claiming application readiness
- **AND** liveness and public setup documents remain available

### Requirement: Structured CLI diagnostics

The CLI SHALL provide a `doctor` operation that checks server readiness using a configurable server URL and timeout. The default output SHALL be exactly one JSON document on stdout, using the envelope `schemaVersion`, `ok`, `data`, and `error`. Version 1 results SHALL distinguish a ready system, an unavailable database, an incomplete or failed installation, an unreachable or unresponsive server, an invalid server response, and invalid arguments. Diagnostic text SHALL NOT corrupt JSON output.

The CLI SHALL exit with code 0 for success, code 1 for a failed diagnostic operation, and code 2 for invalid arguments or configuration. The doctor data SHALL include `api` and `database` states; an unchecked database SHALL be `unknown`. A documented initialization failure with a reachable database SHALL report `data.api: "reachable"`, `data.database: "ready"` and the allowlisted initialization error, not mislabel it as database unavailability. Raw server error messages SHALL NOT be echoed.

#### Scenario: Diagnose a working environment
- **WHEN** the CLI runs `doctor` against a ready server
- **THEN** it exits with code 0 and returns `schemaVersion: 1`, `ok: true`, `data.api: "reachable"`, `data.database: "ready"`, and `error: null`

#### Scenario: Diagnose an unavailable database
- **WHEN** the server returns the documented database readiness failure
- **THEN** the CLI exits with code 1 and returns `ok: false`, `data.api: "reachable"`, `data.database: "unavailable"`, and error code `DEPENDENCY_UNAVAILABLE`

#### Scenario: Diagnose an unreachable or timed-out server
- **WHEN** the server connection fails or the configured request deadline expires
- **THEN** the CLI exits with code 1 within the configured timeout, returns error code `SERVER_UNREACHABLE` or `TIMEOUT` as appropriate, and reports the database state as `unknown`

#### Scenario: Reject an unexpected server response
- **WHEN** the server returns an undocumented status/body combination or malformed JSON
- **THEN** the CLI exits with code 1 and returns error code `INVALID_RESPONSE` without claiming database readiness or printing the response body

#### Scenario: Reject invalid arguments
- **WHEN** the CLI receives an unknown command, an invalid server URL, an unsupported output format, or an invalid timeout
- **THEN** it exits with code 2 and returns error code `INVALID_ARGUMENT` in a single JSON document using the default format

#### Scenario: Diagnose setup or schema failure
- **WHEN** the server returns documented 503 `INITIALIZING`, `SETUP_REQUIRED`, `BOOTSTRAP_FAILED` or `SCHEMA_ERROR`
- **THEN** doctor exits 1 with that code and an application-owned message, reporting the API reachable and database ready
- **AND** its existing data fields and schema version are preserved

### Requirement: Web foundation displays actual readiness

The web application SHALL provide a consistent application shell with a public setup/status page served by the same process as the API. Once loaded, the page SHALL retrieve readiness from that origin and represent loading, ready, initialization in progress, setup required, bootstrap/schema failure, dependency unavailable, and server unavailable states separately. It SHALL support retrying a failed check without reloading the page and SHALL NOT present placeholder data as an operational integration. The page SHALL explain deployment-driven initialization, expose no administrator-creation form and offer normal sign-in once ready.

Checks SHALL run on page entry and explicit user request, without automatic retries, polling or focus/reconnect refetches. Each browser check SHALL settle within five seconds, including response-body consumption. A fresh check SHALL display a checking state instead of presenting a previous success as current evidence. A superseded result SHALL NOT overwrite a newer result.

An already-loaded page SHALL display a safe server-unavailable message when its server cannot be reached. A fresh navigation while the server process is stopped is outside this in-page diagnostic guarantee; no independently served fallback page is required.

#### Scenario: Load the page with a ready server
- **WHEN** a user opens the setup/status page while the server, database, schema and installation are ready
- **THEN** the page transitions from loading to a ready state using the server response and offers sign-in

#### Scenario: Distinguish a dependency failure from a server failure
- **WHEN** a loaded page receives a documented dependency failure or cannot reach the server
- **THEN** the page explains the corresponding state and offers a retry action

#### Scenario: Recover through the retry action
- **WHEN** the user retries after the failed dependency or server has recovered and initialization is complete
- **THEN** the loaded page updates to ready without a browser reload

#### Scenario: Ignore a superseded result
- **WHEN** an earlier check completes after a newer user-requested check has completed
- **THEN** the page retains the newer result and does not display or announce the stale result

#### Scenario: Bound a stalled response body
- **WHEN** the server sends response headers but does not complete the readiness body
- **THEN** the page exits the checking state within five seconds with a safe timeout message and an enabled retry action

#### Scenario: Open a page while the server is stopped
- **WHEN** the user starts a fresh navigation with the server process stopped
- **THEN** no Clavis page can be served and the browser handles the connection failure
- **AND** documentation does not promise a separate status server or an offline application shell

#### Scenario: Explain incomplete installation
- **WHEN** a loaded page receives a documented initialization/setup/bootstrap/schema failure
- **THEN** it displays the corresponding safe state and deployment guidance without exposing secrets, paths or account details
- **AND** checking again does not itself trigger administrator creation

### Requirement: Repeatable quality and smoke checks

The project SHALL provide documented non-interactive commands for formatting checks, static analysis, generated-source consistency, non-browser tests, builds, and an end-to-end bootstrap smoke check. A failing check SHALL return a nonzero exit status. The smoke check SHALL exercise the real local server and database, verify API and CLI behavior against the same server origin, and clean up only the temporary resources it creates. Setup, quality and smoke commands SHALL NOT install or require a browser runtime.

Smoke verification SHALL run the built server from a separate working directory without companion web assets and SHALL verify document/asset availability through HTTP alongside CLI diagnostics and authentication. It SHALL cover database outage/recovery and server stop/restart through fresh HTTP and CLI requests. Automated browser behavior, DOM, screenshot and already-loaded-page checks are outside the current test scope.

#### Scenario: Validate the project from a clean installation
- **WHEN** a contributor runs the quality and smoke commands with the documented prerequisites
- **THEN** the checks verify that the application builds, generated sources are consistent, and API/CLI requests observe real server/database behavior
- **AND** no browser installation or browser automation is invoked

#### Scenario: Verify the deployable artifact
- **WHEN** the copied server executable runs in an otherwise empty directory with valid configuration
- **THEN** direct HTTP requests retrieve its public documents and required embedded assets, and the CLI obtains readiness/authentication results without a companion asset directory

#### Scenario: Verify server recovery through clients
- **WHEN** the smoke runner stops the server and restarts it at the same address
- **THEN** HTTP and CLI requests distinguish the outage and succeed after the server becomes ready again

#### Scenario: A required check fails
- **WHEN** a test, static check, generated-source check, build, or smoke assertion fails
- **THEN** the corresponding command exits unsuccessfully and identifies the failing stage

#### Scenario: Smoke cleanup leaves developer resources intact
- **WHEN** the smoke check completes or fails
- **THEN** it terminates its own processes and temporary database resources without removing the contributor's normal development database volume
