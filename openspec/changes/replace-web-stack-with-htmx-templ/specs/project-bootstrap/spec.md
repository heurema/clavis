## MODIFIED Requirements

### Requirement: Independently buildable application entry points

The project SHALL provide separately buildable server and CLI executables. The server executable SHALL include the web application and all assets required to serve it; a separate deployable web bundle SHALL NOT be required. The CLI executable SHALL be named `clavis`, and building it alone SHALL NOT require web asset generation or frontend tools. The CLI's local help and version operations SHALL work without a running server, database, or frontend runtime.

#### Scenario: Build the application outputs
- **WHEN** a contributor runs the documented build command with dependencies installed
- **THEN** separate server and `clavis` executables are produced
- **AND** the server executable serves both the API and complete web interface without a companion asset directory

#### Scenario: Build only the CLI
- **WHEN** a contributor with the required Go toolchain and Go dependencies runs the documented CLI-only build
- **THEN** the `clavis` executable is built without invoking template, stylesheet or browser tooling

#### Scenario: Use local CLI commands offline
- **WHEN** the contributor invokes CLI help or version while the server and database are stopped
- **THEN** the command succeeds without a network request

### Requirement: Web foundation displays actual readiness

The web application SHALL provide a consistent application shell with a setup/status page served by the same process as the API. Once loaded, the page SHALL retrieve readiness from that origin and represent loading, ready, dependency unavailable, and server unavailable states separately. It SHALL support retrying a failed check without reloading the page and SHALL NOT present placeholder data as an operational integration.

Checks SHALL run on page entry and explicit user request, without automatic retries, polling or focus/reconnect refetches. Each browser check SHALL settle within five seconds, including response-body consumption. A fresh check SHALL display a checking state instead of presenting a previous success as current evidence. A superseded result SHALL NOT overwrite a newer result.

An already-loaded page SHALL display a safe server-unavailable message when its server cannot be reached. A fresh navigation while the server process is stopped is outside this in-page diagnostic guarantee; no independently served fallback page is required.

#### Scenario: Load the page with a ready server
- **WHEN** a user opens the setup/status page while the server and database are available
- **THEN** the page transitions from loading to a ready state using the server response

#### Scenario: Distinguish a dependency failure from a server failure
- **WHEN** a loaded page receives a documented dependency failure or cannot reach the server
- **THEN** the page explains the corresponding state and offers a retry action

#### Scenario: Recover through the retry action
- **WHEN** the user retries after the failed dependency or server has recovered
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

### Requirement: Repeatable quality and smoke checks

The project SHALL provide documented non-interactive commands for formatting checks, static analysis, generated-source consistency, tests, builds, and an end-to-end bootstrap smoke check. A failing check SHALL return a nonzero exit status. The smoke check SHALL exercise the real local server and database, verify CLI diagnostics and browser readiness against the same server origin, and clean up only the temporary resources it creates.

Smoke verification SHALL run the built server from a separate working directory without companion web assets and SHALL verify browser functionality without third-party asset requests. It SHALL cover database outage/recovery and loss/recovery of the server connection in an already-loaded page.

#### Scenario: Validate the project from a clean installation
- **WHEN** a contributor runs the quality and smoke commands with the documented prerequisites
- **THEN** the checks verify that the application builds, generated sources are consistent, and the CLI and browser observe the real server/database readiness
- **AND** browser tests use the built server directly rather than a frontend preview server

#### Scenario: Verify the deployable artifact
- **WHEN** the copied server executable runs in an otherwise empty directory with valid configuration
- **THEN** smoke verification loads its complete styled page, exercises appearance and retry, and obtains the existing CLI readiness result without a companion asset directory
- **AND** browser requests for required assets remain on the server's origin

#### Scenario: Verify server recovery in an existing page
- **WHEN** the smoke runner stops the server after the page has loaded and restarts it at the same address
- **THEN** the loaded page reports a failed check safely and a subsequent explicit retry recovers without reloading

#### Scenario: A required check fails
- **WHEN** a test, static check, generated-source check, build, or smoke assertion fails
- **THEN** the corresponding command exits unsuccessfully and identifies the failing stage

#### Scenario: Smoke cleanup leaves developer resources intact
- **WHEN** the smoke check completes or fails
- **THEN** it terminates its own processes and temporary database resources without removing the contributor's normal development database volume
