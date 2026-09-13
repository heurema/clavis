## MODIFIED Requirements

### Requirement: Repeatable quality and smoke checks

The project SHALL provide documented non-interactive commands for formatting checks, static analysis, generated-source consistency, non-browser tests, builds, and an end-to-end bootstrap smoke check. Static analysis SHALL include a whole-program dead-code check that fails when any Go function is unreachable from the project's executables, with tests not counted as roots, so that code only tests reach is reported; the tool SHALL be pinned and installed by the setup command like the other Go tools. A failing check SHALL return a nonzero exit status. The smoke check SHALL exercise the real local server and database, verify API and CLI behavior against the same server origin, and clean up only the temporary resources it creates. Setup, quality and smoke commands SHALL NOT install or require a browser runtime.

Smoke verification SHALL run the built server from a separate working directory without companion web assets and SHALL verify document/asset availability through HTTP alongside CLI diagnostics and authentication. It SHALL cover database outage/recovery and server stop/restart through fresh HTTP and CLI requests. Automated browser behavior, DOM, screenshot and already-loaded-page checks are outside the current test scope.

#### Scenario: Validate the project from a clean installation
- **WHEN** a contributor runs the quality and smoke commands with the documented prerequisites
- **THEN** the checks verify that the application builds, generated sources are consistent, and API/CLI requests observe real server/database behavior
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
- **WHEN** a test, static check, generated-source check, build, or smoke assertion fails
- **THEN** the corresponding command exits unsuccessfully and identifies the failing stage

#### Scenario: Smoke cleanup leaves developer resources intact
- **WHEN** the smoke check completes or fails
- **THEN** it terminates its own processes and temporary database resources without removing the contributor's normal development database volume
