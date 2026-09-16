## MODIFIED Requirements

### Requirement: Structured CLI diagnostics

The CLI SHALL provide a `doctor` operation that checks server readiness using a timeout and the server chosen by the CLI's server resolution (`--server` or `--profile`, then `CLAVIS_PROFILE`, then the current profile), with no built-in default server. The resolved server SHALL pass the same canonical-origin rule as `login`, so a server that passes `doctor` cannot be refused by `login`. The default output SHALL be exactly one JSON document on stdout, using the envelope `schemaVersion`, `ok`, `data`, and `error`, plus the top-level `server` and `profile` fields once a server is resolved. Version 1 results SHALL distinguish a ready system, an unavailable database, an incomplete or failed installation, an unreachable or unresponsive server, an invalid server response, and invalid arguments. Diagnostic text SHALL NOT corrupt JSON output.

The CLI SHALL exit with code 0 for success, code 1 for a failed diagnostic operation, and code 2 for invalid arguments or configuration. The doctor data SHALL include `api` and `database` states; an unchecked database SHALL be `unknown`. A documented initialization failure with a reachable database SHALL report `data.api: "reachable"`, `data.database: "ready"` and the allowlisted initialization error, not mislabel it as database unavailability. Raw server error messages SHALL NOT be echoed.

#### Scenario: Diagnose a working environment
- **WHEN** the CLI runs `doctor` against a ready server
- **THEN** it exits with code 0 and returns `schemaVersion: 1`, `ok: true`, `data.api: "reachable"`, `data.database: "ready"`, `error: null`, and the resolved `server` and `profile`

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
- **WHEN** the CLI receives an unknown command, a server URL that fails the canonical-origin rule (including a base path or non-loopback HTTP), an unsupported output format, an invalid timeout, or no resolvable server
- **THEN** it exits with code 2 and returns error code `INVALID_ARGUMENT` in a single JSON document using the default format, with the hint `clavis profiles set <name> --server <url>` when no server was resolved

#### Scenario: Diagnose setup or schema failure
- **WHEN** the server returns documented 503 `INITIALIZING`, `SETUP_REQUIRED`, `BOOTSTRAP_FAILED` or `SCHEMA_ERROR`
- **THEN** doctor exits 1 with that code and an application-owned message, reporting the API reachable and database ready
- **AND** its existing data fields and schema version are preserved

#### Scenario: Diagnose through the current profile
- **WHEN** the current profile is `fce` and a user runs `doctor` with no flag or variable
- **THEN** readiness is checked against the `fce` server and the result carries `profile: "fce"`
