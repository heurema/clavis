## ADDED Requirements

### Requirement: Safe local CLI sign-in

The CLI SHALL provide login using a username and either hidden terminal input or explicit `--password-stdin`. It SHALL NOT accept passwords or session tokens through command-line values or environment variables. Noninteractive input without an explicit input mode SHALL fail rather than wait for a prompt. Password input SHALL be bounded and follow the same newline/validation rules as bootstrap. Prompts SHALL NOT corrupt stdout.

#### Scenario: Automated CLI login
- **WHEN** a caller supplies a password on stdin with `--password-stdin`
- **THEN** the CLI authenticates without prompting or echoing the password and emits exactly one safe result

#### Scenario: Interactive CLI login
- **WHEN** a user runs login from a terminal without the stdin flag
- **THEN** the password is read without echo and the prompt is separate from structured stdout

#### Scenario: Invalid input mode
- **WHEN** a noninteractive caller omits the stdin flag or supplies unsupported credential flags
- **THEN** the command exits with code 2 and safe `INVALID_ARGUMENT` JSON without hanging

### Requirement: Origin-bound protected session storage

The CLI SHALL store session credentials outside the project in a private user configuration location, keyed by canonical server origin. Authentication commands SHALL reject base-path URLs for this milestone and require HTTPS except literal loopback HTTP. Cache directories/files SHALL have protected permissions, safe ownership, bounded contents and atomic regular-file updates, with symlink/nonregular-file rejection. Credential-changing commands SHALL serialize per origin. Failed login SHALL NOT overwrite a working cached credential.

#### Scenario: Sign in to different servers
- **WHEN** the user signs in to two distinct canonical origins
- **THEN** the sessions are stored independently and requests to one origin never use the other's token

#### Scenario: Unsafe or failed cache write
- **WHEN** local credential storage is unsafe or persistence fails after token issuance
- **THEN** login does not report success or print the token
- **AND** the CLI attempts bounded best-effort revocation and reports a safe credential-storage failure

#### Scenario: Concurrent login and logout
- **WHEN** credential-changing processes target the same origin concurrently
- **THEN** bounded locking prevents partial writes or one logout deleting a newly replaced unrelated session

### Requirement: Authoritative identity and explicit sign-out

The CLI SHALL provide `whoami`, `logout` and administrator `sessions revoke --user <uuid>`. Current identity SHALL be verified with the server, not inferred from cache. Logout SHALL attempt remote revocation and remove the matching local credential even when the server is unreachable, while reporting unconfirmed remote revocation as failure. Missing local credentials and confirmed invalid/expired server sessions SHALL make logout an idempotent success.

#### Scenario: Verify an active identity
- **WHEN** whoami runs with a valid cached session
- **THEN** the server-confirmed user and expiry are returned without the token

#### Scenario: Remote session is revoked
- **WHEN** whoami uses a session revoked through another client
- **THEN** it reports an authentication failure instead of presenting cached identity as active

#### Scenario: Sign out during an outage
- **WHEN** logout cannot reach the server
- **THEN** the local credential is removed and exit code 1 clearly reports that remote revocation was not confirmed
- **AND** the output does not claim `revoked:true`

#### Scenario: Sign out repeatedly
- **WHEN** logout has no local credential or the server confirms that the cached session is no longer valid
- **THEN** it succeeds after ensuring the matching local credential is absent

#### Scenario: Revoke another user's sessions
- **WHEN** a current administrator invokes sessions revoke with a valid user UUID
- **THEN** the CLI calls the protected revocation endpoint and reports only its safe result
- **AND** a non-admin receives a forbidden result without a mutation

### Requirement: Bounded and non-disclosing authentication transport

Authentication requests SHALL use a single documented whole-request deadline, bounded response bodies, strict status/body validation and no redirects or automatic mutation retries. Credentials SHALL never be forwarded to a redirect destination. Malformed responses and transport errors SHALL be mapped to application-owned errors without exposing raw server content.

#### Scenario: Credential request redirects
- **WHEN** login or a bearer request receives a redirect
- **THEN** the CLI does not contact the destination and reports `INVALID_RESPONSE`

#### Scenario: Stalled or malformed authentication response
- **WHEN** the response body stalls, exceeds its limit or contains an undocumented status/body combination with sentinel secrets
- **THEN** the CLI terminates within the deadline with a safe timeout/invalid-response result and does not display the body

### Requirement: Authentication preserves CLI output conventions

Authentication commands SHALL preserve the schemaVersion 1 result envelope and exit codes 0 for success, 1 for operation failure and 2 for invalid arguments/configuration. Invalid invocation SHALL force JSON output. JSON and text SHALL expose only safe identity, expiry and operation outcomes; session tokens and passwords SHALL never enter result data. Offline help/version and Go-only CLI builds SHALL remain independent of authentication and web tooling.

#### Scenario: Successful login output
- **WHEN** login completes and safely stores its session
- **THEN** stdout contains one success result with user/expiry but no token or password, and the command exits 0

#### Scenario: Invalid arguments with text requested
- **WHEN** an authentication command receives invalid flags, URL, timeout or positional arguments with text output requested
- **THEN** it exits 2 with one safe JSON invalid-argument result

#### Scenario: Local offline operation
- **WHEN** help/version or a CLI-only build runs without a server or web tools
- **THEN** it continues to work without loading stored credentials or contacting an authentication endpoint
