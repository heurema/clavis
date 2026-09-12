# cli-authentication Specification

## Purpose

Provide authenticated CLI access with safe credential input, origin-bound session storage, authoritative identity and explicit session revocation.

## Requirements

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

The CLI SHALL provide `whoami`, `logout` and administrator `sessions revoke --user <uuid-or-username>`. Current identity SHALL be verified with the server, not inferred from cache, and `whoami` SHALL report the names of the connections the caller holds a grant on, with a truncation flag; administrators see an empty list because they need no grants. Logout SHALL attempt remote revocation and remove the matching local credential even when the server is unreachable, while reporting unconfirmed remote revocation as failure. Missing local credentials and confirmed invalid/expired server sessions SHALL make logout an idempotent success.

#### Scenario: Verify an active identity
- **WHEN** whoami runs with a valid cached session
- **THEN** the server-confirmed user, expiry and granted connection names are returned without the token

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
- **WHEN** a current administrator invokes sessions revoke with a valid user UUID or username
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

### Requirement: Administrative user commands

The CLI SHALL provide `users list`, `users create --username <name>`, `users block --user <uuid-or-username>`, `users unblock --user <uuid-or-username>`, `users reset-password --user <uuid-or-username>` and `users set-role --user <uuid-or-username> --role admin|member`. These commands SHALL use the stored session for the selected origin, the same `--server`/`--timeout` flags, origin policy and bounded transport as the other authentication commands, and SHALL call only the documented administration endpoints. `users create` and `users reset-password` SHALL read the password through hidden terminal input or explicit `--password-stdin` with the same validation, bounds and noninteractive rules as `login`; passwords SHALL NOT be accepted through command-line values or environment variables.

Results SHALL keep the schemaVersion 1 envelope and exit codes 0/1/2. JSON and text output SHALL expose only safe user records (`id`, `username`, `role`, `disabled`, `createdAt`), the list's `truncated` flag and, for password resets and blocks, whether sessions were revoked. Passwords, hashes and session tokens SHALL never enter result data. Text output SHALL support the new result types. Server error codes `USERNAME_TAKEN`, `LAST_ADMINISTRATOR`, `SELF_TARGET`, `USER_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL be passed through as safe application-owned results; undocumented responses SHALL map to `INVALID_RESPONSE`.

#### Scenario: Create a user from automation
- **WHEN** an administrator runs `users create --username alice --password-stdin` with the password on stdin
- **THEN** the CLI creates the account without echoing the password and prints one success result containing the new user's ID, username, role and no password

#### Scenario: Reset a password interactively
- **WHEN** an administrator runs `users reset-password --user alice` from a terminal
- **THEN** the password is read without echo and the result reports the user and that sessions were revoked

#### Scenario: Member runs an administrative command
- **WHEN** a member's stored session runs any `users` command
- **THEN** the CLI exits 1 with `FORBIDDEN` and no mutation occurs

#### Scenario: Server refuses a guarded mutation
- **WHEN** `users block` or `users set-role --role member` receives `LAST_ADMINISTRATOR` or `SELF_TARGET` from the server
- **THEN** the CLI exits 1 with that code and the server's safe message, sends no further request and the role is unchanged

#### Scenario: Invalid administrative arguments
- **WHEN** a `users` command receives a value that is neither a UUID nor a valid username, an unsupported role, a positional argument or a missing password input mode in a noninteractive session
- **THEN** it exits 2 with one safe `INVALID_ARGUMENT` JSON result without contacting the server

#### Scenario: List users as text
- **WHEN** `users list --output text` runs with a valid administrator session
- **THEN** each user is printed on its own line with ID, username, role and status, followed by a truncation notice only when the server reports truncation

### Requirement: Connection management commands

The CLI SHALL provide `connections list [--selector <terms>] [--limit N]`, `connections get --connection <id>`, `connections create --name <slug> --provider <type> --url <target> [--label key=value]... [--title] [--description] [--scope] [--statement-timeout] [--max-rows] [--max-bytes] [--auth] [--auth-user] [--auth-header]`, `connections update --connection <id> [same fields]` (labels and the target are replaced whole; any target flag on update requires `--url`), `connections set-credentials --connection <id>`, `connections enable|disable|delete --connection <id>` and `connections check --connection <id>`, where `<id>` is a UUID or a name. These commands SHALL use the stored session, the `--server`/`--timeout` flags, origin policy, bounded transport and result envelope of the other authenticated commands, SHALL call only the documented connection routes, and SHALL use one verb vocabulary shared with `users`.

Secrets for `create` and `set-credentials` SHALL be read through exactly one of: a hidden terminal prompt when interactive, `--password-stdin`, `--password-file <absolute path>` read with the bootstrap secret-file rules, or `--password-env <NAME>` naming an environment variable whose value is read by the CLI. Supplying more than one input, a flag carrying the secret value itself, a relative or unsafe file, or an unset variable SHALL exit 2 with `INVALID_ARGUMENT` and the accepted-inputs hint before any request. The global `--timeout` remains the request deadline; the connection's statement timeout is `--statement-timeout`. The secret value SHALL never appear in arguments, results, prompts on stdout or errors.

Every mutating command SHALL accept `--dry-run`, forwarding it so the server validates and authorizes without committing, and SHALL render the result marked as a dry run. Results SHALL expose only safe connection records; errors SHALL render the server's `hint` when present, in JSON as `error.hint` and in text on its own line. `CONNECTION_EXISTS`, `CONNECTION_NOT_FOUND`, `CONNECTION_IN_USE`, `CREDENTIALS_UNAVAILABLE`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`. The JSON envelope SHALL keep `schemaVersion` 1, since `hint` is additive.

#### Scenario: Create from automation with a secret file
- **WHEN** an agent runs `connections create --name payments-prod-reporting --provider postgresql --url postgres://reporting@db:5432/payments?sslmode=require --label env=prod --password-file /run/secrets/reporting`
- **THEN** the CLI reads the file, sends one create request, prints the record with `id` and `name` and no secret, and exits 0

#### Scenario: Secret from a named environment variable
- **WHEN** an agent runs `connections set-credentials --connection payments-prod-reporting --password-env REPORTING_PW`
- **THEN** the CLI reads only that variable, never prints its value, and the argument list contains only the variable's name

#### Scenario: Secret value on the command line
- **WHEN** a command receives `--password <value>`, two secret inputs at once, a relative `--password-file` path, or an unset `--password-env` name
- **THEN** it exits 2 with `INVALID_ARGUMENT` and a hint listing the accepted inputs, without contacting the server

#### Scenario: Dry run
- **WHEN** `connections delete --connection x --dry-run` targets an enabled connection
- **THEN** the CLI exits 1 with `CONNECTION_IN_USE`, renders the hint, and the server has changed nothing and recorded nothing

#### Scenario: Selector listing as text
- **WHEN** `connections list --selector env=prod --output text` runs
- **THEN** each connection prints on one line with id, name, provider, status and last check outcome, followed by a truncation notice only when the server reports truncation

#### Scenario: Error hint rendering
- **WHEN** the server answers `CONNECTION_EXISTS` with a hint
- **THEN** JSON output contains `error.hint` and text output prints the hint on a separate line after the message

### Requirement: Grant commands

The CLI SHALL provide `grants list [--user <ref>] [--connection <ref>] [--limit N]`, `grants create --user <ref> --connection <ref> [--dry-run]` and `grants revoke --user <ref> --connection <ref> [--dry-run]`, where a user reference is a UUID or username and a connection reference is a UUID or name, validated locally before any request. The commands SHALL use the stored session, the shared flags, transport, envelope, dry-run and hint conventions of the other groups. Results SHALL render the grant with both identifiers and names; `revoke` SHALL render whether a grant was removed. `USER_NOT_FOUND`, `CONNECTION_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`. Members MAY run `grants list` and see only their own grants.

#### Scenario: Grant by names
- **WHEN** an administrator runs `grants create --user alice --connection payments-prod-reporting`
- **THEN** the CLI sends one request and prints the grant with alice's UUID and username and the connection's UUID and name

#### Scenario: Repeated revoke
- **WHEN** `grants revoke` runs twice for the same pair
- **THEN** the first prints `Revoked: true` and the second `Revoked: false`, both exit 0

#### Scenario: Invalid references
- **WHEN** `--user` or `--connection` is neither a UUID nor a valid name, or a positional argument is present
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Member lists own grants as text
- **WHEN** a member runs `grants list --output text`
- **THEN** each of their grants prints on one line with username, connection name and the grant time, followed by a truncation notice only when the server reports truncation
