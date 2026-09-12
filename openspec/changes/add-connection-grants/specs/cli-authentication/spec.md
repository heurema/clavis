## MODIFIED Requirements

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

## ADDED Requirements

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
