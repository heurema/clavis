## ADDED Requirements

### Requirement: Administrative user commands

The CLI SHALL provide `users list`, `users create --username <name>`, `users block --user <uuid>`, `users unblock --user <uuid>`, `users reset-password --user <uuid>` and `users set-role --user <uuid> --role admin|member`. These commands SHALL use the stored session for the selected origin, the same `--server`/`--timeout` flags, origin policy and bounded transport as the other authentication commands, and SHALL call only the documented administration endpoints. `users create` and `users reset-password` SHALL read the password through hidden terminal input or explicit `--password-stdin` with the same validation, bounds and noninteractive rules as `login`; passwords SHALL NOT be accepted through command-line values or environment variables.

Results SHALL keep the schemaVersion 1 envelope and exit codes 0/1/2. JSON and text output SHALL expose only safe user records (`id`, `username`, `role`, `disabled`, `createdAt`), the list's `truncated` flag and, for password resets and blocks, whether sessions were revoked. Passwords, hashes and session tokens SHALL never enter result data. Text output SHALL support the new result types. Server error codes `USERNAME_TAKEN`, `LAST_ADMINISTRATOR`, `USER_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL be passed through as safe application-owned results; undocumented responses SHALL map to `INVALID_RESPONSE`.

#### Scenario: Create a user from automation
- **WHEN** an administrator runs `users create --username alice --password-stdin` with the password on stdin
- **THEN** the CLI creates the account without echoing the password and prints one success result containing the new user's ID, username, role and no password

#### Scenario: Reset a password interactively
- **WHEN** an administrator runs `users reset-password --user <uuid>` from a terminal
- **THEN** the password is read without echo and the result reports the user and that sessions were revoked

#### Scenario: Member runs an administrative command
- **WHEN** a member's stored session runs any `users` command
- **THEN** the CLI exits 1 with `FORBIDDEN` and no mutation occurs

#### Scenario: Demote the last administrator
- **WHEN** `users set-role --role member` targets the only enabled administrator
- **THEN** the CLI exits 1 with `LAST_ADMINISTRATOR` and the role is unchanged

#### Scenario: Invalid administrative arguments
- **WHEN** a `users` command receives a malformed UUID, an unsupported role, a positional argument or a missing password input mode in a noninteractive session
- **THEN** it exits 2 with one safe `INVALID_ARGUMENT` JSON result without contacting the server

#### Scenario: List users as text
- **WHEN** `users list --output text` runs with a valid administrator session
- **THEN** each user is printed on its own line with ID, username, role and status, followed by a truncation notice only when the server reports truncation
