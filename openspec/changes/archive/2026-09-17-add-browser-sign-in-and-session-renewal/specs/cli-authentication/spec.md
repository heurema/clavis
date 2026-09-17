## MODIFIED Requirements

### Requirement: Safe local CLI sign-in

The CLI SHALL sign in only through the browser. `login` SHALL accept no username, password, code or token input: it SHALL NOT read stdin or prompt, and it SHALL NOT define `--username` or `--password-stdin`, so either flag is an invalid invocation that exits 2.

`login` SHALL generate a random 32-byte verifier and a random 32-byte state, listen on `127.0.0.1` at a port the operating system assigns, and print the authorization link for the resolved server to stderr. It SHALL NOT require a terminal. Unless `--no-browser` is given it SHALL then try to open the link with the platform opener, and a failure to open SHALL NOT fail the command. It SHALL wait at most five minutes for one `GET /callback` whose `state` matches, answering every other request on the listener with 400 or 404 and continuing to wait. A matching callback SHALL receive a static page telling the person to return to the terminal, and the CLI SHALL redeem the code with the verifier and store the returned session under the protected storage rules. Five minutes without a matching callback SHALL exit 1 with `TIMEOUT`, and an interruption SHALL exit without storing anything. Links and notices SHALL go to stderr and SHALL NOT corrupt stdout.

#### Scenario: Browser login from a terminal
- **WHEN** a user runs `login` and approves the request in the browser
- **THEN** the CLI prints the authorization link to stderr, opens it, receives the callback, stores a CLI session for the resolved server and emits exactly one success result on stdout

#### Scenario: Login without opening a browser
- **WHEN** a user runs `login --no-browser`, then pastes the printed link into a browser on the same machine and approves
- **THEN** the CLI does not invoke the platform opener and completes the sign-in as in browser login

#### Scenario: Scripted login without a terminal
- **WHEN** a script runs `login --no-browser` with stdin and stderr redirected, reads the link from stderr and completes the browser form and Approve over HTTP
- **THEN** the CLI stores the session and emits one success result

#### Scenario: Browser cannot be opened
- **WHEN** the platform opener is missing or fails
- **THEN** the CLI keeps waiting with the link already printed and completes when the person approves through it

#### Scenario: Nobody approves
- **WHEN** no matching callback arrives within five minutes
- **THEN** the CLI exits 1 with `TIMEOUT`, closes the listener and leaves any stored session unchanged

#### Scenario: Forged callback
- **WHEN** a request reaches the callback listener with a missing or different `state`
- **THEN** the CLI does not redeem its code, answers without the success page and keeps waiting for the matching callback

#### Scenario: Redemption refused
- **WHEN** the server answers the code redemption with `INVALID_CREDENTIALS`
- **THEN** the CLI exits 1 with that code and a working stored session for the origin is not replaced

#### Scenario: Password flags are refused
- **WHEN** a caller runs `login --username alice` or `login --password-stdin` with a password on stdin
- **THEN** the command exits 2 with `INVALID_ARGUMENT` JSON without reading stdin, listening or contacting the server

### Requirement: Authoritative identity and explicit sign-out

The CLI SHALL provide `whoami`, `logout` and administrator `sessions revoke --user <uuid-or-username>`. Current identity SHALL be verified with the server, not inferred from cache, and `whoami` SHALL report the session's absolute expiry as `expiresAt` and its idle expiry as `idleExpiresAt`, the names of the connections the caller can effectively use through direct grants and group memberships, each once, with a truncation flag, and the names of the groups the caller belongs to with their own truncation flag; administrators see an empty connection list because they need no grants. The CLI SHALL NOT refuse a command locally because a stored expiry has passed; the server's answer decides. Logout SHALL attempt remote revocation and remove the matching local credential even when the server is unreachable, while reporting unconfirmed remote revocation as failure. Missing local credentials and confirmed invalid/expired server sessions SHALL make logout an idempotent success.

#### Scenario: Verify an active identity
- **WHEN** whoami runs with a valid cached session
- **THEN** the server-confirmed user, `expiresAt`, `idleExpiresAt`, effective connection names and group names are returned without the token

#### Scenario: Remote session is revoked
- **WHEN** whoami uses a session revoked through another client
- **THEN** it reports an authentication failure instead of presenting cached identity as active

#### Scenario: Stored expiry has passed on the local clock
- **WHEN** the stored `expiresAt` is in the past according to the local clock but the server still accepts the session
- **THEN** whoami sends the request and reports the server's answer

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

### Requirement: Authentication preserves CLI output conventions

Authentication commands SHALL preserve the schemaVersion 1 result envelope and exit codes 0 for success, 1 for operation failure and 2 for invalid arguments/configuration. Every result of a command that resolved a server SHALL carry the top-level fields `server` (the canonical origin) and `profile` (the profile name, empty when the server was given with `--server`), on success and on failure alike; a result produced before a server was resolved SHALL omit both. These fields are additive and `schemaVersion` SHALL stay 1. Text output of such a result SHALL print the server, and the profile when there is one, on its first line, before any error line. Invalid invocation SHALL force JSON output. JSON and text SHALL expose only safe identity, expiry and operation outcomes; a login or whoami result SHALL carry both `expiresAt` and `idleExpiresAt`, and its text output SHALL print both. Session tokens, authorization links, codes, verifiers and passwords SHALL never enter result data. Offline help, version, `skill` commands and Go-only CLI builds SHALL remain independent of authentication and web tooling and SHALL NOT read the client configuration or stored credentials.

#### Scenario: Successful login output
- **WHEN** login completes and safely stores its session
- **THEN** stdout contains one success result with user, `expiresAt`, `idleExpiresAt`, `server` and `profile` but no token, code or password, and the command exits 0

#### Scenario: Result names the server and profile
- **WHEN** the current profile is `fce` and `whoami` succeeds
- **THEN** the result carries `server` set to the `fce` origin and `profile: "fce"`

#### Scenario: Failure names the server
- **WHEN** `whoami --profile fce` cannot reach its server
- **THEN** the result has `ok: false`, `error.code` `SERVER_UNREACHABLE`, `server` set to the `fce` origin and `profile: "fce"`

#### Scenario: One-off server
- **WHEN** `whoami --server https://clavis.example.com` runs
- **THEN** the result carries `server: "https://clavis.example.com"` and `profile: ""`

#### Scenario: Text output names the server
- **WHEN** `connections list --output text` runs through profile `fce`
- **THEN** the first line names the `fce` origin and the profile, followed by the usual connection lines

#### Scenario: Invalid arguments with text requested
- **WHEN** an authentication command receives invalid flags, URL, timeout or positional arguments with text output requested
- **THEN** it exits 2 with one safe JSON invalid-argument result

#### Scenario: Local offline operation
- **WHEN** help/version, a `skill` command or a CLI-only build runs without a server or web tools, with a corrupt `config.toml` and an unsafe `sessions` directory
- **THEN** it continues to work without reading the configuration, loading stored credentials or contacting an authentication endpoint

### Requirement: Administrative user commands

The CLI SHALL provide `users list`, `users create --username <name>`, `users block --user <uuid-or-username>`, `users unblock --user <uuid-or-username>`, `users reset-password --user <uuid-or-username>` and `users set-role --user <uuid-or-username> --role admin|member`. These commands SHALL use the stored session for the selected origin, the same `--server`/`--timeout` flags, origin policy and bounded transport as the other authentication commands, and SHALL call only the documented administration endpoints. `users create` and `users reset-password` SHALL read the password through hidden terminal input or explicit `--password-stdin` under the same newline, validation and bound rules as bootstrap; noninteractive input without `--password-stdin` SHALL fail rather than wait for a prompt, and prompts SHALL NOT corrupt stdout. Passwords SHALL NOT be accepted through command-line values or environment variables.

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

### Requirement: Server resolution

Every command that contacts a server, including `login` and `doctor`, SHALL resolve exactly one server and the Clavis home before any credential, secret or statement input, callback listener, cache access or network I/O, in this order: `--server URL` or `--profile NAME` on the command line; otherwise `CLAVIS_PROFILE` in the environment, where an empty value counts as unset; otherwise the configuration's `current`. Supplying both `--server` and `--profile`, or either flag with an empty value, SHALL exit 2 with `INVALID_ARGUMENT`; a `--profile` or `CLAVIS_PROFILE` value that fails the profile-name rule SHALL exit 2 with `INVALID_ARGUMENT` before the configuration is read and without echoing the value; a later step is not consulted once an earlier one decides. `CLAVIS_SERVER_URL` SHALL NOT be read. A profile name from a flag, the environment or `current` SHALL be looked up in the configuration, and an unknown one SHALL exit 2 with `INVALID_ARGUMENT` and a hint naming `profiles list`. The configuration SHALL be read only when resolution reaches a profile, so a server given with `--server` never depends on the file. Every resolved server SHALL pass the canonical-origin rule. When no step yields a server the command SHALL exit 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`; there SHALL be no built-in default server.

#### Scenario: Current profile
- **WHEN** the current profile is `fce` and a user runs `whoami` with no flag or variable
- **THEN** the request goes to the `fce` server

#### Scenario: Flag beats environment
- **WHEN** `CLAVIS_PROFILE=local` is set and an agent runs `connections list --profile fce`
- **THEN** the request goes to the `fce` server

#### Scenario: Environment beats current
- **WHEN** `current` is `fce`, `CLAVIS_PROFILE=local` is set, and an agent runs `whoami`
- **THEN** the request goes to the `local` server

#### Scenario: Sign in through the current profile
- **WHEN** the current profile is `fce` and a user runs `login` and approves in the browser
- **THEN** the authorization link names the `fce` server and the session is stored for its origin

#### Scenario: Conflicting flags
- **WHEN** a command receives both `--server` and `--profile`
- **THEN** it exits 2 with `INVALID_ARGUMENT` without reading a password or credential, listening for a callback, opening storage or contacting a server

#### Scenario: Former server variable is ignored
- **WHEN** only `CLAVIS_SERVER_URL=https://clavis.example.com` is set and a user runs `whoami`
- **THEN** it exits 2 with `INVALID_ARGUMENT` and the `profiles set` hint, and no request is sent

#### Scenario: Nothing configured
- **WHEN** a user with no configuration file and no variable runs `whoami`
- **THEN** it exits 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`, and no request is sent to `127.0.0.1:8080` or anywhere else

#### Scenario: Direct server ignores a broken file
- **WHEN** `config.toml` is corrupt and an agent runs `whoami --server https://clavis.example.com`
- **THEN** the configuration is not read and the command proceeds against that server

#### Scenario: Corrupt file before listening
- **WHEN** `config.toml` is corrupt, `fce` is named by `--profile`, and a user runs `login --profile fce`
- **THEN** it exits 2 with `INVALID_ARGUMENT` naming the file before a callback listener is opened or any request is sent

#### Scenario: Relative Clavis home
- **WHEN** `CLAVIS_HOME=relative/dir` is set and a user runs `users create --server https://clavis.example.com --username alice --password-stdin`
- **THEN** it exits 2 with `INVALID_ARGUMENT` naming `CLAVIS_HOME` before stdin is read or any request is sent
