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

The CLI SHALL store session credentials outside the project in the `sessions` directory of the Clavis home (`CLAVIS_HOME` or `~/.clavis`), keyed by canonical server origin, so that two profiles naming one server share one session. Authentication commands SHALL reject base-path URLs for this milestone and require HTTPS except literal loopback HTTP. The path to the Clavis home SHALL be traversed without following symlinks, so a symlink at any component, the home included, SHALL be a storage failure. Each ancestor SHALL be owned by the user or root and not group- or world-writable, root-owned sticky directories excepted, and missing components SHALL be created with owner-only mode. The home itself SHALL be owned by the user and not group- or world-writable. The `sessions` directory SHALL be a real directory with exactly owner-only permissions, and session and lock files SHALL be owner-only regular files with safe ownership, bounded contents and atomic updates, with symlink and nonregular-file rejection. A storage failure SHALL name the offending path and the required mode without displaying credentials. Credential-changing commands SHALL serialize per origin. Failed login SHALL NOT overwrite a working cached credential. Sessions stored in the former operating-system configuration directory SHALL NOT be read, migrated or deleted.

#### Scenario: Sign in to different servers
- **WHEN** the user signs in to two distinct canonical origins
- **THEN** the sessions are stored independently and requests to one origin never use the other's token

#### Scenario: Two profiles share a server
- **WHEN** profiles `prod` and `prod-admin` name the same origin and the user signs in through `prod`
- **THEN** a command run with `--profile prod-admin` uses that same stored session

#### Scenario: Home created under a normal umask
- **WHEN** `~/.clavis` has mode 0755 and `sessions` inside it has mode 0700
- **THEN** login stores the session and later commands use it

#### Scenario: Unsafe or symlinked home, or unsafe sessions directory
- **WHEN** the Clavis home is group-writable or a symlink, or `sessions` has mode 0755 or is a symlink
- **THEN** the command fails with `CREDENTIAL_STORAGE_FAILED` whose message names that path and the required mode, and no token is read or written

#### Scenario: Unsafe or failed cache write
- **WHEN** local credential storage is unsafe or persistence fails after token issuance
- **THEN** login does not report success or print the token
- **AND** the CLI attempts bounded best-effort revocation and reports a safe credential-storage failure

#### Scenario: Concurrent login and logout
- **WHEN** credential-changing processes target the same origin concurrently
- **THEN** bounded locking prevents partial writes or one logout deleting a newly replaced unrelated session

#### Scenario: Upgrade from the former location
- **WHEN** a user signed in with an earlier CLI and upgrades
- **THEN** commands report `UNAUTHENTICATED` until the user signs in again, and the former session files are left untouched

### Requirement: Authoritative identity and explicit sign-out

The CLI SHALL provide `whoami`, `logout` and administrator `sessions revoke --user <uuid-or-username>`. Current identity SHALL be verified with the server, not inferred from cache, and `whoami` SHALL report the names of the connections the caller can effectively use through direct grants and group memberships, each once, with a truncation flag, and the names of the groups the caller belongs to with their own truncation flag; administrators see an empty connection list because they need no grants. Logout SHALL attempt remote revocation and remove the matching local credential even when the server is unreachable, while reporting unconfirmed remote revocation as failure. Missing local credentials and confirmed invalid/expired server sessions SHALL make logout an idempotent success.

#### Scenario: Verify an active identity
- **WHEN** whoami runs with a valid cached session
- **THEN** the server-confirmed user, expiry, effective connection names and group names are returned without the token

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

Authentication requests SHALL use a single documented whole-request deadline, bounded request and response bodies, strict status/body validation and no redirects or automatic mutation retries. Bounds SHALL be per route: the general request and response limits apply everywhere except the documented listings, which read up to the listing limit, and the query route, whose request carries up to 256 KiB of SQL and whose response is read up to twice the byte-cap ceiling plus the envelope allowance; a body above its route's bound SHALL be reported as `INVALID_RESPONSE` (response) or refused locally with `INVALID_ARGUMENT` (request). Credentials SHALL never be forwarded to a redirect destination. Malformed responses and transport errors SHALL be mapped to application-owned errors without exposing raw server content.

#### Scenario: Credential request redirects
- **WHEN** login or a bearer request receives a redirect
- **THEN** the CLI does not contact the destination and reports `INVALID_RESPONSE`

#### Scenario: Stalled or malformed authentication response
- **WHEN** the response body stalls, exceeds its limit or contains an undocumented status/body combination with sentinel secrets
- **THEN** the CLI terminates within the deadline with a safe timeout/invalid-response result and does not display the body

#### Scenario: Query bodies use their own bounds
- **WHEN** a query sends 200 KiB of SQL and receives a 5 MiB result on a connection capped at 8 MiB
- **THEN** both pass, while the same result on a connection capped at 1 MiB is reported as `INVALID_RESPONSE` rather than partially displayed

### Requirement: Authentication preserves CLI output conventions

Authentication commands SHALL preserve the schemaVersion 1 result envelope and exit codes 0 for success, 1 for operation failure and 2 for invalid arguments/configuration. Every result of a command that resolved a server SHALL carry the top-level fields `server` (the canonical origin) and `profile` (the profile name, empty when the server was given with `--server`), on success and on failure alike; a result produced before a server was resolved SHALL omit both. These fields are additive and `schemaVersion` SHALL stay 1. Text output of such a result SHALL print the server, and the profile when there is one, on its first line, before any error line. Invalid invocation SHALL force JSON output. JSON and text SHALL expose only safe identity, expiry and operation outcomes; session tokens and passwords SHALL never enter result data. Offline help, version, `skill` commands and Go-only CLI builds SHALL remain independent of authentication and web tooling and SHALL NOT read the client configuration or stored credentials.

#### Scenario: Successful login output
- **WHEN** login completes and safely stores its session
- **THEN** stdout contains one success result with user/expiry, `server` and `profile` but no token or password, and the command exits 0

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

The CLI SHALL provide `connections list [--selector <terms>] [--limit N]`, `connections get --connection <id>`, `connections create --name <slug> --provider <type> --url <target> [--label key=value]... [--title] [--description] [--scope] [--statement-timeout] [--max-rows] [--max-bytes] [--auth] [--auth-user] [--auth-header] [--account-id N] [--project-id N]`, `connections update --connection <id> [same fields]` (labels and the target are replaced whole; any target flag on update requires `--url`), `connections set-credentials --connection <id>`, `connections enable|disable|delete --connection <id>` and `connections check --connection <id>`, where `<id>` is a UUID or a name. These commands SHALL use the stored session, the `--server`/`--timeout` flags, origin policy, bounded transport and result envelope of the other authenticated commands, SHALL call only the documented connection routes, and SHALL use one verb vocabulary shared with `users`. `--account-id` and `--project-id` are the `victorialogs` tenant settings, sent as target settings and refused by the server for any other provider.

Secrets for `create` and `set-credentials` SHALL be read through exactly one of: a hidden terminal prompt when interactive, `--password-stdin`, `--password-file <absolute path>` read with the bootstrap secret-file rules, or `--password-env <NAME>` naming an environment variable whose value is read by the CLI. Supplying more than one input, a flag carrying the secret value itself, a relative or unsafe file, or an unset variable SHALL exit 2 with `INVALID_ARGUMENT` and the accepted-inputs hint before any request. The global `--timeout` remains the request deadline; the connection's statement timeout is `--statement-timeout`. The secret value SHALL never appear in arguments, results, prompts on stdout or errors.

Every mutating command SHALL accept `--dry-run`, forwarding it so the server validates and authorizes without committing, and SHALL render the result marked as a dry run. Results SHALL expose only safe connection records; errors SHALL render the server's `hint` when present, in JSON as `error.hint` and in text on its own line. `CONNECTION_EXISTS`, `CONNECTION_NOT_FOUND`, `CONNECTION_IN_USE`, `CREDENTIALS_UNAVAILABLE`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`. The JSON envelope SHALL keep `schemaVersion` 1, since `hint` is additive.

#### Scenario: Create from automation with a secret file
- **WHEN** an agent runs `connections create --name payments-prod-reporting --provider postgresql --url postgres://reporting@db:5432/payments?sslmode=require --label env=prod --password-file /run/secrets/reporting`
- **THEN** the CLI reads the file, sends one create request, prints the record with `id` and `name` and no secret, and exits 0

#### Scenario: Log connection with a tenant
- **WHEN** an agent runs `connections create --name payments-logs --provider victorialogs --url http://vlogs:9428 --auth bearer --account-id 12 --password-env LOGS_TOKEN`
- **THEN** the CLI sends the target with `accountId` 12 and no `projectId`, prints the record with both settings visible and no secret, and exits 0; the same flag with `--provider postgresql` is refused by the server with `INVALID_ARGUMENT`, passed through with its hint

#### Scenario: Secret from a named environment variable
- **WHEN** an agent runs `connections set-credentials --connection payments-prod-reporting --password-env REPORTING_PW`
- **THEN** the CLI reads only that variable, never prints its value, and the argument list contains only the variable's name

#### Scenario: Secret value on the command line
- **WHEN** a command receives `--password <value>`, two secret inputs at once, a relative `--password-file` path, or an unset `--password-env` name
- **THEN** it exits 2 with `INVALID_ARGUMENT` and a hint listing the accepted inputs, without contacting the server

#### Scenario: Dry run
- **WHEN** `connections delete --connection x --dry-run` targets an enabled connection
- **THEN** the CLI exits 1 with `CONNECTION_IN_USE`, renders the hint, and the server has changed nothing

#### Scenario: Selector listing as text
- **WHEN** `connections list --selector env=prod --output text` runs
- **THEN** each connection prints on one line with id, name, provider, status and last check outcome, followed by a truncation notice only when the server reports truncation

#### Scenario: Error hint rendering
- **WHEN** the server answers `CONNECTION_EXISTS` with a hint
- **THEN** JSON output contains `error.hint` and text output prints the hint on a separate line after the message

### Requirement: Grant commands

The CLI SHALL provide `grants list [--user <ref> | --group <ref>] [--connection <ref>] [--limit N] [--effective]`, `grants create (--user <ref> | --group <ref>) --connection <ref> [--dry-run]` and `grants revoke (--user <ref> | --group <ref>) --connection <ref> [--dry-run]`, where a user reference is a UUID or username, a group reference is a UUID or name and a connection reference is a UUID or name, validated locally for syntax and flag exclusivity before any request. `create` and `revoke` SHALL require exactly one of `--user` and `--group`; `list` SHALL accept at most one of them, and `--effective` SHALL refuse `--group` locally and send `--user` as given or omitted, leaving the role-dependent default and refusal to the server. The commands SHALL use the stored session, the shared flags, transport, envelope, dry-run and hint conventions of the other groups; listings SHALL be read under the listing response limit. Results SHALL render the grant with the recipient kind, both identifiers and names; `revoke` SHALL render whether a grant was removed; the effective listing SHALL render the subject's username, role and status, then one line per connection and path naming the source and, for a group path, the group, and SHALL validate that a `group` entry carries a group and a `direct` entry does not. `USER_NOT_FOUND`, `GROUP_NOT_FOUND`, `CONNECTION_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`. Members MAY run `grants list` and see only their own direct grants, and `grants list --effective` for their own grant paths.

#### Scenario: Grant by names
- **WHEN** an administrator runs `grants create --user alice --connection payments-prod-reporting`
- **THEN** the CLI sends one request and prints the grant with a `user` recipient carrying alice's UUID and username and the connection's UUID and name

#### Scenario: Grant to a group
- **WHEN** an administrator runs `grants create --group finance-managers --connection payments-prod-reporting`
- **THEN** the CLI sends one request and prints the grant with a `group` recipient carrying the group's UUID and name

#### Scenario: Repeated revoke
- **WHEN** `grants revoke` runs twice for the same pair
- **THEN** the first prints `Revoked: true` and the second `Revoked: false`, both exit 0

#### Scenario: Invalid references
- **WHEN** `--user`, `--group` or `--connection` is neither a UUID nor a valid name, both `--user` and `--group` are given, neither is given to a mutation, `--effective` is combined with `--group`, or a positional argument is present
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Grant paths as text
- **WHEN** an administrator runs `grants list --user alice --effective --output text`
- **THEN** alice's username, role and status print first, then each path on one line with the connection name, `direct` or the group name, and the grant time, followed by a truncation notice only when the server reports truncation

#### Scenario: Member inspects own paths
- **WHEN** a member runs `grants list --effective` without `--user`, or with their own username
- **THEN** the CLI sends the request as given and prints their own paths; with another user's reference the server answers `FORBIDDEN` and the CLI exits 1 with that code

#### Scenario: Administrator omits the subject
- **WHEN** an administrator runs `grants list --effective` without `--user`
- **THEN** the server answers `INVALID_ARGUMENT` with a hint naming `--user`, which the CLI renders and exits 2, as it does for every invalid-argument answer

#### Scenario: Member lists own grants as text
- **WHEN** a member runs `grants list --output text`
- **THEN** each of their direct grants prints on one line with the recipient, connection name and the grant time, followed by a truncation notice only when the server reports truncation

### Requirement: Query command

The CLI SHALL provide `query --connection <ref> (--sql <text> | --sql-stdin | --sql-file <path> | --promql <expr> | --promql-stdin | --promql-file <path> | --labels | --label-values <name> | --series <selector> | --logsql <query> | --logsql-stdin | --logsql-file <path> | --field-names | --field-values <name> | --streams | --stream-field-names | --stream-field-values <name>) [--at <time>] [--start <time>] [--end <time>] [--step <duration>] [--match <selector or query>] [--limit N] [--filter <substring>] [--max-rows N]`, where `<ref>` is a UUID or name, exactly one input is required, the file inputs take absolute paths, the SQL, expression, query or `--match` text is bounded to 256 KiB before any request, `--at` applies only to `--promql` without `--start`, `--step` requires `--start`, `--match`, `--start` and `--end` apply to PromQL and discovery inputs only, a label name is validated locally, a field name is bounded only, `--limit` is a non-negative integer forwarded as the source's own limit and never added by the CLI, `--filter` is a substring, both apply to the LogsQL and log discovery inputs only, and every log discovery input requires `--match`. Time strings, steps, selectors, queries, limits and filters are sent exactly as typed. The command SHALL use the stored session, the shared flags, transport, envelope and hint conventions of the other groups, except that its `--timeout` SHALL default to the documented query budget rather than five seconds so a statement running to the connection's bound is not cut off by the client, SHALL send one request to the query route and SHALL render the results document in JSON or as text: `psql`-style tables for PostgreSQL, and for VictoriaMetrics one line per vector sample with sorted labels, a block per matrix series, one line per scalar, string or discovery item, with the source's warnings first, and for VictoriaLogs one physical line per row (`_time`, `_msg`, the remaining fields as sorted `key=value`, `_stream` and `_stream_id` last, names and values quoted when they contain whitespace, quotes, backslashes, control characters or `=`) and `value<TAB>hits` per discovery item. `SOURCE_ERROR`, `SOURCE_TIMEOUT`, `SOURCE_UNREACHABLE`, `SOURCE_AUTH_REJECTED`, `CREDENTIALS_UNAVAILABLE`, `PROVIDER_UNSUPPORTED`, `CONNECTION_NOT_FOUND`, `CONNECTION_DISABLED`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through; undocumented responses SHALL map to `INVALID_RESPONSE`. A truncated result SHALL exit 0 with the truncation visible in both outputs; every failure code SHALL exit 1; invalid arguments SHALL exit 2. The SQL, expression or query SHALL NOT be echoed in results or errors. A provider mismatch reported by the server SHALL pass through as `INVALID_ARGUMENT` with its hint.

#### Scenario: Inline query as JSON
- **WHEN** an agent runs `query --connection payments-prod-reporting --sql 'select count(*) from orders'`
- **THEN** the CLI prints one envelope whose `data.results[0]` carries the column list and one row of strings, exit 0

#### Scenario: Source error as text
- **WHEN** a text-output query fails with a PostgreSQL syntax error
- **THEN** the CLI prints `ERROR: <sqlstate> <message>` with the position line and the statement index, exits 1, and the SQL is not repeated

#### Scenario: Invalid inputs
- **WHEN** the reference is invalid, `--max-rows` is not a positive integer, two inputs are given, the file path is relative, `--at` is combined with `--start`, `--step` lacks `--start`, a time flag accompanies `--sql`, a label name is not a Prometheus label name, `--limit` is negative, `--filter` or `--limit` accompanies a SQL or PromQL input, or a log discovery input lacks `--match`
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Instant PromQL as JSON
- **WHEN** an agent runs `query --connection payments-metrics --promql 'up'`
- **THEN** the CLI prints one envelope whose `data.provider` is `victoriametrics`, `data.resultType` is `vector` and `data.result` is the source's vector unchanged, exit 0

#### Scenario: Metric names as text
- **WHEN** an agent runs `query --connection payments-metrics --label-values __name__ --output text`
- **THEN** each metric name prints on its own line followed by the truncation notice only when the server reports truncation

#### Scenario: Log rows as JSON
- **WHEN** an agent runs `query --connection payments-logs --logsql 'error' --limit 20`
- **THEN** the CLI prints one envelope whose `data.provider` is `victorialogs`, `data.resultType` is `logs` and `data.result` is the source's rows unchanged, exit 0

#### Scenario: Log rows as text
- **WHEN** a text-output log query returns a row whose `_msg` spans two lines
- **THEN** the row prints as one physical line with `_time` first, the message quoted, the other fields sorted and `_stream` last, followed by the truncation notice only when the server reports truncation

#### Scenario: LogsQL error as text
- **WHEN** a text-output log query is rejected by the source
- **THEN** the CLI prints `ERROR: http_400 <message>` with no position or statement line, exits 1, and the query is not repeated

#### Scenario: PromQL error as text
- **WHEN** a text-output PromQL query fails to parse on the source
- **THEN** the CLI prints `ERROR: <errorType> <message>` with no position or statement line, exits 1, and the expression is not repeated

### Requirement: Group management commands

The CLI SHALL provide `groups list [--limit N]`, `groups get --group <ref>`, `groups create --name <slug> [--description <text>]`, `groups update --group <ref> [--name <slug>] [--description <text>]`, `groups delete --group <ref>`, `groups members --group <ref> [--limit N]`, `groups add-member --group <ref> --user <ref>` and `groups remove-member --group <ref> --user <ref>`, where a group reference is a UUID or a name and a user reference is a UUID or a username, validated locally before any request. These commands SHALL use the stored session, the `--server`/`--timeout` flags, origin policy, bounded transport and result envelope of the other authenticated commands, SHALL read the group and member listings under the listing response limit, SHALL call only the documented group routes, and SHALL use the verb vocabulary shared with `users`, `connections` and `grants`. Every mutating command SHALL accept `--dry-run`. Results SHALL expose only group records, membership results and safe user records; errors SHALL render the server's `hint` when present. `GROUP_EXISTS`, `GROUP_NOT_FOUND`, `GROUP_IN_USE`, `USER_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`.

#### Scenario: Create and populate a group
- **WHEN** an administrator runs `groups create --name finance-managers --description "Finance managers"` and then `groups add-member --group finance-managers --user alice`
- **THEN** the first command prints the record with `id`, `name`, zero members and zero grants, and the second prints the membership with both identifiers and names and `added: true`

#### Scenario: Guarded delete as a dry run
- **WHEN** `groups delete --group finance-managers --dry-run` targets a group that still holds grants
- **THEN** the CLI exits 1 with `GROUP_IN_USE`, renders the hint with the remaining count, and the server has changed nothing

#### Scenario: Members as text
- **WHEN** `groups members --group finance-managers --output text` runs
- **THEN** each member prints on one line with ID, username, status and the time they were added, followed by a truncation notice only when the server reports truncation

#### Scenario: Invalid group arguments
- **WHEN** a `groups` command receives a reference that is neither a UUID nor a valid name, a name outside the grammar, a positional argument, or `update` without any field
- **THEN** it exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Member runs a group command
- **WHEN** a member's stored session runs any `groups` command
- **THEN** the CLI exits 1 with `FORBIDDEN` and no mutation occurs

### Requirement: Client profiles

The CLI SHALL keep client configuration in `config.toml` inside the Clavis home, which is `CLAVIS_HOME` when set and non-empty (an absolute path, otherwise `INVALID_ARGUMENT`) and `~/.clavis` otherwise. The file SHALL hold an optional top-level `current` naming a profile and a `profiles` table whose entries each carry exactly one key, `server`. A profile name SHALL be 1 to 64 characters, a lowercase letter followed by lowercase letters, digits, `.`, `_` or `-`, reported with its own error message and hint. The file SHALL never hold a secret, SHALL be read up to 64 KiB (a larger file is `INVALID_ARGUMENT`), SHALL be decoded strictly with keys matched exactly, and SHALL be loaded whole or not at all: a file that does not parse, an unknown key, an invalid profile name, a profile without a `server` passing the canonical-origin rule or a `current` naming a missing profile SHALL fail with `INVALID_ARGUMENT` naming the file and the offending key. An absent file SHALL mean no profiles and no current profile. A `config.toml` that is a symlink or not a regular file SHALL be refused with `INVALID_ARGUMENT` naming the path. Writes SHALL serialize under a lock in the Clavis home, re-read the file under that lock and replace it atomically. A write that cannot complete SHALL leave the file unchanged and exit 1: an unsafe Clavis home with `CREDENTIAL_STORAGE_FAILED`, a lock not acquired within the shared five-second deadline with `TIMEOUT`, and any other lock, encoding or file-system failure with `CONFIGURATION_WRITE_FAILED` naming the path. Only the `profiles` commands SHALL write the file; `login` and every other command SHALL NOT.

The CLI SHALL provide `profiles set <name> --server <url>`, `profiles use <name>`, `profiles current`, `profiles list` and `profiles remove <name>`; `set`, `use` and `remove` take the name as their only positional argument and `current` and `list` take none. They SHALL be local commands that never contact a server and SHALL NOT carry the envelope's `server` and `profile` fields. Their data SHALL be:

- `set`: `{name, server, created, madeCurrent}`. It creates the profile or replaces its server with the canonical origin, and sets `current` only when the file has none. It SHALL NOT read or change any session.
- `use`: `{profile, override}`. It SHALL fail on an unknown name, read the stored session for the profile's server, and only then set `current`, so a storage failure leaves the file unchanged.
- `current`: `{profile, source}`, where `source` is `environment` when `CLAVIS_PROFILE` names the profile and `config` otherwise. With neither it SHALL exit 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`.
- `list`: `{current, override, profiles}`, the profiles sorted by name.
- `remove`: `{name, currentCleared}`. Removing the current profile SHALL clear `current` and report `currentCleared: true`. It SHALL NOT read, change or delete any session.

A profile entry is `{name, server, current, session}`, where `current` is true for the file's `current` and `session` is `{username, expiresAt}` from the locally stored session for that server, or `null` when there is none. `override` is the value of `CLAVIS_PROFILE`, or empty; a `CLAVIS_PROFILE` that fails the profile-name rule SHALL make `use`, `current` and `list` exit 2 with `INVALID_ARGUMENT` naming the variable, and a well-formed one naming no profile SHALL still be reported by `use` and `list`. Session reads SHALL use the protected storage checks, SHALL NOT create the Clavis home, the `sessions` directory or any lock file, SHALL NOT wait for a session lock, and an unsafe or corrupt store SHALL fail the whole command with `CREDENTIAL_STORAGE_FAILED`. The stored expiry is reported as stored and SHALL NOT be presented as verification; text output SHALL label it "Stored session". An unknown name SHALL exit 2 with `INVALID_ARGUMENT` and a hint naming `profiles list`. Results SHALL use the schemaVersion 1 envelope with a text rendering in which `list` marks the current profile with `*`, and `use` and `list` print a note when `override` is set and differs from the file's `current`, stating either that it selects that profile in this environment or that it names no profile and networked commands there exit 2. No result SHALL contain a token.

#### Scenario: First profile becomes current
- **WHEN** a user with no configuration file runs `profiles set fce --server https://clavis.example.com/`
- **THEN** `config.toml` holds profile `fce` with server `https://clavis.example.com` and `current = "fce"`, the result reports `created: true` and `madeCurrent: true`, and no network request is made

#### Scenario: A second profile leaves current alone
- **WHEN** `fce` is current and the user runs `profiles set local --server http://127.0.0.1:8080`
- **THEN** profile `local` is added, `current` stays `fce`, and the result reports `madeCurrent: false`

#### Scenario: Change a profile's server
- **WHEN** the user runs `profiles set fce --server https://clavis2.example.com` for an existing profile with a stored session for its former server
- **THEN** the profile's server is replaced, the result reports `created: false`, and the session file for the former server is untouched

#### Scenario: Switch the current profile
- **WHEN** a user runs `profiles use local --output text` with a stored session for `http://127.0.0.1:8080`
- **THEN** `current` becomes `local` and the output names the profile, the server and the stored username and expiry as a stored session, without any network request

#### Scenario: Environment overrides current
- **WHEN** `CLAVIS_PROFILE=fce` is set and the user runs `profiles use local`
- **THEN** `current` becomes `local`, the result reports `override: "fce"`, and text output notes that `CLAVIS_PROFILE` still selects `fce` in this environment

#### Scenario: Environment names no profile
- **WHEN** `CLAVIS_PROFILE=staging` is set, no profile `staging` exists, and the user runs `profiles list --output text`
- **THEN** the command exits 0, reports `override: "staging"`, and the note says that `staging` names no profile and networked commands in this environment exit 2

#### Scenario: Invalid profile arguments
- **WHEN** `profiles set` runs without `--server`, with a server failing the canonical-origin rule or with an invalid name, `profiles use` or `remove` runs without a name or with two, or `profiles list` or `current` receives a positional argument
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, and `config.toml` is unchanged

#### Scenario: Show the profile in effect
- **WHEN** `current` is `local` and `CLAVIS_PROFILE=fce` is set, and the user runs `profiles current`
- **THEN** the result reports profile `fce` with `source: "environment"`; without the variable it reports `local` with `source: "config"`

#### Scenario: Nothing current
- **WHEN** a user with no configuration file and no `CLAVIS_PROFILE` runs `profiles current`
- **THEN** it exits 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`

#### Scenario: List profiles as text
- **WHEN** `profiles list --output text` runs with profiles `fce` (current, signed in as alice) and `local` (no session)
- **THEN** each profile prints on one line, `fce` marked with `*` and showing alice and the stored expiry, `local` showing that it is not signed in

#### Scenario: Remove the current profile
- **WHEN** a user runs `profiles remove fce` while `fce` is current and has a stored session
- **THEN** `fce` is removed, `current` is cleared, the result reports `currentCleared: true`, the session file is still present, and a following `whoami` without flags exits 2 with the `profiles set` hint

#### Scenario: Unsafe storage while switching
- **WHEN** the `sessions` directory has mode 0755 and a user runs `profiles use local`
- **THEN** the command exits 1 with `CREDENTIAL_STORAGE_FAILED` naming the path and `config.toml` is unchanged

#### Scenario: Login never writes the configuration
- **WHEN** a user signs in with `login`, with or without `--profile` or `CLAVIS_PROFILE`
- **THEN** `config.toml` is neither created nor modified

#### Scenario: Corrupt configuration
- **WHEN** `config.toml` contains an unknown key `output = "text"` and a command needs the configuration
- **THEN** it exits 2 with `INVALID_ARGUMENT` naming the file and the key, and does not act on any profile it did contain

#### Scenario: Symlinked configuration file
- **WHEN** `config.toml` is a symlink to a valid file
- **THEN** every command that needs the configuration exits 2 with `INVALID_ARGUMENT` naming the path, and the link's target is unchanged

### Requirement: Server resolution

Every command that contacts a server, including `login` and `doctor`, SHALL resolve exactly one server and the Clavis home before any credential, secret or statement input, cache access or network I/O, in this order: `--server URL` or `--profile NAME` on the command line; otherwise `CLAVIS_PROFILE` in the environment, where an empty value counts as unset; otherwise the configuration's `current`. Supplying both `--server` and `--profile`, or either flag with an empty value, SHALL exit 2 with `INVALID_ARGUMENT`; a `--profile` or `CLAVIS_PROFILE` value that fails the profile-name rule SHALL exit 2 with `INVALID_ARGUMENT` before the configuration is read and without echoing the value; a later step is not consulted once an earlier one decides. `CLAVIS_SERVER_URL` SHALL NOT be read. A profile name from a flag, the environment or `current` SHALL be looked up in the configuration, and an unknown one SHALL exit 2 with `INVALID_ARGUMENT` and a hint naming `profiles list`. The configuration SHALL be read only when resolution reaches a profile, so a server given with `--server` never depends on the file. Every resolved server SHALL pass the canonical-origin rule. When no step yields a server the command SHALL exit 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`; there SHALL be no built-in default server.

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
- **WHEN** the current profile is `fce` and a user runs `login --username alice`
- **THEN** the session is stored for the `fce` server's origin

#### Scenario: Conflicting flags
- **WHEN** a command receives both `--server` and `--profile`
- **THEN** it exits 2 with `INVALID_ARGUMENT` without reading a password or credential, opening storage or contacting a server

#### Scenario: Former server variable is ignored
- **WHEN** only `CLAVIS_SERVER_URL=https://clavis.example.com` is set and a user runs `whoami`
- **THEN** it exits 2 with `INVALID_ARGUMENT` and the `profiles set` hint, and no request is sent

#### Scenario: Nothing configured
- **WHEN** a user with no configuration file and no variable runs `whoami`
- **THEN** it exits 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`, and no request is sent to `127.0.0.1:8080` or anywhere else

#### Scenario: Direct server ignores a broken file
- **WHEN** `config.toml` is corrupt and an agent runs `whoami --server https://clavis.example.com`
- **THEN** the configuration is not read and the command proceeds against that server

#### Scenario: Corrupt file before a password prompt
- **WHEN** `config.toml` is corrupt, `fce` is named by `--profile`, and a user runs `login --profile fce --password-stdin` with a password on stdin
- **THEN** it exits 2 with `INVALID_ARGUMENT` naming the file before stdin is read or any request is sent

#### Scenario: Relative Clavis home
- **WHEN** `CLAVIS_HOME=relative/dir` is set and a user runs `login --server https://clavis.example.com --password-stdin`
- **THEN** it exits 2 with `INVALID_ARGUMENT` naming `CLAVIS_HOME` before stdin is read or any request is sent
