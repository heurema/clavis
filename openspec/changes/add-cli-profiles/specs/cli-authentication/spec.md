## ADDED Requirements

### Requirement: Client profiles

The CLI SHALL keep client configuration in `config.toml` inside the Clavis home, which is `CLAVIS_HOME` when set and non-empty (an absolute path, otherwise `INVALID_ARGUMENT`) and `~/.clavis` otherwise. The file SHALL hold an optional top-level `current` naming a profile and a `profiles` table whose entries each carry exactly one key, `server`. A profile name SHALL follow the username grammar, with its own error message and hint. The file SHALL never hold a secret, SHALL be read up to 64 KiB (a larger file is `INVALID_ARGUMENT`), SHALL be decoded strictly with keys matched exactly, and SHALL be loaded whole or not at all: a file that does not parse, an unknown key, an invalid profile name, a profile without a `server` passing the canonical-origin rule or a `current` naming a missing profile SHALL fail with `INVALID_ARGUMENT` naming the file and the offending key. An absent file SHALL mean no profiles and no current profile. A `config.toml` that is a symlink or not a regular file SHALL be refused with `INVALID_ARGUMENT` naming the path. Writes SHALL serialize under a lock in the Clavis home, re-read the file under that lock and replace it atomically. A write that cannot complete SHALL leave the file unchanged and exit 1: an unsafe Clavis home with `CREDENTIAL_STORAGE_FAILED`, a lock not acquired within the shared five-second deadline with `TIMEOUT`, and any other lock, encoding or file-system failure with `CONFIGURATION_WRITE_FAILED` naming the path. Only the `profiles` commands SHALL write the file; `login` and every other command SHALL NOT.

The CLI SHALL provide `profiles set <name> --server <url>`, `profiles use <name>`, `profiles current`, `profiles list` and `profiles remove <name>`; `set`, `use` and `remove` take the name as their only positional argument and `current` and `list` take none. They SHALL be local commands that never contact a server and SHALL NOT carry the envelope's `server` and `profile` fields. Their data SHALL be:

- `set`: `{name, server, created, madeCurrent}`. It creates the profile or replaces its server with the canonical origin, and sets `current` only when the file has none. It SHALL NOT read or change any session.
- `use`: `{profile, override}`. It SHALL fail on an unknown name, read the stored session for the profile's server, and only then set `current`, so a storage failure leaves the file unchanged.
- `current`: `{profile, source}`, where `source` is `environment` when `CLAVIS_PROFILE` names the profile and `config` otherwise. With neither it SHALL exit 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`.
- `list`: `{current, override, profiles}`, the profiles sorted by name.
- `remove`: `{name, currentCleared}`. Removing the current profile SHALL clear `current` and report `currentCleared: true`. It SHALL NOT read, change or delete any session.

A profile entry is `{name, server, current, session}`, where `current` is true for the file's `current` and `session` is `{username, expiresAt}` from the locally stored session for that server, or `null` when there is none. `override` is the value of `CLAVIS_PROFILE`, or empty; a `CLAVIS_PROFILE` that fails the profile-name rule SHALL make `use`, `current` and `list` exit 2 with `INVALID_ARGUMENT` naming the variable, and a well-formed one naming no profile SHALL still be reported by `use` and `list`. Session reads SHALL use the protected storage checks, SHALL NOT create the Clavis home, the `sessions` directory or any lock file, SHALL NOT wait for a session lock, and an unsafe or corrupt store SHALL fail the whole command with `CREDENTIAL_STORAGE_FAILED`. The stored expiry is reported as stored and SHALL NOT be presented as verification; text output SHALL say "stored session". An unknown name SHALL exit 2 with `INVALID_ARGUMENT` and a hint naming `profiles list`. Results SHALL use the schemaVersion 1 envelope with a text rendering in which `list` marks the current profile with `*`, and `use` and `list` print a note when `override` is set and differs from the file's `current`, stating either that it selects that profile in this environment or that it names no profile and networked commands there exit 2. No result SHALL contain a token.

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

## MODIFIED Requirements

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
