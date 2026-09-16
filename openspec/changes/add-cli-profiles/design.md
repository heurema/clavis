## Context

Every networked command is built by `authCommands` (`internal/cli/auth_commands.go`) with a `--server` flag whose value defaults to `http://127.0.0.1:8080` and is also sourced from `CLAVIS_SERVER_URL` through urfave's `Sources`. `runAuth` canonicalizes it with `auth.CanonicalOrigin`, which already refuses base paths and non-loopback HTTP, and maps every `openCache` error to one fixed `storageFailure()` message. `doctor` is defined separately in `cli.go` with the same default and variable, and validates with its own looser `validateURL` (`doctor.go`), which accepts a base path and plain HTTP anywhere, so a server can pass `doctor` and then be refused by `login`.

Sessions live under `os.UserConfigDir()/clavis/sessions` (`cache_posix.go`): `~/Library/Application Support/clavis/sessions` on macOS and `$XDG_CONFIG_HOME/clavis/sessions` or `~/.config/clavis/sessions` on Linux. `openConfigDirectory` walks every component with `O_NOFOLLOW`, creating any that are missing, trusting root-owned ancestors and requiring user-owned ones to be unwritable by others; `clavis` and `sessions` must then be exactly 0700. Files are named by the SHA-256 of the canonical origin, with a per-origin flock and temp-file-and-rename writes. `cache_unsupported.go` fails every operation off darwin and linux.

`Result` (`result.go`) is `{schemaVersion, ok, data, error}`; `render` switches on the data type for text. `RunWithIO` forces JSON for `INVALID_ARGUMENT` and rejects any positional argument through the shared `check`. Unit tests redirect storage by setting `HOME` and `XDG_CONFIG_HOME` and reach test servers through `CLAVIS_SERVER_URL`; the smoke and kind scripts set `HOME` and `XDG_CONFIG_HOME` per client and pass `--server` on every call, `doctor` included. The skill drift test (`skill_drift_test.go`) parses every `clavis` invocation in the skill on the assumption that no command takes a positional argument. The go.mod has no TOML library. `SKILL.md` is 158 lines against a 200-line limit, and its setup section wrongly says `login` accepts `--password-file` and `--password-env`.

kubectl, whose model the owner chose, keeps named contexts and a `current-context` in one kubeconfig. It picks the context from `--context`, then `current-context`, and has no environment variable for it. `config set-context` creates or merges an entry without changing the current one, `use-context` switches locally and fails on an unknown name, `get-contexts` marks the current one, `current-context` prints it, and `delete-context` removes even the current one with only a warning. Credentials are defined separately from contexts.

## Goals / Non-Goals

**Goals:** a remembered, named server per machine managed like kubectl contexts; one resolution order for every networked command with no silent default; every networked result states the server it used; a way to pin one terminal or agent without switching the machine; sessions beside the configuration in a directory people can create under a normal umask; the skill teaches agents to name and choose servers without changing them.

**Non-Goals:** browser sign-in, session renewal and the session policy (change 3); per-profile output format, timeout, default connection or certificates (rejected in the plan); `profiles rename`; merging several configuration files the way `KUBECONFIG` does; a symlinked Clavis home or `config.toml`; migrating sessions from the former location; Windows, including keeping the new configuration code compiling for it.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| File `~/.clavis/config.toml`, TOML, strict, no secrets, `CLAVIS_HOME` override; a profile is a name and a server | plan, change 2 "File" | Retained |
| Output format, timeout, default connection and certificates are not profile settings | plan, change 2 "File" | Retained |
| The selected profile is stored as `default` | plan, change 2 "File" | Changed (owner, 2026-09-16): stored as `current`, after kubectl's `current-context` |
| `login --profile NAME [--server URL]` creates or updates a profile and sets the default when none exists; `login --server` alone writes nothing | plan, change 2 "Commands" | Changed (owner, 2026-09-16): `profiles set` creates and updates, becoming current only when none is; `login` never writes the configuration and `--profile` on it only selects the server |
| `profiles list`, `profiles use`; `use` prints the server and the signed-in user | plan, change 2 "Commands" | Retained; `profiles current` added; the user comes from the stored session (decision 6, owner-confirmed direction, reviewer-agreed) |
| `profiles remove` refuses the default and never touches sessions | plan, change 2 "Commands" | Changed (owner, 2026-09-16): removing the current profile is allowed, as `kubectl config delete-context` allows; kubectl leaves `current-context` dangling with a warning, while Clavis clears `current` because a dangling one would make the file invalid; sessions still untouched |
| Resolution: flag pair, then `CLAVIS_SERVER_URL` or `CLAVIS_PROFILE`, then default; both of a pair is an error; otherwise `INVALID_ARGUMENT` with a login hint; loopback default removed | plan, change 2 "Resolution of the server" | Changed (owner, 2026-09-16): `CLAVIS_SERVER_URL` removed so a leftover export cannot silently override `profiles use`; `CLAVIS_PROFILE` kept, unlike kubectl, to pin a terminal or agent; hint names `profiles set`; loopback default removed as planned |
| Top-level `server` and `profile` on every networked result, additive, `schemaVersion` 1; text prints the server first | plan, change 2 "Visibility of the choice" | Retained |
| Skill: read `server`, state it, target with `--profile` or `CLAVIS_PROFILE`, never change profiles | plan, change 2 "Visibility of the choice" | Retained; the forbidden commands are now `profiles set`, `use` and `remove` |
| Config read only by networked commands; absent file is not an error; corrupt file is `INVALID_ARGUMENT` naming file and key, never a partial load; writes are temp-file-and-rename under a lock | plan, change 2 "Implementation notes" | Retained; the `profiles` commands also read it, being the commands that manage it |
| Home relaxed to "not group- or world-writable" because users "will create `~/.clavis` under a normal umask or symlink it from a dotfile manager"; `sessions` exact; failures name path and mode | plan, change 2 "Implementation notes" | Narrowed (owner, 2026-09-16): the umask relaxation is kept; symlinked homes are dropped, and a symlink anywhere on the path stays refused as today |
| `doctor` adopts the canonical-origin rule; skill setup paragraph corrected; release note about signing in again | plan, change 2 "Implementation notes" | Retained |
| Sessions stored in a private user configuration location keyed by canonical origin | cli-authentication "Origin-bound protected session storage" | Explicitly changed (delta) |
| Offline help, version and CLI-only builds never load credentials | cli-authentication "Authentication preserves CLI output conventions" | Retained and extended (delta): they also never read the configuration |
| `users`, `connections`, `groups` commands use "the `--server`/`--timeout` flags" | cli-authentication, three command requirements | Retained as written: `--server` remains and "Server resolution" adds `--profile` to every networked command |
| `doctor` checks readiness with a configurable server URL | project-bootstrap "Structured CLI diagnostics" | Explicitly changed (delta). The plan named two specs; this third delta follows from `doctor`'s requirement living here |
| Skill setup teaches `--server` and `CLAVIS_SERVER_URL` | agent-skill "Embedded skill content" | Explicitly changed (delta) |
| Passwords and tokens never in arguments or environment | cli-authentication "Safe local CLI sign-in" | Retained; the configuration holds only names and origins |
| Breaking changes allowed during the beta | plan "Why" | Retained |
| Windows postponed | plan "Postponed" | Retained (owner, 2026-09-16): the new configuration code is not required to compile for Windows; no stubs are added for it, and the existing stubs are left as they are |
| Ships as `v0.1.0-rc.3` | plan, change 2 | Changed (owner, 2026-09-16): `rc.2` to `rc.5` were consumed releasing change 1, so this ships as `v0.1.0-rc.6` |

## Decisions

### 1. The Clavis home

`clavisHome()` returns `CLAVIS_HOME` when non-empty (absolute, else `INVALID_ARGUMENT` naming the variable), otherwise `os.UserHomeDir()` joined with `.clavis`. It is pure and runs during resolution (decision 3), so a relative value fails before any input is read.

Opening the store keeps today's walk: `openConfigDirectory` opens the home path component by component with `O_NOFOLLOW`, creating missing components with 0700 and applying the ancestor rule, so a symlink anywhere on the path, the home included, is refused. The home then gets the non-exact private check (user-owned, not group- or world-writable) instead of the configuration root's, and `sessions` inside it keeps `O_NOFOLLOW` and the exact 0700 check. The only structural change is dropping `os.UserConfigDir()` and the intermediate `clavis` component. Everything below `sessions` is unchanged: digest file names, per-origin locks, atomic writes, token comparison on remove. The walk works for real homes such as `/Users/alice` and `/home/alice`; a home under a symlinked system directory (macOS `mktemp -d` under `/var`) is refused, as it is today, which is why the tests already resolve their temporary home first.

`openCache` returns a typed `storageError{path, requirement}`; `runAuth` renders `CREDENTIAL_STORAGE_FAILED` with `<path> must be <requirement>` (for example `/Users/alice/.clavis/sessions must be a directory with mode 0700`). The path comes from the check, never from server data. A read-only variant used by the `profiles` commands takes a flag on the same walk to create nothing: an absent home or `sessions` means no stored session.

Alternatives: keep `os.UserConfigDir()` for sessions and put only the configuration in `~/.clavis` (two places to explain, against the plan); follow XDG on both systems (the plan chose one path people type the same everywhere); accept a symlinked home for dotfile managers (resolving it safely needs the link's directory checked as well as its target and breaks on system symlinks such as macOS `/var`; dropped as unrequested, `CLAVIS_HOME` covers relocation).

### 2. Configuration file and library

```go
type clientConfig struct {
	Current  string                   `toml:"current,omitempty"`
	Profiles map[string]clientProfile `toml:"profiles,omitempty"`
}
type clientProfile struct {
	Server string `toml:"server"`
}
```

Decoding uses `github.com/pelletier/go-toml/v2` with `DisallowUnknownFields`, whose `StrictMissingError` carries the offending key, read through a 64 KiB bound. Validation after decoding: every profile name passes `auth.ValidUsername` (reported with a profile-specific message and hint, not `auth.UsernameHint`), every `server` passes `auth.CanonicalOrigin`, `current` is empty or names a profile. Any failure is `INVALID_ARGUMENT` with `<path>: <key> ...` and nothing from the file is used. `profiles set` stores the canonical origin; a hand-written server is canonicalized at resolution and left as written until the CLI next writes the file.

Writes (only from `profiles set`, `use`, `remove`) take `config.lock` in the home with the existing `openLock` and flock helper under the shared five-second deadline, re-read and re-validate the file, apply the change, encode the whole struct, write a temp file (`O_EXCL|O_NOFOLLOW`, mode 0600), fsync and rename. `config.toml` is opened with `O_NOFOLLOW` for reading and writing, and one that is a symlink or not a regular file is refused with `INVALID_ARGUMENT` naming the path. A CLI write drops hand-written comments and sorts profiles by name; the README says so.

Alternatives: `BurntSushi/toml` (strictness through `MetaData.Undecoded` after the fact; go-toml v2 makes it a decoder option and names the key); JSON (the plan agreed on TOML for hand editing); YAML like kubeconfig (TOML was agreed, and its strict decoding is simpler to get right).

### 3. Resolution

The `--server` flag loses its default value and its `Sources`, so `command.IsSet("server")` means the command line; `--profile` joins it on every networked command and on `doctor`. `CLAVIS_PROFILE` is read with `os.Getenv`; empty is unset. `CLAVIS_SERVER_URL` is not read anywhere.

```go
type target struct{ Origin, Profile, Home string }
func resolveTarget(server, profile string, getenv func(string) string, load func(home string) (clientConfig, *Result)) (target, *Result)
```

Steps: compute the home (decision 1); `--server` and `--profile` together is `INVALID_ARGUMENT`; `--server` alone canonicalizes and returns with an empty profile, never loading the file; otherwise take the name from `--profile`, then `CLAVIS_PROFILE`, then `current` (loading the file once, only now); an unknown name is `INVALID_ARGUMENT` with a `profiles list` hint; no name at all is `INVALID_ARGUMENT` with `clavis profiles set <name> --server <url>`. `login` uses the same function. It runs first in `runAuth` and in the `doctor` action: before argument validation that reads input, before any password, secret or SQL input, and before `openCache`.

Alternatives: keep `CLAVIS_SERVER_URL` below the flags (a leftover export from before profiles existed would silently beat `profiles use`); drop `CLAVIS_PROFILE` as kubectl does (pinning a terminal or an agent would then depend on remembering `--profile` on every command, or on per-shell configuration files); resolve lazily in the transport (too late: storage and input would already be touched).

### 4. Envelope

`Result` gains `Server *string \`json:"server,omitempty"\`` and `Profile *string \`json:"profile,omitempty"\``, placed after `ok`. One helper sets both after resolution in `runAuth` and `doctor`, covering every return after that point, early ones included (argument validation, storage failure, `UNAUTHENTICATED` without a session). Pointers let `profile` be present and empty for a one-off while both stay absent before resolution. `render` prints `Server: <origin>` or `Server: <origin> (profile <name>)` first when `Server` is set, before the `CODE: message` line on failure, and the existing rendering follows unchanged, query tables included. The `profiles` commands never set these fields: they resolve no server.

### 5. Login

`login` resolves like every other command, reads the password, signs in and stores the session exactly as today. Its data and text are unchanged apart from the envelope fields. `login --profile fce` means "sign in to `fce`'s server"; it never creates a profile, so a person sets a profile first. This removes the partial-failure state the plan's `login --profile` had (signed in but profile not saved).

### 6. Profiles commands

A `profiles` group with `set`, `use`, `current`, `list`, `remove`. `set`, `use` and `remove` take exactly one positional name, validated with the profile-name rule; `current` and `list` take none. The shared positional check in `RunWithIO` gains an allowance keyed on the full command lineage (`command.Lineage()`: `clavis profiles set|use|remove`), requiring exactly one argument, never on the leaf name alone. None of them contacts a server, carries `--server` resolution or `--profile`, or sets the envelope's `server` and `profile`; `set` has its own required `--server` naming the value to store.

Data (JSON field names are the spec's contract):

| Command | Data | Reads sessions | Writes file |
|---|---|---|---|
| `set NAME --server URL` | `{name, server, created, madeCurrent}` | no | yes; `current` set only when empty |
| `use NAME` | `{profile: entry, override}` | yes, before writing | yes |
| `current` | `{profile: entry, source: "environment"\|"config"}` | yes | no |
| `list` | `{current, override, profiles: [entry]}` sorted by name | yes | no |
| `remove NAME` | `{name, currentCleared}` | no | yes; clears `current` when it named this profile |

`entry` is `{name, server, current, session: {username, expiresAt} | null}`; `override` is `CLAVIS_PROFILE` or empty. A `CLAVIS_PROFILE` that fails the profile-name rule makes every `profiles` command that reports it exit 2 with `INVALID_ARGUMENT` naming the variable, so no arbitrary environment bytes are echoed. `current` with `CLAVIS_PROFILE` set reports that profile (unknown → `INVALID_ARGUMENT` naming `profiles list`); otherwise the file's `current`; neither → `INVALID_ARGUMENT` with the `profiles set` hint. `use` and `list` with a well-formed but unknown `CLAVIS_PROFILE` still succeed and report it as `override`.

Sessions are read through the read-only store variant, one origin at a time, without taking the per-origin lock: opening a lock creates its file, and the session writer only ever replaces a session by rename or unlinks it, so a lock-free read sees a whole file or none, and `read` still validates the opened descriptor strictly. An unsafe or corrupt store fails the whole command with `CREDENTIAL_STORAGE_FAILED`, and for `use` this happens before the write so the file is unchanged. Write failures exit 1: an unsafe home is `CREDENTIAL_STORAGE_FAILED` as for every other command, a lock not acquired in five seconds is `TIMEOUT`, and any other lock, encoding or file-system failure is `CONFIGURATION_WRITE_FAILED` naming the path. The expiry is the cached one; text says "stored session" and `whoami` remains the verified check.

Text: `set` prints `Profile fce set to https://…` plus `, now current` when it became current; `use` and `current` print the profile, server and `stored session: alice until <time>` or `not signed in`; `list` prints one line per profile with `*` for the current one; `use` and `list` add `Note: CLAVIS_PROFILE=<name> selects <name> in this environment` when the override differs from the file's `current`, or `Note: CLAVIS_PROFILE=<name> names no profile; networked commands in this environment exit 2` when it is unknown; `remove` prints `Removed fce` plus `; no profile is current now` when it cleared `current`.

Alternatives: `use` asks the server like `whoami` (fails offline or during an outage, exactly when a person switches away from a dead server, and duplicates `whoami`); refuse removing the current profile (the plan's rule; the owner chose kubectl's behaviour, and the next networked command fails loudly with the `profiles set` hint rather than falling back); `profiles set` never changes `current` (kubectl's rule; one more command on first setup for no safety gain when nothing is current).

### 7. Doctor

`doctor` calls `resolveTarget`, uses the canonical origin plus `/readyz`, and wraps its result with the target. `validateURL` is deleted.

### 8. Skill and documentation

`SKILL.md` setup: the person configures profiles (`clavis profiles set <name> --server <url>`, `clavis login`); the agent reads `server` and `profile` from every envelope and names the server in its answer, targets another configured server with `--profile <name>` or `CLAVIS_PROFILE`, may run `profiles current` or `profiles list` to see what exists, never runs `profiles set`, `use` or `remove`, and on the `profiles set` hint asks the person. A sign-in password goes only through `--password-stdin`. The eight-hour session sentence stays until change 3; the file stays under 200 lines. The drift test's parser learns that `profiles set`, `use` and `remove` take one positional argument, so an invocation with `<name>` passes and a misspelled subcommand still fails; any quoted hint joins its allowlist with a constant in `internal/cli`.

README CLI section: the file with an example, `CLAVIS_HOME`, the five commands mapped to their kubectl counterparts, the resolution order, comments and ordering dropped on a CLI write, `server`/`profile` in results, and an upgrade note. PRD decision row "CLI profiles" is updated to the kubectl-style commands, `current` and the removal of `CLAVIS_SERVER_URL`.

## Risks / Trade-offs

- [Every text-output test that compares exact output gains a first line] → Tests compare through a helper that checks and strips the server line once.
- [Every test reaching a server through `CLAVIS_SERVER_URL` breaks] → Mechanical: the test helpers pass `--server`, or set `CLAVIS_PROFILE` against a test configuration; the sweep is reported separately from new tests.
- [People with `CLAVIS_SERVER_URL` exported get the setup hint after upgrading] → Intended; the release note says to replace it with a profile or `CLAVIS_PROFILE`.
- [`CLAVIS_PROFILE` left exported makes `profiles use` look ineffective in that shell] → `use` and `list` print the override note, `current` reports `source: environment`; results carry `profile`.
- [Removing the current profile leaves no profile current] → The next networked command exits 2 with the `profiles set` hint; nothing falls back to another server.
- [A CLI write drops comments and reorders the file] → Documented; the file is small and managed by `profiles`.
- [Old sessions linger in the former directory until they expire] → They expire within eight hours; the release note says the directory may be deleted.
- [Two profiles with one origin share a session, so logging out through one logs out the other] → Intended; `profiles list` shows the shared session on both.

## Migration Plan

Merge, tag `v0.1.0-rc.6` from `main`, and prepend to the generated release notes: `CLAVIS_SERVER_URL` and the loopback default are gone; run `clavis profiles set <name> --server <url>` and `clavis login` once; export `CLAVIS_PROFILE` where a shell used to export the server; sessions moved to `~/.clavis/sessions`, so everyone signs in again, and the former directory may be deleted. Rollback is installing `v0.1.0-rc.5`, which still reads sessions in the former directory.

## Open Questions

None.
