## Why

The first beta users arrived on September 16, 2026, and `clavis whoami` reported the server unreachable right after a successful login: the CLI never remembers a server, so every command resolves it from `--server` or `CLAVIS_SERVER_URL` and silently falls back to `http://127.0.0.1:8080`. A person who works with more than one installation, or an agent that inherits a shell without the variable, has no durable and visible way to say which server a command talks to. This is change 2 of `docs/plans/2026-09-16-cli-sign-in-profiles-release.md`, reshaped on the same day by the owner after the kubectl context model, and must land before browser sign-in (change 3), which relies on a remembered server.

## What Changes

- A client configuration file `~/.clavis/config.toml` (directory overridable with `CLAVIS_HOME`) holding named profiles, each a name and a server URL, plus `current`, the profile used when a command names none, the counterpart of kubectl's `current-context`. Strict decoding rejects unknown keys; the file never holds a secret; writes are atomic under a lock.
- New local commands modelled on `kubectl config`: `clavis profiles set NAME --server URL` creates a profile or changes its server and makes it current only when no profile is current, saying so; `profiles use NAME` sets `current`; `profiles current` shows the profile a command would use; `profiles list` shows every profile with the current one marked; `profiles remove NAME` deletes a profile and, when it was current, clears `current` and says so. None of them contacts a server; `use`, `current` and `list` show the session stored locally for each server and note when `CLAVIS_PROFILE` overrides `current`.
- `login` only signs in: it resolves its server like every other command and never writes the configuration.
- Every networked command (including `doctor`) resolves its server in one order: `--server URL` (a one-off) or `--profile NAME` on the command line, then `CLAVIS_PROFILE`, then `current`. **BREAKING**: `CLAVIS_SERVER_URL` and the silent `http://127.0.0.1:8080` default are removed; with nothing configured the command exits 2 with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`.
- Every networked result, success or failure, carries top-level `server` (the canonical origin) and `profile` (empty for a one-off). This is additive, so `schemaVersion` stays 1. Text output prints the server on its first line.
- **BREAKING**: sessions move from the operating system's configuration directory (`~/Library/Application Support/clavis/sessions` on macOS, `$XDG_CONFIG_HOME/clavis/sessions` or `~/.config/clavis/sessions` on Linux) to `~/.clavis/sessions/`, still keyed by origin. Existing sessions are not migrated; everyone signs in once more after upgrading.
- The storage check keeps exact owner-only mode on `sessions/` and its files but relaxes the Clavis home to "owned by the user and not group- or world-writable", so `~/.clavis` created under a normal umask works. Symlinks stay refused anywhere on the path, as today; `CLAVIS_HOME` can name the real directory instead. Storage failures name the path and the required mode.
- **BREAKING**: `doctor` validates the server with the canonical-origin rule `login` uses, so it now refuses base paths and non-loopback HTTP.
- The skill's setup section teaches profiles: read `server` from every envelope and state it in the answer, target a server with `--profile` or `CLAVIS_PROFILE`, never run `profiles set`, `use` or `remove`, and ask the person when the setup hint appears; it also corrects the claim that `login` accepts `--password-file` and `--password-env`.
- Ships as `v0.1.0-rc.6` (tags through `rc.5` already exist) with a release note: replace `CLAVIS_SERVER_URL` with a profile, sign in once more.

## Departures from the plan (owner, 2026-09-16)

- kubectl-style `profiles set/use/current/list/remove` replace `login --profile` as the way profiles are created; `login` never writes the configuration.
- The key is `current`, not `default`.
- `CLAVIS_SERVER_URL` is removed; `CLAVIS_PROFILE` is kept as the one environment input, a deliberate difference from kubectl, which has no context variable, so a terminal or an agent can be pinned without switching the machine-wide profile.
- Removing the current profile is allowed and clears `current`, as `kubectl config delete-context` does, instead of being refused.
- A symlinked `~/.clavis` is not supported: the plan's dotfile-manager case is dropped because nobody asked for it and it carried most of the storage complexity; `CLAVIS_HOME` covers relocation.
- The first `profiles set` becomes current when none is, a deliberate difference from `kubectl config set-context`, keeping first-time setup to two commands.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cli-authentication`: "Origin-bound protected session storage" moves the store to the Clavis home and relaxes the home check; "Authentication preserves CLI output conventions" gains the `server` and `profile` envelope fields and the rule that offline commands never read the configuration; requirements "Client profiles" and "Server resolution" are added. The requirements for `users`, `connections` and `groups` commands still say they use "the `--server`/`--timeout` flags"; that stays true (`--server` remains, joined by `--profile` under "Server resolution") and they are accepted as written.
- `project-bootstrap`: "Structured CLI diagnostics" resolves the server through profiles, applies the canonical-origin rule and carries the `server` and `profile` fields. The plan listed only two specs; `doctor`'s requirement lives here, so this third delta is a necessary consequence rather than new scope.
- `agent-skill`: "Embedded skill content" replaces "`--server` and `CLAVIS_SERVER_URL`" in the setup teaching with profile targeting, the `server` field and the prohibition on changing profiles.

## Impact

- `internal/cli`: `cli.go` and `doctor.go` (flags, resolution, canonical origin), `auth_commands.go` (flags, resolution, storage error mapping), `result.go` (envelope fields, text first line, profile renderers), `cache_posix.go` (home location and checks), new files for the home, the configuration and the `profiles` commands, and the tests that set `XDG_CONFIG_HOME`, `CLAVIS_SERVER_URL` or read `os.UserConfigDir()` (`auth_test.go`, `cache_posix_test.go`, `cli_test.go`, `subprocess_posix_test.go`, `skill_test.go`, and the per-group tests that rely on the variable).
- `internal/skill/clavis/SKILL.md` (stays under 200 lines) and `internal/cli/skill_drift_test.go`, whose parser assumes no command takes a positional argument.
- `scripts/smoke.mjs` gains a profile flow; `smoke-image.mjs` and `verify-kind.mjs` already pass `--server` on every call.
- `README.md` CLI section and upgrade note; `docs/PRD.md` "CLI profiles" decision row.
- One new Go dependency for TOML decoding and encoding (`github.com/pelletier/go-toml/v2`).
- No server, API, database or chart change. A pre-change CLI keeps working against the new server.
