## Why

Three providers can be queried, and the first real run on the dev cluster's logs showed that every remaining inconvenience is knowledge, not code: which discovery to run first, that JSON inside a log message needs the source's own pipes, that `--limit` is the source's limit and `--max-rows` the platform's cap, how ordering and time formats work per source. The PRD makes the skill part of the MVP (7.6, SKILL-01 to SKILL-04) and the roadmap agreed on 2026-09-14 puts it before groups. The owner decided the skill installs through the CLI itself (route 1 of the agterm model), so the document and the binary it describes always come from one commit.

## What Changes

- Add an embedded skill, `internal/skill/clavis/` in the repository, compiled into the CLI: a short `SKILL.md` entry and one reference each for PostgreSQL, VictoriaMetrics and VictoriaLogs, written for Claude Code and Codex, which read the same directory format.
- Add `clavis skill install [--agent claude|codex] [--scope user|project] [--dir <path>] [--force] [--dry-run]`: copies the skill directory into every agent skill directory present on the machine (`~/.claude/skills/clavis`, `~/.codex/skills/clavis`), creates Claude Code's when none exists, stamps the CLI version into the frontmatter, updates its own earlier copy, and refuses to overwrite a directory without its marker unless `--force`; reports each target as written, updated, unchanged or refused in the JSON envelope, exit 2 with a hint on a refusal.
- Add `clavis skill show [--file <name>]`: prints one skill file to stdout, `SKILL.md` by default, for reading or piping.
- Guard against drift: a test parses every `clavis` invocation and flag in the skill files and checks each against the CLI's command and flag definitions, and every quoted hint against the constants, so the text cannot describe a flag the binary lacks.
- Rehearse the skill: a fresh agent session with only the installed skill and the smoke stack completes one task per provider and states its limits, recorded as verification evidence.
- README gains an "Agents" section (install the CLI, `clavis skill install`, log in); PRD 7.6 and 12 record the skill as implemented and how it installs.

## Capabilities

### New Capabilities

- `agent-skill`: the embedded skill's content contract, the `skill install` and `skill show` commands, the marker and version rules, and the drift guard.

### Modified Capabilities

None. The skill describes the existing commands and changes none of them; `cli-authentication` keeps its requirements, and the new commands are offline commands that neither authenticate nor contact the server.

## Impact

- CLI: `internal/cli/skill_commands.go` (new), `internal/cli/skill_test.go` (new), the root command list in `internal/cli/cli.go`; `internal/skill/` (new package embedding its `clavis/` directory with `go:embed`); `internal/buildinfo` read for the version stamp.
- Docs: `README.md`, `docs/PRD.md`, `scripts/smoke.mjs` (install into a temporary home, show, refusal, force).
- Dependencies: none new.

## Owner decisions (2026-09-14)

- Route 1 only: the skill ships in the binary and installs through the CLI; no plugin marketplace for now.
- Install into every agent directory present; Claude Code's created when none is; user scope by default; project scope and an explicit directory on request.
- A foreign skill in the way is refused with exit 2 and a hint naming `--force`.
- The marker is a frontmatter line carrying the CLI version, so an agent can tell whether its skill is stale, and reinstalling from a newer CLI is the update.
- One skill with per-provider reference files rather than one skill per provider, so agents load the entry by its description and read only the reference they need.
- No `uninstall`; deleting a directory needs no tool and the marker tells a person it is ours.
- Text output of log rows stays as it is; the skill teaches the source's `unpack_json` and `fields` pipes rather than the platform pretty-printing anything.

## Non-goals

A plugin marketplace, per-connection operator notes stored on the server, a skill for the web interface, local validation of time strings, any change to what the query commands return.
