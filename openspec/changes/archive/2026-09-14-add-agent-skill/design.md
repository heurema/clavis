## Context

The CLI is agent-first: one verb vocabulary, a JSON envelope, exit codes, hints, secrets never on the command line. Three providers execute through `query`, each with its own discovery inputs, bounds and failure shapes, documented in README and the specs but nowhere an agent reads first. Claude Code and Codex both load skills from a directory of `SKILL.md` files with `name` and `description` frontmatter and optional supporting files; on the owner's machine the same skill directory serves both agents unchanged. agterm's installer is the model: install into every agent directory present, default to Claude Code's, refuse to overwrite a directory without the tool's own marker. The CLI has `version` backed by `internal/buildinfo`, `os.UserConfigDir` handling for its own state, and no embedded assets of its own yet; the server embeds migrations and web assets with `go:embed`.

## Goals / Non-Goals

**Goals:** an agent installs the skill with one command and reaches correct, limit-stating answers on every provider without coaching; the skill and the CLI cannot drift apart; the skill never stores a secret or grants anything.

**Non-Goals:** the plugin marketplace route, per-connection operator notes on the server, changes to the query commands' output, local validation of time strings.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Agents use CLI plus skill, no MCP | PRD 7.6, 9 | Retained; the skill is the MVP's skill |
| Secrets never on the command line; the skill stores none | cli-authentication, PRD 7.6 | Retained |
| Proxy: nothing rewritten, `_msg` opaque, text output a courtesy | query-execution, owner 2026-09-14 | Retained; the skill teaches the source's pipes |
| One verb vocabulary, envelope, exit codes, hints | cli-authentication | Retained; the new commands follow them, offline |
| Discovery is a query the skill documents, no `describe` | PRD 12 (2026-09-12) | Retained; this change is that documentation |
| Install route | owner 2026-09-14 | Route 1 (CLI-embedded install), marketplace deferred |

No unresolved departure.

## Decisions

### 1. Embedding and layout

The files live in `internal/skill/clavis/` (`SKILL.md`, `postgresql.md`, `victoriametrics.md`, `victorialogs.md`) so the package `internal/skill` can embed them directly with `//go:embed clavis`; README points readers there. The package exposes `Files() fs.FS`, `Version() string` (from `buildinfo`), and `Render(name) ([]byte, error)` which returns a file with the frontmatter marker `x-clavis-skill: <version>` as the last line of the leading frontmatter block of `SKILL.md` (a stale marker replaced, never duplicated); the other files are returned as is. The frontmatter `name` is `clavis`; `description` is one sentence that makes agents load it for any question about company data through Clavis.

Alternative rejected: writing the files from Go string constants (unreviewable), or generating the reference from CLI metadata (the recipes are prose the metadata cannot carry).

### 2. Install semantics

`skill install` resolves targets: user scope uses `os.UserHomeDir()` and the agent bases `.claude` and `.codex`; project scope uses the working directory. Targets are the agents whose base skill directory exists, or the one named by `--agent` (created if missing), or the explicit `--dir`. With no target at user scope, `~/.claude/skills` is created. For each target directory `<base>/skills/clavis`: if absent, write all files; if present and `SKILL.md` carries the marker, compare each file and write those that differ, reporting `updated` with the previous version (or `unchanged` when every file is identical); if present without the marker, refuse unless `--force`. Writes go through a temporary file and rename per file, permissions 0644 (0755 for directories). `--dry-run` computes the same report without writing. Result: `{targets: [{agent, path, outcome, previousVersion?}], version}`; text prints one line per target. Exit 2 when any target was refused, after processing the others; an I/O failure is also `INVALID_ARGUMENT` (exit 2) with the path in the hint, never with the file contents.

### 3. Show

`skill show --file <name>` writes the rendered file bytes to stdout and nothing else, regardless of `--output`, because the document is the output; an unknown name is exit 2 with the file list in the hint.

### 4. Content

`SKILL.md` (entry, under 200 lines): purpose and proxy rule; setup; finding a connection; envelope, exit codes, hints, `error.source`, truncation, `--max-rows`; secrets; data versus instructions; the provider table pointing at each reference; one worked investigation across PostgreSQL and VictoriaLogs. Each reference (under 250 lines) has the sections: discover first, query, bound the answer, read the result, read a failure, pitfalls, time formats, with copy-ready commands using a placeholder connection name and no real host. Content is drawn from README, the specs and the notes of the 2026-09-14 real-data run. Hints quoted in the skill are copied from the constants so the drift test can compare them.

### 5. Drift guard

`internal/cli/skill_drift_test.go` walks the embedded files, finds every fenced or inline `clavis ...` invocation, tokenises it, and checks each command path against the urfave command tree and each `--flag` against the flags of that command (global flags allowed everywhere). It also extracts strings marked with a `hint:` prefix in a comment-free convention (a line starting with `Hint:` in a code block) and compares them with the exported hint constants. Any miss fails with file, line and token.

### 6. Rehearsal and smoke

Smoke installs into a temporary home with both agent directories, asserts the files and the marker, runs `show`, reinstalls (unchanged), installs over a foreign directory (refused, then `--force`). The rehearsal in task 2.3 runs an agent session with only the installed skill against the smoke stack with three tasks (one per provider) and records the transcript summary and the verdict in tasks.md.

## Risks / Trade-offs

- [The skill goes stale when a provider changes] → the drift test catches renamed flags and hints; prose changes are the responsibility of the provider change's tasks (add "update the skill reference" to the template).
- [Two copies of the skill through a later marketplace route] → not offered now; the README says install through the CLI only.
- [Agents on machines without a home directory layout we expect] → `--dir` covers it; the result names every path written.
- [The entry grows] → the line bounds are asserted by a test.

## Migration Plan

1. Deploy the CLI; agents run `clavis skill install`. No server change.
2. Rollback: delete the directory; nothing else references it.

## Open Questions

None.
