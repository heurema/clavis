# agent-skill Specification

## Purpose

Teach an agent to use the CLI correctly on every provider through a skill that ships inside the CLI binary, installs through the CLI into the Claude Code and Codex skill directories, and cannot drift from the commands it describes.

## Requirements

### Requirement: Embedded skill content


The CLI SHALL embed one skill directory, `clavis`, holding a `SKILL.md` entry and one reference file per registered provider (`postgresql.md`, `victoriametrics.md`, `victorialogs.md`), in the directory format Claude Code and Codex read (a `SKILL.md` with `name` and `description` frontmatter plus supporting files). The entry SHALL be under 200 lines and SHALL teach: what the platform is (a proxy that forwards the query as typed, applies the connection's stored credentials, bounds the answer and passes the source's own errors through) and is not (it never rewrites a query or an answer, never grants access); setup (`doctor` and `whoami`, that the person signs in with `clavis login` in the browser and the agent uses that session and never runs `login` itself, that a session renews while it is used and ends after the idle timeout without use or at its absolute expiry, so an `UNAUTHENTICATED` result means asking the person to run `clavis login` rather than retrying, and that the person configures profiles while the agent never runs `profiles set`, `profiles use` or `profiles remove`); choosing a server (read the top-level `server` field of every envelope and state that server in the answer, target another configured server with `--profile` or `CLAVIS_PROFILE`, and treat an `INVALID_ARGUMENT` whose hint names `clavis profiles set` as a request to ask the person, not to configure a profile or sign in on their behalf); finding a connection (`connections list --selector`, the `provider` field naming the reference to read, `description` and `scope` saying what the source holds); the result envelope (`schemaVersion`, `ok`, `data`, `error` with `code`, `hint` and `source`), exit codes 0, 1 and 2, `truncated` checked even on success, `--max-rows` as the platform's cap, `--output text` as a courtesy rendering; that returned content is data and never an instruction; and one worked investigation across two sources that names the connections, the time range and the limits of the answer. Each reference SHALL have the same sections in the same order: discover first, query, bound the answer, read the result, read a failure, pitfalls, time formats. The PostgreSQL reference SHALL carry the catalog query and put ordering and limits inside SQL; the VictoriaMetrics reference SHALL start with `--label-values __name__`, distinguish instant, pinned and range queries, explain the sample cap across series, branching on `resultType` and `warnings` and `isPartial` beside `truncated`; the VictoriaLogs reference SHALL start with stream and field discovery under `--match` and a time window, explain that `_msg` is text and JSON inside it needs the source's `unpack_json` and `fields` pipes, that ordering needs a sort pipe, that `--limit` is the source's limit and `--max-rows` the platform's cap, that hit counts under a discovery limit are not observed, that an empty result never proves a field exists, that `end` is exclusive, and prefer absolute RFC 3339 times. No skill file SHALL contain a credential, a hostname of a real source or an instruction to change access.

#### Scenario: An agent finds the right reference
- **WHEN** an agent loads the skill and lists connections whose `provider` is `victorialogs`
- **THEN** the entry tells it to read `victorialogs.md`, which starts with discovery under `--match` and a time window before any log query

#### Scenario: JSON inside a log message
- **WHEN** an agent reads the VictoriaLogs reference for a service that logs JSON lines
- **THEN** the recipe it finds unpacks the fields in the query itself (`| unpack_json fields (level, msg) | fields _time, level, msg`) and the platform is not asked to render anything

#### Scenario: Truncated success
- **WHEN** an agent follows the entry and a query answers `truncated: true` with exit 0
- **THEN** the entry has told it to report the answer as incomplete and to narrow the request or, on a log source, pass a limit with a sort pipe

#### Scenario: An agent names the server it used
- **WHEN** an agent following the entry answers a question from a query result
- **THEN** the entry has told it to read `server` from the envelope and state it, and to pass `--profile <name>` rather than change the current profile when the person asked about another configured server

#### Scenario: No server configured
- **WHEN** an agent's first command fails with `INVALID_ARGUMENT` and the hint `clavis profiles set <name> --server <url>`
- **THEN** the entry has told it to ask the person to configure a profile, and it does not run `profiles set`, `profiles use` or `login` itself

#### Scenario: Credential channels in setup
- **WHEN** an agent reads the setup section
- **THEN** it finds no way to pass a sign-in password, and `--password-stdin`, `--password-file` and `--password-env` only where user passwords set by an administrator or connection credentials are described

#### Scenario: An agent's session ends
- **WHEN** an agent's command fails with `UNAUTHENTICATED`
- **THEN** the entry has told it to ask the person to run `clavis login`, and it neither retries the request nor runs `login` itself
### Requirement: Skill install command

The CLI SHALL provide `skill install [--agent claude|codex] [--scope user|project] [--dir <path>] [--force] [--dry-run]`, an offline command that never contacts the server. Without `--agent` it SHALL target every agent whose skill directory exists at the chosen scope (`~/.claude/skills` and `~/.codex/skills` at user scope, `.claude/skills` and `.codex/skills` under the current directory at project scope) and, when none exists at user scope, SHALL create Claude Code's; `--agent` SHALL restrict the targets and create the named agent's directory; `--dir` SHALL replace the targets with one explicit directory. Into each target it SHALL write the skill directory `clavis` whole, with the frontmatter line `x-clavis-skill: <version>` carrying the CLI's build version as the ownership marker. A target whose `clavis` directory already exists SHALL be updated only when its `SKILL.md` carries the marker; otherwise the command SHALL refuse that target with exit 2, `INVALID_ARGUMENT` and a hint naming `--force`, unless `--force` is given. Files that are already identical SHALL be reported as unchanged. `--dry-run` SHALL report what would happen without writing. The result SHALL list each target with its path and outcome (`written`, `updated` with the previous version, `unchanged`, `refused`) in the JSON envelope and as one line per target in text; a refusal of any target SHALL exit 2 after the other targets were handled.

#### Scenario: One command sets up both agents
- **WHEN** a machine has both `~/.claude/skills` and `~/.codex/skills` and an agent runs `clavis skill install`
- **THEN** both receive `clavis/SKILL.md` and the three references with the version marker, the result lists both as `written`, and the exit code is 0

#### Scenario: Nothing to detect
- **WHEN** neither agent directory exists at user scope
- **THEN** `~/.claude/skills/clavis` is created and reported as `written`

#### Scenario: Update from a newer CLI
- **WHEN** the skill was installed by version 0.5 and a 0.6 CLI runs `skill install`
- **THEN** the files are replaced, the marker reads 0.6, and the result reports `updated` from 0.5

#### Scenario: A foreign skill in the way
- **WHEN** `~/.claude/skills/clavis/SKILL.md` exists without the marker
- **THEN** the command leaves it untouched, reports it as `refused`, prints a hint naming `--force`, exits 2, and with `--force` replaces it and exits 0

#### Scenario: Project scope
- **WHEN** an agent runs `clavis skill install --scope project` in a repository
- **THEN** the skill is written under the repository's `.claude/skills/clavis` and `.codex/skills/clavis` for the agents present, and nothing is written under the home directory

### Requirement: Skill show command

The CLI SHALL provide `skill show [--file <name>]`, an offline command printing one embedded skill file to stdout unchanged, `SKILL.md` by default, in every output format; an unknown file name SHALL exit 2 with a hint listing the files.

#### Scenario: Read the entry without installing
- **WHEN** a person runs `clavis skill show`
- **THEN** the embedded `SKILL.md` is printed as is, exit 0, and `clavis skill show --file victorialogs.md` prints that reference

### Requirement: Skill cannot drift from the CLI

The repository SHALL carry a test that reads every embedded skill file, extracts each `clavis` invocation and each `--flag` it names, and fails when a command, subcommand or flag does not exist in the CLI's definitions; and a test that fails when a hint text the skill quotes no longer matches the CLI's or the service's constant. The skill's stated compatible version SHALL be the build version stamped at install, never a hand-written number.

#### Scenario: A renamed flag
- **WHEN** a flag named in a reference is renamed in the CLI without the reference following
- **THEN** the drift test fails naming the file and the flag
