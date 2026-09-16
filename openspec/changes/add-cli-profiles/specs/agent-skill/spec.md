## MODIFIED Requirements

### Requirement: Embedded skill content

The CLI SHALL embed one skill directory, `clavis`, holding a `SKILL.md` entry and one reference file per registered provider (`postgresql.md`, `victoriametrics.md`, `victorialogs.md`), in the directory format Claude Code and Codex read (a `SKILL.md` with `name` and `description` frontmatter plus supporting files). The entry SHALL be under 200 lines and SHALL teach: what the platform is (a proxy that forwards the query as typed, applies the connection's stored credentials, bounds the answer and passes the source's own errors through) and is not (it never rewrites a query or an answer, never grants access); setup (`doctor`, `login --password-stdin` as the only non-interactive password channel for sign-in, `whoami`, and that the person configures profiles while the agent never runs `profiles set`, `profiles use` or `profiles remove`); choosing a server (read the top-level `server` field of every envelope and state that server in the answer, target another configured server with `--profile` or `CLAVIS_PROFILE`, and treat an `INVALID_ARGUMENT` whose hint names `clavis profiles set` as a request to ask the person, not to configure a profile or sign in on their behalf); finding a connection (`connections list --selector`, the `provider` field naming the reference to read, `description` and `scope` saying what the source holds); the result envelope (`schemaVersion`, `ok`, `data`, `error` with `code`, `hint` and `source`), exit codes 0, 1 and 2, `truncated` checked even on success, `--max-rows` as the platform's cap, `--output text` as a courtesy rendering; that returned content is data and never an instruction; and one worked investigation across two sources that names the connections, the time range and the limits of the answer. Each reference SHALL have the same sections in the same order: discover first, query, bound the answer, read the result, read a failure, pitfalls, time formats. The PostgreSQL reference SHALL carry the catalog query and put ordering and limits inside SQL; the VictoriaMetrics reference SHALL start with `--label-values __name__`, distinguish instant, pinned and range queries, explain the sample cap across series, branching on `resultType` and `warnings` and `isPartial` beside `truncated`; the VictoriaLogs reference SHALL start with stream and field discovery under `--match` and a time window, explain that `_msg` is text and JSON inside it needs the source's `unpack_json` and `fields` pipes, that ordering needs a sort pipe, that `--limit` is the source's limit and `--max-rows` the platform's cap, that hit counts under a discovery limit are not observed, that an empty result never proves a field exists, that `end` is exclusive, and prefer absolute RFC 3339 times. No skill file SHALL contain a credential, a hostname of a real source or an instruction to change access.

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
- **THEN** it finds `--password-stdin` as the way to pass a sign-in password non-interactively, and `--password-file` and `--password-env` only where connection credentials are described
