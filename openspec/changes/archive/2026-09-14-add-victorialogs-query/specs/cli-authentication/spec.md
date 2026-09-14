## MODIFIED Requirements

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
