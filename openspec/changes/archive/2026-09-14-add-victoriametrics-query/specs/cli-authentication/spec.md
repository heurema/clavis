## MODIFIED Requirements

### Requirement: Query command

The CLI SHALL provide `query --connection <ref> (--sql <text> | --sql-stdin | --sql-file <path> | --promql <expr> | --promql-stdin | --promql-file <path> | --labels | --label-values <name> | --series <selector>) [--at <time>] [--start <time>] [--end <time>] [--step <duration>] [--match <selector>] [--max-rows N]`, where `<ref>` is a UUID or name, exactly one input is required, the file inputs take absolute paths, the SQL or expression is bounded to 256 KiB before any request, `--at` applies only to `--promql` without `--start`, `--step` requires `--start`, `--match`, `--start` and `--end` apply to PromQL and discovery inputs only, and a label name is validated locally. Time strings, steps and selectors are sent exactly as typed. The command SHALL use the stored session, the shared flags, transport, envelope and hint conventions of the other groups, except that its `--timeout` SHALL default to the documented query budget rather than five seconds so a statement running to the connection's bound is not cut off by the client, SHALL send one request to the query route and SHALL render the results document in JSON or as text: `psql`-style tables for PostgreSQL, and for VictoriaMetrics one line per vector sample with sorted labels, a block per matrix series, one line per scalar, string or discovery item, with the source's warnings first. `SOURCE_ERROR`, `SOURCE_TIMEOUT`, `SOURCE_UNREACHABLE`, `SOURCE_AUTH_REJECTED`, `CREDENTIALS_UNAVAILABLE`, `PROVIDER_UNSUPPORTED`, `CONNECTION_NOT_FOUND`, `CONNECTION_DISABLED`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through; undocumented responses SHALL map to `INVALID_RESPONSE`. A truncated result SHALL exit 0 with the truncation visible in both outputs; every failure code SHALL exit 1; invalid arguments SHALL exit 2. The SQL or expression SHALL NOT be echoed in results or errors. A provider mismatch reported by the server SHALL pass through as `INVALID_ARGUMENT` with its hint.

#### Scenario: Inline query as JSON
- **WHEN** an agent runs `query --connection payments-prod-reporting --sql 'select count(*) from orders'`
- **THEN** the CLI prints one envelope whose `data.results[0]` carries the column list and one row of strings, exit 0

#### Scenario: Source error as text
- **WHEN** a text-output query fails with a PostgreSQL syntax error
- **THEN** the CLI prints `ERROR: <sqlstate> <message>` with the position line and the statement index, exits 1, and the SQL is not repeated

#### Scenario: Invalid inputs
- **WHEN** the reference is invalid, `--max-rows` is not a positive integer, two inputs are given, the file path is relative, `--at` is combined with `--start`, `--step` lacks `--start`, a time flag accompanies `--sql`, or a label name is not a Prometheus label name
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Instant PromQL as JSON
- **WHEN** an agent runs `query --connection payments-metrics --promql 'up'`
- **THEN** the CLI prints one envelope whose `data.provider` is `victoriametrics`, `data.resultType` is `vector` and `data.result` is the source's vector unchanged, exit 0

#### Scenario: Metric names as text
- **WHEN** an agent runs `query --connection payments-metrics --label-values __name__ --output text`
- **THEN** each metric name prints on its own line followed by the truncation notice only when the server reports truncation

#### Scenario: PromQL error as text
- **WHEN** a text-output PromQL query fails to parse on the source
- **THEN** the CLI prints `ERROR: <errorType> <message>` with no position or statement line, exits 1, and the expression is not repeated
