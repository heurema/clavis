## MODIFIED Requirements

### Requirement: Pass-through execution request

The system SHALL execute one request against a connection the caller may use, as decided by the per-request connection authorization: administrators without a grant, members with one, never a disabled connection. A request carries exactly one input: SQL for a PostgreSQL connection, or for a VictoriaMetrics connection a PromQL expression (an instant query, pinned with an optional `at`, or a range query when `start` and `step` are given, `end` defaulting to the source's now) or one discovery input (`labels`, `labelValues` naming a label, or `series` naming a selector, each with an optional `match` selector and the same time bounds). An input that does not fit the connection's provider SHALL fail with `INVALID_ARGUMENT` and a hint naming the right input, before any credential is opened. The SQL string SHALL be forwarded to PostgreSQL unchanged over the simple query protocol under the connection's stored credentials; the platform SHALL NOT parse, rewrite, restrict by statement type or wrap the string in a transaction, so a string with several statements runs in order under PostgreSQL's implicit transaction unless it contains its own transaction control. No session state SHALL survive a request: each request SHALL open one fresh connection with the connection's statement timeout, `client_encoding` `UTF8` and an `application_name` naming the platform, the connection name and the user, and SHALL close it when the request ends. The platform SHALL impose no pool and no concurrency limit of its own; a role connection limit in the external system is the documented throttle. For VictoriaMetrics the expression, the time strings, the step and the selectors SHALL be forwarded to the source's read-only query and metadata endpoints (`/api/v1/query`, `/api/v1/query_range`, `/api/v1/labels`, `/api/v1/label/<name>/values`, `/api/v1/series`) exactly as submitted, with the stored authentication applied per request, one request per execution, no keep-alive and redirects refused; the platform SHALL NOT parse or validate PromQL, time strings or selectors, so the source's own acceptance rules apply (including its clamping of a reversed range), and no other path on the source SHALL be reachable. A label name for `labelValues` SHALL be validated as a Prometheus label name because it forms a path segment. The SQL or expression SHALL be bounded to 256 KiB and rejected above it with `INVALID_ARGUMENT` and a hint. A connection whose provider does not support execution SHALL answer `PROVIDER_UNSUPPORTED` with a hint before any credential is opened.

#### Scenario: Granted member runs a script
- **WHEN** a member holding a grant sends `insert into notes values ('x'); select count(*) from notes;`
- **THEN** both statements run under the connection's role in one implicit transaction and the response lists two results in order

#### Scenario: Statement the role may not run
- **WHEN** the connection's role lacks the privilege for the submitted statement
- **THEN** PostgreSQL's own error is returned as `SOURCE_ERROR` and the platform has not altered or refused the statement itself

#### Scenario: Ungranted or disabled connection
- **WHEN** a member targets a connection they hold no grant on, or anyone targets a disabled connection
- **THEN** the request fails with `CONNECTION_NOT_FOUND` or `CONNECTION_DISABLED` respectively, no credential is opened and no source is contacted

#### Scenario: Input does not fit the provider
- **WHEN** a request carries SQL for a VictoriaMetrics connection, PromQL for a PostgreSQL one, or two inputs at once
- **THEN** it fails with `INVALID_ARGUMENT` and a hint naming the input the provider takes, and no source is contacted

#### Scenario: Granted member runs PromQL
- **WHEN** a member holding a grant on a VictoriaMetrics connection sends `sum(rate(http_requests_total[5m])) by (job)` with `start`, `end` and `step`
- **THEN** the expression and the three strings reach `/api/v1/query_range` unchanged under the stored authentication and the source's matrix comes back as it is

#### Scenario: Discover metric names
- **WHEN** an agent sends `labelValues: "__name__"` with a `match` selector and time bounds
- **THEN** the request reaches `/api/v1/label/__name__/values` with those parameters unchanged and the source's list comes back bounded by the row cap

#### Scenario: Access revoked between requests
- **WHEN** a member's grant is revoked or their session is revoked after a successful request
- **THEN** the next request is refused, with no connection kept open on their behalf

### Requirement: Structured results

A successful response SHALL carry `provider` naming the connection's provider, and the shape that provider defines. For PostgreSQL it SHALL carry `results`, a list with one entry per executed statement in order, each with `command` (the PostgreSQL command tag word), `columns` (name and PostgreSQL type name per column, empty for statements without rows), `rows` (arrays of values in column order, each value the text PostgreSQL renders or `null` for NULL, never a JSON number, boolean or object), `rowCount` (rows returned for row-producing statements, rows affected otherwise) and `truncated`; plus top-level `truncated` and `durationMs`. The list shape SHALL be used even for a single statement. For VictoriaMetrics it SHALL carry `resultType` (`vector`, `matrix`, `scalar` or `string` for an expression, whatever the request mode, and `labels`, `labelValues` or `series` for discovery) and `result` holding the source's own `data` in the Prometheus format with sample values as strings, plus the source's `warnings`, `infos` and `isPartial` when present; the platform SHALL NOT reformat, reorder or convert any of it beyond the truncation defined below. Text output SHALL render, for PostgreSQL, one aligned table per result with a header, `NULL` marked distinctly from an empty string, a `(N rows)` line, the command tag and affected count for statements without rows; for VictoriaMetrics, one line per vector sample (sorted labels, value, timestamp), one block per matrix series (a labels header and one timestamp-value line per sample), one line for a scalar or string, one item per line for discovery, and warnings before the data; both followed by the truncation notice when set.

#### Scenario: Typed values stay exact
- **WHEN** a statement returns a `numeric`, an `int8` beyond 2^53, a `timestamptz` and a NULL
- **THEN** the values arrive as the strings PostgreSQL rendered, NULL as `null`, and the column list names the types

#### Scenario: Duplicate column names
- **WHEN** a statement is `select 1, 1`
- **THEN** both columns are present in order with the same name and the rows carry both values

#### Scenario: Statement without rows
- **WHEN** a statement is an `UPDATE` affecting three rows
- **THEN** its result has `command: "UPDATE"`, empty `columns` and `rows`, `rowCount: 3`

#### Scenario: Native metrics result
- **WHEN** an instant query returns a vector of two series and the source attaches a warning
- **THEN** the response has `provider: "victoriametrics"`, `resultType: "vector"`, `result` with the two series exactly as the source rendered them (labels and `[timestamp, "value"]`), `warnings` with the source's text, and `truncated: false`

#### Scenario: Instant query that returns a matrix
- **WHEN** an instant query's expression is a range selector such as `up[5m]`
- **THEN** the response is accepted with `resultType: "matrix"`; the result type is validated on its own, never inferred from the request mode

### Requirement: Bounds and explicit truncation

For PostgreSQL the connection's statement timeout SHALL be set as `statement_timeout` for the request so PostgreSQL aborts the statement and its implicit transaction; PostgreSQL applies it to each statement of a script separately, so the platform's own deadline is only a hung-connection backstop of ten times the timeout plus five seconds. For VictoriaMetrics the same timeout SHALL be sent as the API `timeout` parameter so the source aborts its own evaluation (the source caps it at its configured maximum, which the platform respects), and the HTTP request SHALL be bounded by that timeout plus a short documented grace. The platform SHALL report `SOURCE_TIMEOUT` with the bound and SHALL NOT cancel work for any other reason than those backstops. For PostgreSQL the row cap and byte cap SHALL apply to the whole response: once the rows kept reach the cap or their values' UTF-8 length exceeds the byte cap, further rows SHALL be read and discarded until every statement completes, so that what the database did never depends on what the caller sees. The first row of the first row-producing result SHALL always be kept. A response cut this way SHALL mark `truncated` on the affected result and at the top level. For VictoriaMetrics the row cap SHALL be a sample cap over the whole response (one per vector sample, one per matrix value, one per discovery item) and the byte cap SHALL count the UTF-8 length of kept label names, label values and sample values; the platform SHALL decode the source's JSON as a stream, keep samples in source order until a cap is reached; past the sample cap each remaining series keeps its labels and the samples kept so far, and past the byte cap remaining series are dropped whole so kept bytes stay bounded by the cap plus the series that crossed it; each cut series is marked `truncated: true` inside its object, the response `truncated` at the top level, and reading continues so the whole envelope is validated. The body SHALL be read under a documented ceiling of four times the connection's byte cap plus one MiB; a body beyond it or one that does not parse as the source's envelope SHALL fail with `SOURCE_ERROR` carrying `errorType` `response_too_large` or `malformed_response` and a hint, never as truncated data. `isPartial` from the source SHALL be reported as it is and SHALL NOT be folded into `truncated`. The caller MAY pass `maxRows` at or below the connection's row cap; a value above it or below 1 SHALL fail with `INVALID_ARGUMENT` and a hint stating the cap. The platform SHALL read results as a stream and SHALL NOT hold more than the kept rows in memory.

#### Scenario: Row cap hit inside a script
- **WHEN** a script's first statement returns 2,000 rows against a cap of 1,000 and its second statement inserts a row
- **THEN** the response keeps 1,000 rows of the first result marked truncated, the second result shows the insert completed, top-level `truncated` is true and the insert is committed

#### Scenario: Caller lowers the cap
- **WHEN** a request passes `maxRows: 10` on a connection capped at 1,000
- **THEN** at most 10 rows are kept per response and the remainder is drained; `maxRows: 5000` is refused with the cap in the hint

#### Scenario: Statement timeout
- **WHEN** a statement runs longer than the connection's timeout
- **THEN** PostgreSQL aborts it, the response is `SOURCE_TIMEOUT` naming the bound in milliseconds, and no partial rows are presented as a result

#### Scenario: Sample cap on a range query
- **WHEN** a range query returns three series of 1,000 samples each against a cap of 1,200
- **THEN** the response keeps 1,000 samples of the first series and 200 of the second, both marked `truncated: true`, the third series has no samples and is marked, top-level `truncated` is true, and the envelope was read to the end

#### Scenario: Metrics timeout
- **WHEN** an expression takes longer than the connection's timeout on the source
- **THEN** the source aborts it and the response is `SOURCE_TIMEOUT` with the bound in the hint; a source that stops answering is cut at the timeout plus the grace with the same code

#### Scenario: Response beyond the ceiling
- **WHEN** the source's body exceeds four times the byte cap plus one MiB
- **THEN** the request fails with `SOURCE_ERROR`, `errorType: "response_too_large"` and a hint to narrow the range or step or lower `maxRows`, and nothing is presented as data

### Requirement: Distinguishable failures

Failures SHALL use distinct codes: `SOURCE_ERROR` (422) when the source rejects or aborts the request, carrying in `source` for PostgreSQL the `sqlstate`, `message`, `detail`, `hint`, `position` and, as `statement`, the number of statements that completed before the failure (the zero-based index of the failing statement, or 0 when the whole string was rejected at parse time), and for VictoriaMetrics the source's own `errorType` and `message` from its error envelope (or `errorType` `http_<status>` with the bounded body text when the source answers a non-JSON error), with `statement` absent; `SOURCE_TIMEOUT` (504) for the statement timeout; `SOURCE_UNREACHABLE` (502) when the source cannot be connected to, including TLS and unknown-database failures; `SOURCE_AUTH_REJECTED` (502) when the source refuses the credentials (PostgreSQL authentication failures, HTTP 401 or 403); `CREDENTIALS_UNAVAILABLE` (409) when the stored secret cannot be decrypted; `PROVIDER_UNSUPPORTED` (400); and the authorization codes `UNAUTHENTICATED`, `FORBIDDEN`, `CONNECTION_NOT_FOUND` and `CONNECTION_DISABLED`. The source's message MAY contain values from the caller's own SQL and SHALL be passed to the caller unchanged; it SHALL NOT enter any log or operational output. Results completed before a failing statement SHALL NOT be returned: under the implicit transaction they were rolled back, and a script with its own transaction control gets the error alone as well.

#### Scenario: Failure in the second statement
- **WHEN** a two-statement script fails on the second statement because a column does not exist
- **THEN** the response is `SOURCE_ERROR` with the SQLSTATE, message and position (an offset into the submitted string) from PostgreSQL and `statement: 1`, and no results are returned

#### Scenario: Grammatical error anywhere in the script
- **WHEN** a script contains a grammatical error, one the parser reports before any statement is analysed
- **THEN** PostgreSQL rejects the whole string before running anything, the response is `SOURCE_ERROR` with `statement: 0` and the position of the error as an offset into the submitted string, and no statement has run

#### Scenario: Source unreachable or refusing credentials
- **WHEN** the target host is down, or the role's password was changed in the source
- **THEN** the response is `SOURCE_UNREACHABLE` or `SOURCE_AUTH_REJECTED` with a hint to run `connections check`, and no driver text is exposed

#### Scenario: Bad PromQL
- **WHEN** an expression fails to parse on the source
- **THEN** the response is `SOURCE_ERROR` with the source's `errorType` (`bad_data`) and message, no `sqlstate` and no `statement`

#### Scenario: Source refuses the resolution
- **WHEN** a range query exceeds the source's configured points-per-series limit
- **THEN** the source's own error is passed through as `SOURCE_ERROR` with its `errorType` and message; the platform changes neither the step nor the range

### Requirement: Query route and command

The system SHALL expose `POST /api/query` accepting `{connection, maxRows?}` plus exactly one input (`sql`, or `promql` with optional `at` or `start`, `end`, `step`, or `labels: true`, `labelValues`, `series`, each with optional `match`, `start`, `end`) from a bearer session, where `connection` is a UUID or name, with strict decoding, `no-store` and the JSON failure envelope; success SHALL be 200 with the results document. The route SHALL NOT run under the five-second operation deadline of the other routes: its request deadline SHALL be a documented query budget large enough for the platform's hung-connection backstop at the largest statement timeout, and the server SHALL extend its write deadline for the request accordingly. The response SHALL be bounded by the connection's byte cap plus at most one row (the row that crossed the cap, or a first row of any size), JSON escaping and a fixed envelope allowance; the CLI SHALL read a query response up to twice the byte-cap ceiling plus the allowance and report `INVALID_RESPONSE` beyond it, so a single value larger than the ceiling cannot be retrieved. The CLI SHALL provide `query --connection <ref> (--sql <text> | --sql-stdin | --sql-file <path> | --promql <expr> | --promql-stdin | --promql-file <path> | --labels | --label-values <name> | --series <selector>) [--at <time>] [--start <time>] [--end <time>] [--step <duration>] [--match <selector>] [--max-rows N] [--output json|text]`, requiring exactly one input and refusing time flags that do not apply to it, validating the reference and bounds locally, sending one request, and passing through `SOURCE_ERROR`, `SOURCE_TIMEOUT`, `SOURCE_UNREACHABLE`, `SOURCE_AUTH_REJECTED`, `CREDENTIALS_UNAVAILABLE`, `PROVIDER_UNSUPPORTED`, `CONNECTION_NOT_FOUND`, `CONNECTION_DISABLED`, `FORBIDDEN` and `UNAUTHENTICATED`; undocumented responses SHALL map to `INVALID_RESPONSE`. Exit codes SHALL be 0 for a successful response including a truncated one, 1 for every failure code, 2 for invalid arguments. The response SHALL never echo the SQL or the expression.

#### Scenario: Query from a heredoc
- **WHEN** an agent pipes a script into `query --connection payments-prod-reporting --sql-stdin`
- **THEN** the CLI sends one request with the script and prints the results document, exit 0

#### Scenario: Two SQL inputs or none
- **WHEN** both `--sql` and `--sql-file` are given, or neither, or the file is not an absolute path
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint naming the three inputs, without contacting the server

#### Scenario: Truncated result as text
- **WHEN** a text-output query hits the row cap
- **THEN** the table shows the kept rows, `(1000 rows)` and a notice that the result was truncated, and the exit code is 0

#### Scenario: Range query from the command line
- **WHEN** an agent runs `query --connection payments-metrics --promql 'rate(errors_total[5m])' --start -1h --step 1m`
- **THEN** the CLI sends one request with the expression, `start` and `step` as typed and no `end`, and prints the matrix document, exit 0

#### Scenario: Time flag on the wrong input
- **WHEN** `--at` is combined with `--start`, or any time flag with `--sql`
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server
