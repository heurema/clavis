## MODIFIED Requirements

### Requirement: Pass-through execution request

The system SHALL execute one request against a connection the caller may use, as decided by the per-request connection authorization: administrators without a grant, members with effective access through a direct grant or a group they belong to, never a disabled connection. A request carries exactly one input: SQL for a PostgreSQL connection, or for a VictoriaMetrics connection a PromQL expression (an instant query, pinned with an optional `at`, or a range query when `start` and `step` are given, `end` defaulting to the source's now) or one discovery input (`labels`, `labelValues` naming a label, or `series` naming a selector, each with an optional `match` selector and the same time bounds), or for a VictoriaLogs connection a LogsQL query (`logsql`, with optional `start`, `end` and `limit`, the source's own limit forwarded as typed) or one log discovery input (`fieldNames`, `fieldValues` naming a field, `streams`, `streamFieldNames`, or `streamFieldValues` naming a field, each requiring `match` as the source's query, with optional `start` and `end`, and `limit` or `filter` where the source's endpoint takes them). An input that does not fit the connection's provider SHALL fail with `INVALID_ARGUMENT` and a hint naming the right input, before any credential is opened. The SQL string SHALL be forwarded to PostgreSQL unchanged over the simple query protocol under the connection's stored credentials; the platform SHALL NOT parse, rewrite, restrict by statement type or wrap the string in a transaction, so a string with several statements runs in order under PostgreSQL's implicit transaction unless it contains its own transaction control. No session state SHALL survive a request: each request SHALL open one fresh connection with the connection's statement timeout, `client_encoding` `UTF8` and an `application_name` naming the platform, the connection name and the user, and SHALL close it when the request ends. The platform SHALL impose no pool and no concurrency limit of its own; a role connection limit in the external system is the documented throttle. For VictoriaMetrics the expression, the time strings, the step and the selectors SHALL be forwarded to the source's read-only query and metadata endpoints (`/api/v1/query`, `/api/v1/query_range`, `/api/v1/labels`, `/api/v1/label/<name>/values`, `/api/v1/series`) exactly as submitted, with the stored authentication applied per request, one request per execution, no keep-alive and redirects refused; the platform SHALL NOT parse or validate PromQL, time strings or selectors, so the source's own acceptance rules apply (including its clamping of a reversed range), and no other path on the source SHALL be reachable. For VictoriaLogs the query, the time strings, the limit and the filter SHALL be forwarded to the source's read-only endpoints (`/select/logsql/query`, `/select/logsql/field_names`, `/select/logsql/field_values`, `/select/logsql/streams`, `/select/logsql/stream_field_names`, `/select/logsql/stream_field_values`) exactly as submitted, with the same per-request authentication, the connection's tenant headers when configured, one request per execution, no keep-alive and redirects refused; the platform SHALL NOT parse LogsQL, add a limit, sort, default or reorder anything, so ordering and aggregation are the query's job, and `limit` or `filter` for an endpoint that does not take it SHALL fail with `INVALID_ARGUMENT` and a hint before any request. A field name for `fieldValues` or `streamFieldValues` is a parameter value and SHALL be bounded, not validated by grammar. A label name for `labelValues` SHALL be validated as a Prometheus label name because it forms a path segment. The SQL, expression, query or discovery query SHALL be bounded to 256 KiB and rejected above it with `INVALID_ARGUMENT` and a hint. A connection whose provider does not support execution SHALL answer `PROVIDER_UNSUPPORTED` with a hint before any credential is opened.

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
- **WHEN** a request carries SQL for a VictoriaMetrics connection, PromQL for a PostgreSQL one, LogsQL for either of them, or two inputs at once
- **THEN** it fails with `INVALID_ARGUMENT` and a hint naming the input the provider takes, and no source is contacted

#### Scenario: Granted member runs PromQL
- **WHEN** a member holding a grant on a VictoriaMetrics connection sends `sum(rate(http_requests_total[5m])) by (job)` with `start`, `end` and `step`
- **THEN** the expression and the three strings reach `/api/v1/query_range` unchanged under the stored authentication and the source's matrix comes back as it is

#### Scenario: Discover metric names
- **WHEN** an agent sends `labelValues: "__name__"` with a `match` selector and time bounds
- **THEN** the request reaches `/api/v1/label/__name__/values` with those parameters unchanged and the source's list comes back bounded by the row cap

#### Scenario: Granted member runs LogsQL
- **WHEN** a member holding a grant on a VictoriaLogs connection sends `error _time:1h | sort by (_time) desc` with `limit: 100`
- **THEN** the query and `limit=100` reach `/select/logsql/query` unchanged under the stored authentication and the connection's tenant headers, and the source's rows come back as it wrote them, in arrival order

#### Scenario: Discover log field values
- **WHEN** an agent sends `fieldValues: "level"` with `match: "*"`, `filter: "err"` and time bounds
- **THEN** the request reaches `/select/logsql/field_values` with `query=*`, `field=level`, `filter=err` and the bounds unchanged, and the source's `value` and `hits` pairs come back bounded by the row cap

#### Scenario: Limit where the source takes none
- **WHEN** a request carries `fieldNames: true` with `limit`, or `filter` with `logsql`
- **THEN** it fails with `INVALID_ARGUMENT` and a hint naming the inputs that take the parameter, and no source is contacted

#### Scenario: Access revoked between requests
- **WHEN** a member's grant is revoked or their session is revoked after a successful request
- **THEN** the next request is refused, with no connection kept open on their behalf
