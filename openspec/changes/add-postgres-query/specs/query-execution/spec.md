## Purpose

Let a user with access execute SQL against a PostgreSQL connection through the platform, under the connection's credentials and bounds, with structured results and distinguishable failures.

## ADDED Requirements

### Requirement: Pass-through execution request

The system SHALL execute one SQL string per request against a connection the caller may use, as decided by the per-request connection authorization: administrators without a grant, members with one, never a disabled connection. The string SHALL be forwarded to PostgreSQL unchanged over the simple query protocol under the connection's stored credentials; the platform SHALL NOT parse, rewrite, restrict by statement type or wrap the string in a transaction, so a string with several statements runs in order under PostgreSQL's implicit transaction unless it contains its own transaction control. No session state SHALL survive a request: each request SHALL open one fresh connection with the connection's statement timeout, `client_encoding` `UTF8` and an `application_name` naming the platform, the connection name and the user, and SHALL close it when the request ends. The platform SHALL impose no pool and no concurrency limit of its own; a role connection limit in the external system is the documented throttle. The SQL SHALL be bounded to 256 KiB and rejected above it with `INVALID_ARGUMENT` and a hint. A connection whose provider does not support execution SHALL answer `PROVIDER_UNSUPPORTED` with a hint before any credential is opened.

#### Scenario: Granted member runs a script
- **WHEN** a member holding a grant sends `insert into notes values ('x'); select count(*) from notes;`
- **THEN** both statements run under the connection's role in one implicit transaction and the response lists two results in order

#### Scenario: Statement the role may not run
- **WHEN** the connection's role lacks the privilege for the submitted statement
- **THEN** PostgreSQL's own error is returned as `SOURCE_ERROR` and the platform has not altered or refused the statement itself

#### Scenario: Ungranted, disabled or unsupported connection
- **WHEN** a member targets a connection they hold no grant on, anyone targets a disabled connection, or the connection is a VictoriaMetrics one
- **THEN** the request fails with `CONNECTION_NOT_FOUND`, `CONNECTION_DISABLED` or `PROVIDER_UNSUPPORTED` respectively, no credential is opened and no source is contacted

#### Scenario: Access revoked between requests
- **WHEN** a member's grant is revoked or their session is revoked after a successful request
- **THEN** the next request is refused, with no connection kept open on their behalf

### Requirement: Structured results

A successful response SHALL carry `results`, a list with one entry per executed statement in order, each with `command` (the PostgreSQL command tag word), `columns` (name and PostgreSQL type name per column, empty for statements without rows), `rows` (arrays of values in column order, each value the text PostgreSQL renders or `null` for NULL, never a JSON number, boolean or object), `rowCount` (rows returned for row-producing statements, rows affected otherwise) and `truncated`; plus top-level `truncated` and `durationMs`. The list shape SHALL be used even for a single statement. Text output SHALL render one aligned table per result with a header, `NULL` marked distinctly from an empty string, a `(N rows)` line, the command tag and affected count for statements without rows, and the truncation notice when set.

#### Scenario: Typed values stay exact
- **WHEN** a statement returns a `numeric`, an `int8` beyond 2^53, a `timestamptz` and a NULL
- **THEN** the values arrive as the strings PostgreSQL rendered, NULL as `null`, and the column list names the types

#### Scenario: Duplicate column names
- **WHEN** a statement is `select 1, 1`
- **THEN** both columns are present in order with the same name and the rows carry both values

#### Scenario: Statement without rows
- **WHEN** a statement is an `UPDATE` affecting three rows
- **THEN** its result has `command: "UPDATE"`, empty `columns` and `rows`, `rowCount: 3`

### Requirement: Bounds and explicit truncation

The connection's statement timeout SHALL be set as PostgreSQL's `statement_timeout` for the request so PostgreSQL aborts the statement and its implicit transaction; the platform SHALL report `SOURCE_TIMEOUT` with the bound and SHALL NOT cancel statements for any other reason. The row cap and byte cap SHALL apply to the whole response: once the rows kept reach the cap or their values' UTF-8 length exceeds the byte cap, further rows SHALL be read and discarded until every statement completes, so that what the database did never depends on what the caller sees. The first row of the first row-producing result SHALL always be kept. A response cut this way SHALL mark `truncated` on the affected result and at the top level. The caller MAY pass `maxRows` at or below the connection's row cap; a value above it or below 1 SHALL fail with `INVALID_ARGUMENT` and a hint stating the cap. The platform SHALL read results as a stream and SHALL NOT hold more than the kept rows in memory.

#### Scenario: Row cap hit inside a script
- **WHEN** a script's first statement returns 2,000 rows against a cap of 1,000 and its second statement inserts a row
- **THEN** the response keeps 1,000 rows of the first result marked truncated, the second result shows the insert completed, top-level `truncated` is true and the insert is committed

#### Scenario: Caller lowers the cap
- **WHEN** a request passes `maxRows: 10` on a connection capped at 1,000
- **THEN** at most 10 rows are kept per response and the remainder is drained; `maxRows: 5000` is refused with the cap in the hint

#### Scenario: Statement timeout
- **WHEN** a statement runs longer than the connection's timeout
- **THEN** PostgreSQL aborts it, the response is `SOURCE_TIMEOUT` naming the bound in milliseconds, and no partial rows are presented as a result

### Requirement: Distinguishable failures

Failures SHALL use distinct codes: `SOURCE_ERROR` (422) when PostgreSQL rejects or aborts the SQL, carrying the source's `sqlstate`, `message`, `detail`, `hint`, `position` and the zero-based index of the failing statement in `source`; `SOURCE_TIMEOUT` (504) for the statement timeout; `SOURCE_UNREACHABLE` (502) when the source cannot be connected to, including TLS and unknown-database failures; `SOURCE_AUTH_REJECTED` (502) when the source refuses the credentials; `CREDENTIALS_UNAVAILABLE` (409) when the stored secret cannot be decrypted; `PROVIDER_UNSUPPORTED` (400); and the authorization codes `UNAUTHENTICATED`, `FORBIDDEN`, `CONNECTION_NOT_FOUND` and `CONNECTION_DISABLED`. The source's message MAY contain values from the caller's own SQL and SHALL be passed to the caller unchanged; it SHALL NOT enter any log or operational output. Results completed before a failing statement SHALL NOT be returned, because the implicit transaction rolled them back.

#### Scenario: Syntax error in the second statement
- **WHEN** a two-statement script fails on the second statement
- **THEN** the response is `SOURCE_ERROR` with the SQLSTATE, message and position from PostgreSQL and `statement: 1`, and no results are returned

#### Scenario: Source unreachable or refusing credentials
- **WHEN** the target host is down, or the role's password was changed in the source
- **THEN** the response is `SOURCE_UNREACHABLE` or `SOURCE_AUTH_REJECTED` with a hint to run `connections check`, and no driver text is exposed

### Requirement: Query route and command

The system SHALL expose `POST /api/query` accepting `{connection, sql, maxRows?}` from a bearer session, where `connection` is a UUID or name, with strict decoding, `no-store` and the JSON failure envelope; success SHALL be 200 with the results document. The response SHALL be bounded by the connection's byte cap plus a fixed envelope allowance, and the CLI SHALL read it under that same bound. The CLI SHALL provide `query --connection <ref> (--sql <text> | --sql-stdin | --sql-file <path>) [--max-rows N] [--output json|text]`, requiring exactly one SQL input, validating the reference and bounds locally, sending one request, and passing through `SOURCE_ERROR`, `SOURCE_TIMEOUT`, `SOURCE_UNREACHABLE`, `SOURCE_AUTH_REJECTED`, `CREDENTIALS_UNAVAILABLE`, `PROVIDER_UNSUPPORTED`, `CONNECTION_NOT_FOUND`, `CONNECTION_DISABLED`, `FORBIDDEN` and `UNAUTHENTICATED`; undocumented responses SHALL map to `INVALID_RESPONSE`. Exit codes SHALL be 0 for a successful response including a truncated one, 1 for every failure code, 2 for invalid arguments. The response SHALL never echo the SQL.

#### Scenario: Query from a heredoc
- **WHEN** an agent pipes a script into `query --connection payments-prod-reporting --sql-stdin`
- **THEN** the CLI sends one request with the script and prints the results document, exit 0

#### Scenario: Two SQL inputs or none
- **WHEN** both `--sql` and `--sql-file` are given, or neither, or the file is not an absolute path
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint naming the three inputs, without contacting the server

#### Scenario: Truncated result as text
- **WHEN** a text-output query hits the row cap
- **THEN** the table shows the kept rows, `(1000 rows)` and a notice that the result was truncated, and the exit code is 0
