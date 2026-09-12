## Why

Grants now answer "may this user use this connection", but nothing can use one: the platform cannot execute a query, so the product's core flow (an agent asks a granted PostgreSQL connection a question and gets a bounded, structured answer) does not exist yet (PRD 7.4 PostgreSQL, CONN-09, CLI-04, CLI-05, CLI-08, CLI-09, ACCESS-04). This is the first caller of the authorization check and the first provider operation, so it fixes the shape every later provider follows.

## What Changes

- Add pass-through query execution for PostgreSQL connections: one request carries one SQL string that is forwarded unchanged under the connection's credentials; the external role is the only access boundary, no statement types are refused and nothing is wrapped in a read-only transaction.
- Allow multi-statement strings: PostgreSQL splits them and applies its implicit transaction; the response is always a list of results, one per statement, in order.
- Return structured results: a column list with PostgreSQL type names, rows as arrays of strings (`null` for NULL), the command tag and affected count for statements without rows.
- Enforce the connection's bounds: the statement timeout through PostgreSQL's `statement_timeout`, the row and byte caps by draining (results beyond the cap are read and dropped, never cancelled), with explicit `truncated` flags per result and per response, and an optional per-request `maxRows` at or below the cap.
- Report failures as distinguishable codes: `SOURCE_ERROR` with the source's SQLSTATE, message, detail, hint, position and failing statement index; `SOURCE_TIMEOUT`; `SOURCE_UNREACHABLE`; `SOURCE_AUTH_REJECTED`; `PROVIDER_UNSUPPORTED` for VictoriaMetrics until its own change; plus the existing authorization and credential codes.
- Open one fresh connection per request and close it afterwards: no pool and no concurrency cap of our own; a role's `CONNECTION LIMIT` in PostgreSQL is the documented throttle.
- Audit every request as `query.execute` with actor, session, connection, outcome, duration, statement count, rows and bytes returned; never the SQL, never a source message. Migration `005` widens the allowlists and adds the nullable metric columns.
- Add `POST /api/query` and `clavis query --connection <ref> (--sql | --sql-stdin | --sql-file) [--max-rows N]` with JSON and `psql`-style text output; the SQL is bounded to 256 KiB and the response to the connection's byte cap plus a fixed envelope allowance.
- Add smoke coverage against the smoke database, README and PRD updates. No web changes.

## Capabilities

### New Capabilities

- `query-execution`: the pass-through request, result shape, bounds and truncation, failure codes, per-request connection lifecycle, the query route and command, and the audit record of an execution.

### Modified Capabilities

- `connection-management`: the provider registry declares an execute operation next to the probe; a disabled connection rejects execution with `CONNECTION_DISABLED`; the stored bounds are now enforced.
- `local-authentication`: the event allowlist gains `query.execute` and the execution outcomes; events gain nullable duration, statement count, rows and bytes columns for request events.
- `cli-authentication`: the `query` command; the bounded transport gains per-route request and response limits (the SQL body and the result body).

## Impact

- Backend: `internal/auth` (query DTOs, `QueryExecutor` interface, codes, action and outcomes), `internal/provider` (`Execute` on the interface, the PostgreSQL implementation with streaming drain, unsupported for VictoriaMetrics), `internal/database` (migration `005`, `ExecuteQuery` on `LocalAuth`, the event write), `internal/server` (the query route).
- Client: `internal/cli` query command, three SQL inputs, result rendering, per-route limits.
- Tooling/docs: `scripts/smoke.mjs`, README, PRD section 12 status.
- Dependencies: none new; pgx's simple query protocol and `pgconn` multi-result reader are already available.

## Owner decisions (2026-09-12 interview)

- One statement string per request, stateless; multi-statement strings allowed through the simple protocol.
- Results always a list; rows as arrays of strings with a typed column list.
- Caps enforced by draining, never by cancel; timeout enforced by PostgreSQL.
- Separate failure codes for source error, timeout, unreachable and refused authentication; the source's message is passed through to the caller and kept out of the audit.
- One connection per request; no pool, no concurrency cap, no key rotation work.
- SQL from `--sql`, `--sql-stdin` or `--sql-file`, exactly one.
- `clavis describe` dropped; schema discovery is a query the skill documents.

## Inherited requirements and explicit departures

- PRD 7.6 says a request event contains duration, result size and whether the result was truncated or timed out. The interview settled "no new audit columns"; that would depart from the PRD, so this proposal keeps the requirement with four nullable integer columns written only by request events. Striking them is an owner decision to record here.
- The `psql` cursor optimisation for single `SELECT`s and connection pooling are recorded as follow-ups, not built.

## Non-goals

VictoriaMetrics queries, groups, audit inspection, the agent skill, schema discovery commands, query cancellation, prepared statements or parameters, result streaming to the CLI, per-connection concurrency limits, key rotation.
