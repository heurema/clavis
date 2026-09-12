## Context

Three changes have built the platform up to "who may use which connection": local users and sessions, connections with encrypted credentials and probes, and grants with `AuthorizeConnection`. The provider package knows how to parse a PostgreSQL target and probe it with pgx; the connection record stores a statement timeout, a row cap and a byte cap that nothing enforces yet; every mutation runs through `administer` and every read through a short transaction with `recheck`. The audit journal is being removed by `remove-audit-journal`, which lands before this change. The CLI has one transport with a general 64 KiB response bound and a 256 KiB listing bound, and an 8 KiB request bound sized for credential bodies.

This change adds the first provider operation, query execution for PostgreSQL, and with it the pattern every later operation follows: authorize, open the secret, call the provider outside any platform transaction, bound the result.

## Goals / Non-Goals

**Goals:**
- Forward SQL unchanged and let PostgreSQL be the only judge of it.
- Bound time, rows and bytes exactly as the record says, with truncation an agent cannot miss.
- Failures an agent can branch on without parsing text.
- A CLI command agents can drive from a heredoc.

**Non-Goals:**
- VictoriaMetrics execution, parameters or prepared statements, cursors, pooling, cancellation, concurrency limits, result streaming to the client, any recording of executions.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Pass-through: any SQL, no statement filtering, no read-only wrapping; the external role is the boundary | PRD 5, 7.4 | Retained |
| Per-connection statement timeout, row cap and byte cap with explicit truncation, defaults and ceilings | connection-management "Connection records" | Retained; enforced here for the first time |
| `AuthorizeConnection` is the one answer before forwarding | connection-grants "Per-request connection authorization" | Retained; called first |
| Secrets decrypted per operation, wiped after use, never in output or logs | connection-management "Encrypted credentials at rest" | Retained; the same `open` helper |
| No audit journal in the MVP | PRD 7.7 as amended 2026-09-12; `remove-audit-journal` | Retained: executions record nothing |
| Agent-first CLI: one vocabulary, refs, hints, envelope, bounded transport | archived add-connections design | Retained; `query` joins the vocabulary |
| Bounded transport with a general limit and a listing limit | cli-authentication "Bounded and non-disclosing authentication transport" | Explicitly changed: per-route bounds, the query route gets its own request and response bound |
| `describe` command | PRD 7.4 "discovery of accessible database structures" | Explicitly dropped by the owner on 2026-09-12: discovery is a query the skill documents |

No unresolved departure requires owner approval; `describe` was dropped by the owner.

## Decisions

### 1. Contracts

`internal/auth` gains:

```go
type QueryRequest struct { Connection string `json:"connection"`; SQL string `json:"sql"`; MaxRows int `json:"maxRows,omitempty"` }
type QueryColumn struct { Name string `json:"name"`; Type string `json:"type"` }
type QueryResult struct {
    Command   string        `json:"command"`
    Columns   []QueryColumn `json:"columns"`
    Rows      [][]*string   `json:"rows"`
    RowCount  int64         `json:"rowCount"`
    Truncated bool          `json:"truncated"`
}
type QueryResponse struct { Results []QueryResult `json:"results"`; Truncated bool `json:"truncated"`; DurationMS int64 `json:"durationMs"` }
type SourceFailure struct { SQLState, Message, Detail, Hint string; Position int; Statement int } // JSON keys sqlstate, message, detail, hint, position, statement
type QueryExecutor interface { ExecuteQuery(ctx, Session, QueryRequest) (QueryResponse, error) }
```

`Error` gains an optional `Source *SourceFailure` rendered as `error.source` in the failure envelope. New codes: `SourceError` (422), `SourceTimeout` (504), `SourceUnreachable` (502), `SourceAuthRejected` (502), `ProviderUnsupported` (400). `MaxSQLBytes = 256 KiB`, `QueryEnvelopeAllowance = 64 KiB`, `QueryPath = /api/query`.

Rows are `[][]*string` so NULL is `null` and every value is the text PostgreSQL sent (simple protocol returns text format). No numeric conversion anywhere.

### 2. Provider execute

`provider.Provider` gains `Execute(ctx, target, secret, request ExecuteRequest) (ExecuteResult, error)` with `ExecuteRequest{SQL string; Timeout time.Duration; MaxRows int; MaxBytes int}` and `ExecuteResult{Results []auth.QueryResult; Truncated bool; Statements, Rows, Bytes int64}`. Errors are typed: `*SourceError{auth.SourceFailure}`, `ErrTimeout`, `ErrUnreachable`, `ErrAuthRejected`, `ErrUnsupported`. VictoriaMetrics returns `ErrUnsupported`.

PostgreSQL: build the config as the probe does (URL without password, password on the config), `ConnectTimeout` from the remaining operation budget, `RuntimeParams` `statement_timeout=<ms>`, `client_encoding=UTF8`, `application_name=clavis:<connection-name>:<username>` (both already validated slugs). Connect, then `conn.PgConn().Exec(ctx, sql)` (simple protocol, multi-statement), iterate `NextResult`/`ResultReader`: capture `FieldDescriptions` (name and type name resolved through `conn.TypeMap().TypeForOID`, falling back to the OID as text), read rows with `NextRow`/`Values`, copy values into strings, count bytes as the UTF-8 length of kept values, stop keeping rows once `MaxRows` or `MaxBytes` is reached (first row of the first row-producing result always kept), keep draining, `Close` each reader for the command tag, `Close` the multi reader for the final error. Map `*pgconn.PgError`: SQLSTATE `57014` to `ErrTimeout`, class `28` on connect to `ErrAuthRejected`, other connect failures to `ErrUnreachable`, everything else to `*SourceError` with the statement index taken from the number of results completed. Close the connection with its own one-second deadline, as the probe does.

PostgreSQL applies `statement_timeout` to each statement of a script separately, so the platform's own deadline is only a hung-connection backstop of ten times the statement timeout plus five seconds, the one case in which the platform itself cancels; reaching it is reported as `SOURCE_TIMEOUT`. The provider composes nothing: the service passes the finished `application_name` (`clavis:<connection-name>:<username>`, which PostgreSQL truncates to 63 bytes) and the provider falls back to `clavis` for an empty value and to the documented default caps for zero caps.

### 3. Service

`ExecuteQuery` on `LocalAuth`: validate the reference, SQL size and `MaxRows` shape (`INVALID_ARGUMENT` with hints); `AuthorizeConnection`; `connectionProvider` and `ErrUnsupported` before opening the secret; `open` the secret, wipe after; call `Execute` with the record's bounds, `MaxRows` lowered by the request; map the result or typed error to the response or code. No advisory key, no row lock, no platform write: nothing in the platform changes, and the duration is measured around the provider call.

### 4. HTTP

`POST /api/query`, bearer only (`cliSession`), `decodeFields` with the SQL bound of `MaxSQLBytes + 4 KiB`, `connection` validated with `ValidConnectionRef`, `maxRows` an optional positive integer. Success 200 with `QueryResponse`; `Error.Source` rendered in the envelope. The response is encoded once and served without a size check: the drain keeps the row that crosses the byte cap and always the first row, and JSON escaping can grow values, so the wire size is the cap plus at most one row plus escaping plus the envelope.

### 5. CLI

`query --connection <ref> --sql <text> | --sql-stdin | --sql-file <path> [--max-rows N]`. Exactly one input, the file read with the same absolute-path rule as `--password-file` but without the permission rule (SQL is not a secret). `apiCall` gains per-route bounds: `requestLimit` (default `MaxCredentialBody`, `MaxSQLBytes + 4 KiB` for the query route) and `responseLimit` (default `MaxResponseBody`, listing limit for listings, `2 * MaxMaxBytes + allowance` for the query route: the cap is unknown to the CLI, the overshoot is at most one row, and escaping at most doubles ordinary text; a single value beyond that cannot be retrieved and is reported as `INVALID_RESPONSE`). `routeFailures` lists the ten codes. Text rendering: per result a header line, an aligned table (column widths from the kept rows, values as is, `NULL` rendered as `∅` to distinguish it from an empty string), `(N rows)`, or `<COMMAND> <count>` for statements without rows; `Truncated: true` after the tables; `Duration: <ms> ms`. A source error renders `ERROR: <sqlstate> <message>`, then `DETAIL:`/`HINT:` when present, `Position: <n>` and `Statement: <index>`.

### 6. Smoke

A `smoke-query` section against the smoke database: the granted member runs a two-statement script (create temp table plus select) and gets two results; a `select generate_series(1, 2000)` against a 1,000 cap comes back truncated with 1,000 rows and exit 0; `--max-rows 5` returns 5; a syntax error returns `SOURCE_ERROR` with a SQLSTATE and exit 1; `--sql-stdin` and `--sql-file` work; an ungranted connection is `CONNECTION_NOT_FOUND`; a disabled one `CONNECTION_DISABLED`; the VictoriaMetrics connection `PROVIDER_UNSUPPORTED`; a `pg_sleep(3)` on a connection updated to a 1 s timeout returns `SOURCE_TIMEOUT`; the platform database row counts are unchanged by the whole section.

## Risks / Trade-offs

- [Draining a huge result costs transfer time] → bounded by the statement timeout; `--max-rows` and `LIMIT` are the agent's tools; the cursor optimisation is a recorded follow-up.
- [Source messages may carry data] → returned to the caller who wrote the SQL, never stored or logged.
- [Statement timeout does not cover connect time] → the request deadline (timeout plus grace) does.
- [Type names for unknown OIDs] → rendered as the OID number; exact values are unaffected.
- [Response size] → values are bounded by the drain; the envelope allowance covers column metadata for wide results (each column costs about 40 bytes; 64 KiB covers 1,000 columns).

## Migration Plan

1. Deploy after `remove-audit-journal`; no migration of its own.
2. Older CLIs lack `query`; nothing else changes for them.
3. Rollback as before: previous binary.

## Open Questions

None.
