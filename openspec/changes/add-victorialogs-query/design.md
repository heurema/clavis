## Context

Two providers execute through one `query` verb and one route: PostgreSQL forwards SQL and drains the response to the end; VictoriaMetrics forwards PromQL and metadata requests, decodes the source's JSON envelope as a stream under a sample cap, a byte cap and a body ceiling, and validates the whole envelope. `provider` names the shape on every response, `errorType` carries a source's own classification, `statement` is optional. VictoriaLogs implements the LogsQL HTTP API: `/select/logsql/query` streams newline-delimited JSON objects, unbounded unless `limit` is given and in arbitrary order unless the query sorts; the discovery endpoints answer one JSON object with a `values` array of `{value, hits}`; errors are plain text with an HTTP status (400 for a rejected query, 503 for the source's own timeout); `timeout` is honoured up to `-search.maxQueryDuration`; tenants are selected by the `AccountID` and `ProjectID` headers; health is `/health`. The PRD lists log sources as a later stage; the owner pulled VictoriaLogs into the MVP on 2026-09-14. The design was critiqued by a second model in two rounds on the same day; every point below was settled between the two.

## Goals / Non-Goals

**Goals:** LogsQL and log discovery through the existing verb; the source's rows returned exactly as written; the connection's bounds enforced without ever changing what the source is asked; every failure the source's own; tenant selection as connection configuration.

**Non-Goals:** `hits`, `stats_query`, `stats_query_range`, `facets`, `stream_ids`, tail, ingestion, Loki, a log catalog of our own, parsing `_msg`, timestamp normalisation, mutual TLS or OAuth2.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| One `query` verb, agent-first flags, hints, envelope, exit codes | query-execution, cli-authentication | Retained; new inputs on the same verb |
| Pass-through: nothing parsed, filtered, rewritten or defaulted | PRD 5 and 6, query-execution | Retained; LogsQL, time strings, limit and filter forwarded as typed; ordering is the query's job |
| Native shape per provider with the `provider` discriminator | archived add-victoriametrics-query | Retained; `logs` rows as written; no shared log schema for future sources |
| Drain to the end of the response, never cancel except at a backstop | query-execution "Bounds and explicit truncation" | Explicitly changed for the log stream (owner 2026-09-14): stop at the cap and close, because a log read has no side effects and JSON lines have no envelope; discovery envelopes keep the drain |
| Discovery sends `limit` = cap + 1 | archived add-victoriametrics-query design 2 | Explicitly changed for VictoriaLogs (owner 2026-09-14): no synthesized limit anywhere, because a source limit changes what the source executes (it sorts by `_time` before cutting); the metrics path is left as it is |
| Log sources are a later stage | PRD 9 | Explicitly changed (owner 2026-09-14): one log source enters the MVP; PRD 7.4, 9 and 12 record it |
| The source's own timeout is its own error; only the platform's deadline is `SOURCE_TIMEOUT` | archived add-victoriametrics-query task 3.4 exception | Retained; VictoriaLogs answers 503 plain text |
| Timeout forwarded and used as the HTTP deadline plus `MetricsGrace` | archived add-victoriametrics-query | Retained |
| Stored auth applied per request, redirects refused, no keep-alive, `/health` probe | connection-management | Retained; tenant headers added beside the auth |
| Provider target settings declared by the provider; unknown keys refused | connection-management "Provider registry" | Retained; `accountId` and `projectId` are `victorialogs` settings |
| No audit journal | PRD 7.7 | Retained |

No unresolved departure.

## Decisions

### 1. Contracts

`auth.ProviderType` gains `victorialogs`. `auth.QueryRequest` gains `LogsQL string` (`logsql`), `Limit *int64` (`limit`, omitted versus explicit zero preserved, zero meaning no limit to the source, negative refused), `FieldNames bool` (`fieldNames`), `FieldValues string` (`fieldValues`), `Streams bool` (`streams`), `StreamFieldNames bool` (`streamFieldNames`), `StreamFieldValues string` (`streamFieldValues`), `Filter string` (`filter`); it reuses `Start`, `End` and `Match`. Exactly one of the eleven inputs is set. Rules: `Limit` and `Filter` only with a VictoriaLogs input, `Limit` only with `logsql`, `fieldValues`, `streams`, `streamFieldValues`; `Filter` only with the four field-name and field-value inputs; `Match` required with every log discovery input; `At` and `Step` never with a log input. `auth.QueryResponse` is unchanged: `ResultType` takes `logs`, `fieldNames`, `fieldValues`, `streams`, `streamFieldNames`, `streamFieldValues`; `Result` holds the array. `SourceFailure` is unchanged. Field names and `Match` are bounded by `MaxSQLBytes`; `Filter` by `maxQueryTimeBytes`-style short bound of 1 KiB. Tenant IDs are validated as decimal unsigned 32-bit integers.

Alternative rejected: a shared `logs` schema across sources (flattening Loki's streams would be interpretation); `--max-rows` doubling as the source's limit (changes execution).

### 2. Provider

`provider.ExecuteRequest` gains `LogsQL, FieldValues, StreamFieldValues, Filter string`, `FieldNames, Streams, StreamFieldNames bool`, `Limit *int64`. PostgreSQL and VictoriaMetrics refuse every log input with `ErrUnsupportedInput`. New `internal/provider/victorialogs.go` shares the URL parsing, auth methods, client construction and header application with VictoriaMetrics (extracted into shared helpers rather than copied), adds `accountId` and `projectId` to `ParseTarget` (refusing a custom auth header named like either), and implements `Probe` (GET `/health` with auth and tenant headers) and `Execute`.

`Execute` chooses the endpoint from the input, builds a GET with query parameters (`query`, `start`, `end`, `limit`, `field`, `filter`, `timeout` = the connection's timeout in seconds) and sends one request with auth and tenant headers, client timeout = timeout + `MetricsGrace`, no redirects, no keep-alive. For `/select/logsql/query` it reads the body line by line through a bounded line reader: each line must be one complete JSON object (the final line may lack its newline), decoded into an ordered structure and re-encoded compactly, never `map[string]any`; rows are kept in arrival order while the row cap is not reached and the kept bytes (UTF-8 length of every field name and value) are within the byte cap, the first row always kept; the current line is read under the body ceiling and a line beyond it is `response_too_large`. When the row cap is reached, or the byte cap after the first row, the reader stops, the response body is closed (which closes the connection since keep-alive is off) and the result is marked truncated (a success carries no hint; the guidance to pass a limit and a sort pipe lives in the README, the `response_too_large` hint and the skill); end of stream before a cap means not truncated. A non-JSON line, or a line that is not an object, before the cap fails the request as `malformed_response` with the bounded offending text and no rows. An empty 200 body is an empty `logs` array. For the discovery endpoints the answer is one JSON object read under the ceiling and drained to the end, `values` items kept in order under the row cap and byte cap (value text plus the `hits` digits), each item re-encoded with `value` and `hits` exact (`UseNumber`), later items dropped whole, truncated marked; a missing `values` or a non-object body is `malformed_response`.

Error mapping: 401/403 → `ErrAuthRejected`; dial/TLS/redirect → `ErrUnreachable`; any other non-200 → `*SourceError{ErrorType: "http_<status>", Message: bounded body text}`; client deadline → `ErrTimeout`. No text search for the word timeout.

### 3. Service and route

`validateQueryInput` learns the eleven-input exclusivity and the limit, filter and match rules with hints; `providerInput` maps `victorialogs` to the log inputs with a hint naming them; `queryFailure` unchanged (the two platform-written types already carry hints; the ceiling hint gains "pass a limit" and the malformed hint no longer names the Prometheus envelope). Migration 006 replaces the provider check constraint, found necessary in slice 2. The route decodes the new fields with the strict decoder; `limit` must be a JSON integer. `ExecuteQuery` passes `Limit` through untouched.

### 4. CLI

New flags `--logsql`, `--logsql-stdin`, `--logsql-file`, `--field-names`, `--field-values`, `--streams`, `--stream-field-names`, `--stream-field-values`, `--limit` (non-negative integer), `--filter`; `--match` keeps its name and now takes a query for log discovery. Local validation of exclusivity, applicability (`--limit`/`--filter`/`--match` rules, no `--at`/`--step` with a log input, `--match` required for log discovery) with one hint. `connections create|update` gain `--account-id` and `--project-id` mapped to the target keys. Response validation branches on `provider`: VictoriaLogs requires `resultType` in the six-name set, `result` an array of objects (`logs`, any fields, values of any JSON type as the source wrote them) or an array of `{value: string, hits: number}` objects; anything else `INVALID_RESPONSE`; `statement` and `sqlstate` on a log failure refused. Text rendering per the spec with `%q` quoting; `ERROR: <errorType> <message>` for failures as for metrics.

### 5. Compose and smoke

`compose.yaml` gains `victorialogs` (`victoriametrics/victoria-logs` pinned by tag and digest, port `127.0.0.1:${CLAVIS_VL_PORT:-9428}:9428`, `-search.maxQueryDuration=5s`, `-retentionPeriod=1d`; the image ships no shell or wget, so there is no container health check and smoke waits on `/health` over HTTP from the host). Smoke ingests rows through `/insert/jsonline` with `_stream_fields` declared, the `application/stream+json` content type (a form content type is silently ignored by the source) and RFC 3339 timestamps anchored inside retention at each run, polls until a query sees them, then: an ordered query with `--limit` and a sort pipe (exact order asserted), a query without limit hitting `--max-rows` (truncated, hint present, exit 0), a `| stats` aggregate (rows without `_msg`), each of the five discovery endpoints with `--match '*'`, `--filter`, a bad query (`http_400`), tenant headers observed by a recording stub together with the stored auth, `--limit` on `--field-names` refused locally, `--sql` on the log connection and `--logsql` on the others refused, member refusal then grant, text output with a two-line message, and the stalling stub as the timeout backstop.

### 6. Slices

Three: contracts and the provider with fake-server tests for every shape, cap and failure (including exact-cap versus cutoff, an oversized row, an error line after rows, connection closure after cutoff, 503 versus the local deadline, the tenant and auth headers together); service, route and CLI with fakes plus the real-database round trip against a fake source; compose, smoke, docs and the whole-change review.

## Risks / Trade-offs

- [Stopping at the cap hides an error the source writes later] → the rows returned are complete and the answer never claims completeness; documented in README and the spec.
- [A caller's `limit` makes the source sort, which is slower on a wide range] → that is the source's documented behaviour and the caller's choice; nothing is added by the platform.
- [Discovery under `limit` can return an arbitrary subset with zero hits] → passed through; the README says hit counts under a limit are not observed absence.
- [A single row larger than what the CLI reads] → `INVALID_RESPONSE` at the CLI, as documented for metrics.
- [Tenant headers on a source without multitenancy] → ignored by a single-node source; optional settings, omitted by default.

## Migration Plan

1. Deploy; migration `006_victorialogs_provider.sql` replaces the provider check constraint on `connections` so the third provider can be stored (found in slice 2: migration 003 pins the two names; the constraint is replaced rather than widened because a check has no ALTER of its own). Target settings are provider-parsed JSON and need no change.
2. Rollback as before (forward-only migrations; a rolled-back binary refuses to store the third provider and reads existing rows unchanged).

## Open Questions

None.
