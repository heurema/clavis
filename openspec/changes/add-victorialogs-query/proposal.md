## Why

The pilot team needs logs next to metrics and tables: an agent investigating a problem reads the database, the metrics and the logs of the same service. VictoriaLogs is the team's log store, and today Clavis cannot register it at all. Log and trace sources are a later stage in the PRD (section 9), so this is an explicit owner decision of 2026-09-14 to pull one log source into the MVP ahead of groups and the agent skill, because every provider added makes the skill more worth writing and the query surface has just been proven provider-neutral by the VictoriaMetrics change.

## What Changes

- Add a third provider, `victorialogs`, with the same non-secret target (`url`, `auth` with `none`, `basic`, `bearer` or `header`) plus optional tenant settings `accountId` and `projectId`, sent as the `AccountID` and `ProjectID` request headers beside the stored authentication; a custom auth header named like either is refused. The connectivity check sends one GET to `/health` as for VictoriaMetrics.
- Add pass-through LogsQL execution through the existing `query` command and route: `--logsql <query>` (or `--logsql-stdin`, `--logsql-file`) forwarded unchanged to the source's `/select/logsql/query` with `--start`, `--end` and an optional `--limit` forwarded as the source's own `limit`. Nothing is parsed, sorted or defaulted: ordering, aggregation and time formats are the query's job, and the platform never synthesizes a limit.
- Add discovery by forwarding five read-only metadata endpoints on the same command: `--field-names`, `--field-values <name>`, `--streams`, `--stream-field-names` and `--stream-field-values <name>`, each requiring `--match <query>` as the source's query, with `--start`, `--end`, and `--limit` and `--filter <substring>` forwarded only to the endpoints that take them. The answers keep the source's `value` and `hits` pairs. No other path on the source is reachable.
- Return the source's rows as they are: `provider: "victorialogs"`, `resultType` `logs` with `result` an array of the source's row objects in arrival order (the only reframing is from JSON lines to one array), or one of the five discovery types with the source's `values` array. Rows are query results, not log lines: an aggregate row has no `_time` or `_msg`, and the platform renders whatever fields exist.
- Bound the log stream the log-client way, an explicit departure from the drain rule of the other providers: when the row cap or the byte cap is reached without a source limit, the platform stops reading, closes the connection and returns the complete rows kept with `truncated: true` and a hint to pass `--limit` and a sort pipe; the truncation means "source completion unverified, more rows may exist", also when the count lands exactly on the cap. The body ceiling bounds one entry, the first entry is always kept up to it, and a discovery envelope is drained and validated as before.
- Keep failures the source's own: a plain-text error line in the stream fails the whole request as `SOURCE_ERROR` with `errorType` `malformed_response` and the bounded text, never data; every non-200 answer is `http_<status>` with bounded text, including the source's 400 for a bad query and its 503 for its own timeout; 401 and 403 are `SOURCE_AUTH_REJECTED`; only the platform's expired deadline (the forwarded `timeout` plus the grace) is `SOURCE_TIMEOUT`. `--sql` or `--promql` on a VictoriaLogs connection, or `--logsql` elsewhere, is `INVALID_ARGUMENT` with a hint naming the right input.
- Text output renders one physical line per row (`_time`, `_msg`, remaining fields as sorted `key=value`, `_stream` and `_stream_id` last, quoting where needed) and `value<TAB>hits` per discovery item.
- Add a pinned single-node VictoriaLogs container to the compose file; smoke ingests rows and exercises ordered queries with a limit, truncation without one, an aggregate, every discovery endpoint, filter, a bad query, tenant headers, refusals, text output and the timeout backstop; README documents ordering, limits and truncation so correct use does not wait for the skill; PRD sections 7.4, 9 and 12 record the scope decision.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `query-execution`: every requirement gains the VictoriaLogs half (the LogsQL and discovery inputs with `limit` and `filter`, the `logs` and discovery result shapes, the stop-at-cap rule for the unbounded stream with its truncation meaning, the stream failure mapping).
- `connection-management`: "Provider registry" adds `victorialogs` with its tenant settings and names three providers in the hint; "Explicit connectivity check" gains the third probe.
- `cli-authentication`: "Connection management commands" gains `--account-id` and `--project-id`; "Query command" gains the LogsQL and discovery inputs, `--limit`, `--filter`, the mismatch refusal and the row rendering.

## Impact

- Backend: `internal/auth/query.go` (request fields, `limit` as an optional integer, result types), `internal/auth/connections.go` (provider type), `internal/provider` (`ExecuteRequest` gains the inputs; a new `victorialogs.go` implements `Provider` and `Executor` with a bounded JSON-lines reader that stops at the cap; PostgreSQL and VictoriaMetrics refuse the new inputs), `internal/database/query.go` (input rules and the provider match), `internal/server/query.go` (decoding), `internal/cli` (flags, validation, the third result shape, rendering, connection flags).
- Tooling/docs: `compose.yaml`, `scripts/smoke.mjs`, `README.md`, `docs/PRD.md`.
- Dependencies: none new; the VictoriaLogs container is a compose service for local verification only.

## Owner decisions (2026-09-14, settled with a second-model critique in two rounds)

- Native shape per provider (`logs` rows as the source wrote them); no shared log schema across future log sources, because flattening another source's shape would be interpretation.
- `--limit` forwards the source's limit as typed and `--max-rows` stays the platform's retention cap; the platform never adds a limit, not even cap plus one, because a source limit changes what the source executes. This departs from the metrics discovery path, which sends cap plus one.
- Stop reading at the cap on the unbounded log stream instead of draining to the end: a log read has no side effects to protect and JSON lines have no envelope to validate; the source documents client cutoff.
- The source's own 503 timeout stays `SOURCE_ERROR http_503`; only the platform's deadline is `SOURCE_TIMEOUT`, as settled for metrics.
- `hits`, `stats_query`, `stats_query_range`, `facets`, `stream_ids` and `tail` deferred: counts per bucket are available through a LogsQL stats pipe, and `hits` needs its own truncation contract.
- Tenants are connection settings, not caller inputs; one secret header cannot carry two tenant identifiers and a credential.
- Roadmap: VictoriaLogs now, then the agent skill covering three providers, then groups.

## Non-goals

Loki (its `streams` shape would be its own provider later), ingestion or any write path, live tail, `hits` and stats endpoints, a log catalog of our own, parsing or reformatting `_msg`, timestamp normalisation, mutual TLS or OAuth2.
