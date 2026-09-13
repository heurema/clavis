## Context

`add-postgres-query` shipped the query surface: `POST /api/query`, `clavis query`, `ExecuteQuery` on the store, the optional `provider.Executor` capability, the row and byte caps, the failure codes and the deadline layering. VictoriaMetrics connections carry a base URL and an auth method (`none`, `basic`, `bearer`, `header`) and are probed on `/health`; queries against them answer `PROVIDER_UNSUPPORTED`. The product rule is proxy: forward, bound, refuse, never interpret. VictoriaMetrics implements the Prometheus HTTP API (`/api/v1/query`, `/api/v1/query_range`, `/api/v1/labels`, `/api/v1/label/<name>/values`, `/api/v1/series`) with its own timestamp formats, MetricsQL extensions, `timeout` capped at `-search.maxQueryDuration`, `-search.maxPointsPerTimeseries` refusals, and cluster bases like `/select/0/prometheus`; cluster answers may carry `isPartial`. The design was reviewed by a second model (Codex) on 2026-09-13; its accepted points are folded in below.

## Goals / Non-Goals

**Goals:** PromQL and discovery through the existing verb; the source's answer returned as is; the connection's bounds enforced without cancelling the source's work except at a documented backstop; every failure the source's own.

**Non-Goals:** write or admin endpoints, alerting, mixed-source queries, `deny_partial_response` handling, a metrics catalog of our own, mutual TLS or OAuth2.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| One `query` verb, agent-first flags, hints, envelope, exit codes | query-execution, cli-authentication | Retained; new inputs on the same verb |
| Pass-through: nothing parsed, filtered or rewritten | PRD 5 and 6, query-execution | Retained; time strings, steps and selectors forwarded as typed |
| Discovery is a query the skill documents, no `describe` | PRD 12 (2026-09-12) | Explicitly changed for metrics (owner 2026-09-13): PromQL has no cheap catalog query, so the source's metadata endpoints are forwarded as three inputs |
| Optional `provider.Executor` capability | archived add-postgres-query design | Retained; VictoriaMetrics now implements it |
| Deadline layering: body under 5 s, route under `QueryRequestBudget`, service backstop ten times the timeout plus five seconds, dial capped | archived add-postgres-query | Retained for the route and service; the provider's own HTTP deadline is the timeout plus five seconds |
| `connections check` probes `/health` | connection-management | Retained (owner 2026-09-13) |
| Stored auth applied per request, redirects refused, no keep-alive | connection-management probe | Retained; the same client construction |
| No audit journal | PRD 7.7 | Retained |

No unresolved departure.

## Decisions

### 1. Contracts

`auth.QueryRequest` gains `PromQL`, `At`, `Start`, `End`, `Step`, `Labels bool`, `LabelValues`, `Series`, `Match` (JSON `promql`, `at`, `start`, `end`, `step`, `labels`, `labelValues`, `series`, `match`, all `omitempty`). Exactly one of `SQL`, `PromQL`, `Labels`, `LabelValues`, `Series` is set; `At` only with `PromQL` and without `Start`; `Step` requires `Start`; `Match`, `Start`, `End` only with PromQL or discovery. `auth.QueryResponse` gains `Provider ProviderType` (`provider`) and the metrics fields `ResultType string` (`resultType`), `Result json.RawMessage` (`result`), `Warnings, Infos []string`, `IsPartial bool` (`isPartial`), all `omitempty`; `Results` becomes `omitempty` and is set only for PostgreSQL. `auth.SourceFailure` gains `ErrorType string` (`errorType,omitempty`) and `Statement` becomes `*int` (`statement,omitempty`; PostgreSQL always sets it, so zero still renders). New bounds: `MetricsBodyCeiling(maxBytes) = 4*maxBytes + 1 MiB`, `MetricsGrace = 5 s`. `ValidLabelName` = `[a-zA-Z_][a-zA-Z0-9_]*`, at most 256 bytes.

### 2. Provider

`provider.ExecuteRequest` gains `PromQL, At, Start, End, Step, LabelValues, Series, Match string` and `Labels bool`; the PostgreSQL executor refuses any non-SQL input with `ErrUnsupportedInput` (new sentinel, mapped to `INVALID_ARGUMENT` by the service, though the service refuses first). `provider.ExecuteResult` gains `ResultType string`, `Result json.RawMessage`, `Warnings, Infos []string`, `IsPartial bool`.

VictoriaMetrics `Execute`: choose the endpoint from the input (`query` when `PromQL` without `Start`, `query_range` with `Start`, `labels`, `label/<name>/values`, `series`); build a form-encoded POST for the two query endpoints and a GET with query parameters for the metadata endpoints (`match[]` for `series` and `match`, `start`, `end`, and `limit` = sample cap plus one where the source honours it); add `timeout` = the connection's timeout in seconds to every request; apply the stored auth exactly as the probe; client timeout = timeout + `MetricsGrace`, no redirects, no keep-alive; read the body through `io.LimitReader(ceiling+1)`; decode as a stream with `json.Decoder` tokens: `status`, `errorType`, `error`, `warnings`, `infos`, `isPartial`, and `data` (`resultType` and `result`). Keep samples in order under the sample cap and byte cap: vector entries are one sample each, matrix `values` one per pair, discovery items one each; once the sample cap is hit, remaining series keep the samples read so far and are marked with an added `"truncated": true` member and later series are emitted with empty `values` and the mark; once the byte cap is hit, later series are dropped whole, labels included, so kept bytes stay within the cap plus one series, and the decoder continues to the end of the document so `status`/`error` fields that follow `data` are honoured. Kept objects are re-encoded compactly; the source's field order inside a series is preserved by decoding into an ordered structure (label map plus samples), never `map[string]any`. A body over the ceiling → `*SourceError{ErrorType: "response_too_large"}`; a body that fails to parse → `"malformed_response"`.

Error mapping: HTTP 401/403 → `ErrAuthRejected`; dial/TLS/connection failures → `ErrUnreachable`; a JSON envelope with `status: "error"` → `*SourceError` with its `errorType` and `error` (an `errorType` of `timeout` → `ErrTimeout`); a non-JSON error status → `*SourceError{ErrorType: "http_<status>", Message: bounded body text}`; client deadline → `ErrTimeout`. HTTP 200 with `status: "success"` is the only success.

### 3. Service and route

`ExecuteQuery` validates input exclusivity and the flag rules locally with hints (`INVALID_ARGUMENT`), then, after `AuthorizeConnection`, checks the input against the provider type (`SQL` for `postgresql`, the rest for `victoriametrics`) and refuses a mismatch with a hint naming the right input before opening the secret; `MaxRows` semantics unchanged (sample cap for metrics). The route decodes the new fields with the same strict decoder and the same body bound; `labelValues` is validated with `ValidLabelName`. `Application` is unused by the metrics provider.

### 4. CLI

New flags `--promql`, `--promql-stdin`, `--promql-file`, `--labels`, `--label-values`, `--series`, `--at`, `--start`, `--end`, `--step`, `--match`; local validation of exclusivity and flag applicability with one hint listing the inputs; the expression inputs reuse the SQL input plumbing and bound. Response validation branches on `provider`: PostgreSQL as today; VictoriaMetrics requires `resultType` in the known set, `result` a JSON value whose shape matches the type (array of series objects with `metric` and `value` or `values`, scalar or string pairs, string lists for `labels`/`labelValues`, object lists for `series`), `warnings`/`infos` string lists, `isPartial` bool; anything else `INVALID_RESPONSE`. Text rendering per decision in the spec. `error.source` accepts `errorType` and an absent `statement`.

### 5. Compose and smoke

`compose.yaml` gains `victoriametrics` (`victoriametrics/victoria-metrics` pinned by tag and digest, port `127.0.0.1:${CLAVIS_VM_PORT:-8428}:8428`, `-search.maxQueryDuration=5s` so the timeout case is provable, a health check on `/health`). Smoke registers `smoke-vm` against it with auth `none`, imports samples through `/api/v1/import/prometheus` with fixed timestamps, then: instant vector, range matrix with `--start`/`--end`/`--step`, an instant range selector returning a matrix, `--label-values __name__`, `--labels --match`, `--series`, a bad expression (`bad_data`), truncation at `--max-rows`, the timeout (an expression that sleeps is not available in PromQL, so the timeout is proven with a 1 s connection timeout against a query the container answers slowly enough or, failing that, against a stub that stalls), `--sql` on the metrics connection and `--promql` on the postgres one, member refusals, and text output. The existing auth stub keeps proving the four auth methods for the check.

### 6. Slices

Three: contracts and the provider with fake-server tests for every shape and failure; service, route and CLI with fakes plus the real-database round trip against a fake source; compose, smoke, docs and the whole-change review.

## Risks / Trade-offs

- [The source's field order in `result` cannot be preserved byte for byte] → decoded into ordered structures and re-encoded; the values are unchanged, the spec promises content not bytes.
- [`limit` support differs across VictoriaMetrics versions] → the platform's own cap is authoritative; `limit` is an optimisation.
- [A cluster answering partial data] → `isPartial` is surfaced; agents decide.
- [Points-per-series refusals] → passed through with the source's message; no automatic step change.
- [Body ceiling reached] → failure rather than data, with a hint.

## Migration Plan

1. Deploy; no migration. The PostgreSQL response gains `provider`; older CLIs refuse it (not in production).
2. Rollback as before.

## Open Questions

None.
