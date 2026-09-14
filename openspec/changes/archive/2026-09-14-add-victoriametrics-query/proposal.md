## Why

Half of the MVP's sources cannot be queried: a VictoriaMetrics connection can be registered, checked and granted, but `query` refuses it with `PROVIDER_UNSUPPORTED`. The PRD's pilot needs instant and range PromQL queries plus a way for an agent to find metric names and labels (PRD 7.4 VictoriaMetrics, CONN-09, CLI-04, CLI-05, CLI-08). This is the second provider operation, so it also proves the query surface is provider-neutral.

## What Changes

- Add pass-through PromQL execution for VictoriaMetrics connections through the existing `query` command and route: `--promql <expr>` (or `--promql-stdin`, `--promql-file`) forwarded unchanged to the source's `/api/v1/query`, or to `/api/v1/query_range` when `--start` and `--step` are given (`--end` defaults to the source's now, `--at` pins an instant query). Time and step strings are passed through as submitted; the platform parses nothing.
- Add discovery by forwarding the source's read-only metadata endpoints on the same command: `--labels`, `--label-values <name>` and `--series <selector>`, each with an optional `--match <selector>` and the same time flags, parameters passed through unchanged and results bounded by the row cap. No other path on the source is reachable.
- Return the source's answer as it is: the response gains a `provider` discriminator; PostgreSQL keeps `results`; VictoriaMetrics answers `resultType` and `result` in the Prometheus format (values as strings), plus the source's `warnings`, `infos` and `isPartial`, with `truncated` and `durationMs` at the top level. **BREAKING** for last week's PostgreSQL response, which gains the `provider` field (allowed, not in production).
- Enforce the connection's bounds the proxy way: the timeout is forwarded as the API `timeout` parameter (the source aborts its own evaluation and caps the value at its configured maximum) and used as the HTTP deadline plus a short grace; the row cap becomes a sample cap, cut as a per-series prefix with per-series and top-level truncation flags; the byte cap counts kept label and value text; the body is read under a hard ceiling and the whole envelope must parse, otherwise the request fails rather than presenting truncated data.
- Keep failures the source's own: its `errorType` and message under `SOURCE_ERROR` (`error.source` gains `errorType`; `statement` becomes optional so PromQL failures do not carry it), HTTP 401 and 403 as `SOURCE_AUTH_REJECTED`, connection failures as `SOURCE_UNREACHABLE`, the source's timeout or ours as `SOURCE_TIMEOUT`. `--sql` on a VictoriaMetrics connection or `--promql` on a PostgreSQL one is `INVALID_ARGUMENT` with a hint naming the right input.
- Apply the stored auth method per request as the probe does, one request per execution, no keep-alive, redirects refused. `connections check` keeps probing `/health`.
- Add a single-node VictoriaMetrics container to the compose file for smoke and development; smoke imports samples and exercises instant, range, discovery, a bad expression, truncation, the timeout and refusals against the real source; README and PRD status updated.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `query-execution`: every requirement gains the VictoriaMetrics half (request inputs, native result shape with the provider discriminator, sample cap and body ceiling, `errorType` failures, the discovery inputs and flags).
- `connection-management`: "Provider registry" records that both providers execute; the "provider without execution" scenario becomes hypothetical.
- `cli-authentication`: "Query command" gains the PromQL and discovery inputs, the time flags, the provider-mismatch refusal and the native-result rendering.

## Impact

- Backend: `internal/auth/query.go` (request fields, response discriminator and metrics fields, `SourceFailure.ErrorType`, optional `Statement`), `internal/provider` (`ExecuteRequest` gains the PromQL and discovery inputs; VictoriaMetrics implements `Executor` with the bounded stream decoder; PostgreSQL refuses non-SQL inputs), `internal/database/query.go` (input validation by provider, cap mapping), `internal/server/query.go` (decoding the new fields), `internal/cli` (flags, validation, two result shapes, rendering).
- Tooling/docs: `compose.yaml`, `scripts/smoke.mjs`, `README.md`, `docs/PRD.md`.
- Dependencies: none new; the VictoriaMetrics container is a compose service for local verification only.

## Owner decisions (2026-09-13 interview, with a Codex critique)

- Same `query` verb; discovery through the source's metadata endpoints as three flags, because PromQL has no cheap catalog query.
- Native Prometheus result format rather than a normalised shape; `provider` discriminator on every response.
- Sample-prefix truncation per series rather than dropping whole series.
- Timeout forwarded to the source and used as the HTTP deadline plus a short grace; no script allowance.
- `connections check` stays on `/health`.
- Time strings pass through unparsed; the source's own clamping of a reversed range is documented, not corrected.

## Non-goals

Alerting, dashboards, mixed-source queries, write endpoints, admin endpoints, `deny_partial_response` handling beyond reporting `isPartial`, mutual TLS or OAuth2, a metrics catalog of our own.
