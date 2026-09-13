Three slices in dependency order; implementation and independent acceptance review are separate tasks, and a reviewer never approves their own implementation. Slice 1 lands first; slices 2 and 3 depend on it. Expect roughly 900 to 1,200 changed handwritten lines; no generated output is expected.

## 1. Contracts and the VictoriaMetrics execute operation

Requirements: query-execution "Pass-through execution request" (endpoints, auth, no parsing), "Structured results" (native shape), "Bounds and explicit truncation" (sample cap, ceiling, timeout), "Distinguishable failures" (`errorType` mapping); connection-management "Provider registry". Owned paths: `internal/auth/query.go`, `internal/auth/query_test.go`, `internal/auth/errors.go` (if `Source` rendering changes), `internal/provider/provider.go`, `internal/provider/victoriametrics.go`, `internal/provider/victoriametrics_test.go`, `internal/provider/postgres.go` (refuse non-SQL input), `internal/provider/provider_test.go`. Verify: `go test -race ./internal/auth/ ./internal/provider/` (fake HTTP servers; no real source).

- [ ] 1.1 Extend the contracts (request inputs, response discriminator and metrics fields, `errorType`, optional `statement`, label-name validation, the body ceiling and grace) with JSON tests proving the PostgreSQL shape still renders as before plus `provider`.
- [ ] 1.2 Implement the VictoriaMetrics executor: endpoint selection, form and query encoding with `timeout` and `limit`, the probe's auth and client construction, the bounded streaming decoder with the sample and byte caps and per-series marks, the ceiling and malformed-body failures, the error mapping; PostgreSQL refuses non-SQL inputs. Fake-server tests: each endpoint receives exactly the submitted strings; vector, matrix, scalar, string and the three discovery shapes pass through unchanged; warnings, infos and `isPartial` surfaced; truncation across series with marks and the envelope read to the end; byte cap; ceiling; malformed JSON; `status: error` envelopes with `bad_data` and `timeout`; non-JSON 500; 401 and 403; redirect refused; connection refused; client deadline; the secret never in any error; the four auth methods on the wire.
- [ ] 1.3 Independent acceptance review of slice 1; record the revision.

## 2. Service, route and CLI

Requirements: query-execution "Pass-through execution request" (provider mismatch before the secret), "Query route and command"; cli-authentication "Query command". Depends on slice 1. Owned paths: `internal/database/query.go`, `internal/database/query_test.go`, `internal/server/query.go`, `internal/server/query_test.go`, `internal/cli/query_commands.go`, `internal/cli/query_test.go`, `internal/cli/auth_transport.go`, `internal/cli/result.go`, `internal/cli/*_test.go`. Verify: `go test -race ./internal/server/ ./internal/cli/ && make build-cli`, and `CLAVIS_BACKEND_TEST_DATABASE_URL=... go test -race -p 1 ./internal/database/ ./internal/server/` (the metrics source is a fake HTTP server in the real-database tests).

- [ ] 2.1 Service: input exclusivity and flag rules with hints, provider-input match after authorization and before the secret, sample-cap mapping; route decoding of the new fields; real-database tests with a fake metrics source for a granted member, refusals, mismatch, truncation and the timeout.
- [ ] 2.2 CLI: the new flags and local validation, the expression inputs on the SQL plumbing, response validation by `provider`, text rendering for every result type and discovery, `error.source` with `errorType`; unit and subprocess tests for every spec scenario.
- [ ] 2.3 Independent acceptance review of slice 2; record the revision.

## 3. Compose, smoke, documentation and whole-change verification

Requirements: all three delta specs end to end; project-bootstrap quality and smoke requirements. Depends on slices 1 and 2. Owned paths: `compose.yaml`, `scripts/smoke.mjs`, `scripts/dev.mjs` if the container needs wiring, `README.md`, `docs/PRD.md` (section 12 status and the positioning line), `reports/` (ignored). Verify: `make check && make smoke && make test-mutation-full`.

- [ ] 3.1 Add the pinned single-node VictoriaMetrics service to compose with a short maximum query duration and a health check; extend smoke with the metrics section from the design.
- [ ] 3.2 Update README (metrics queries, discovery flags, time formats, bounds, `isPartial`) and PRD section 12, adding the positioning line agreed on 2026-09-13 (Grafana's access model with the human's identity behind the agent).
- [ ] 3.3 Run clean-checkout `make setup`, `make check`, the real-database race suite, `make smoke` and `make test-mutation-full`; report handwritten and generated line counts separately; confirm no tracked source is rewritten by successful checks.
- [ ] 3.4 Whole-change independent review against the inherited requirements, all three delta specs and the design's inherited-decisions table, with the pass-through, bounds and failure paths end to end; record the final revision, limits and any exceptions for owner acceptance before archive.
