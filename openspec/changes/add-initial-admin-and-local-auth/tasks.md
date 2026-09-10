## 1. Establish the shared contract and parallel base — coordinator

- [x] 1.1 Encode the design's installation states, safe identity/session DTOs, browser success/failure status and cookie outcomes, error mappings and frozen service/view signatures in contract fixtures; verify JSON/HTML adapters share transport-neutral domain types without importing web code into the CLI.
- [x] 1.2 Add injectable CLI input/prompt and isolated server/view test seams while preserving existing entry-point behavior; verify current checks pass and no fixture or unauthenticated management endpoint is exposed in the production binary.
- [x] 1.3 Pin compatible password-hashing and terminal-input dependencies, land the common-base change, and assign exclusive backend/web/CLI files plus isolated ports/database names/homes/reports; verify each lane can compile and run its focused fixtures before dispatch.

Sections 2–3 are the backend lane. Sections 4 and 5 can run in parallel with that lane after section 1, using the frozen contracts rather than waiting for live endpoints. The coordinator alone updates this checklist and shared dependency/tooling files. Section 6 requires the integrated lanes.

The persistence correction splits into Goose migration ownership (2.1), sqlc application-query conversion (2.7), and generation/build enforcement (2.8). These can run independently against agreed schema and migration-helper boundaries; the coordinator integrates and verifies all three before accepting the backend.

## 2. Implement unattended platform initialization — backend

- [x] 2.1 Integrate pinned Goose v3 with embedded SQL, one Goose version/checksum ledger and provider locking that serializes with bootstrap; replace the custom runner and verify concurrent processes, transactional rollback, unsupported/changed/legacy schema rejection and cancellation-safe lock release without external migration tools.
- [x] 2.2 Implement shared username/password rules and versioned Argon2id verification with bounded parsing/work; verify valid/invalid/disabled/unknown cases, dummy verification, encoding boundaries and the proposed KDF costs using focused tests and a local benchmark.
- [x] 2.3 Add lazy bootstrap input handling and bounded regular-secret-file reading, including projected symlinks, permissions, newline/UTF-8/size validation and no secret-path logging; verify an initialized installation does not open or validate obsolete bootstrap inputs, and FIFO/directory/oversized inputs cannot hang.
- [x] 2.4 Implement locked atomic administrator/event/marker creation; verify competing credentials produce exactly one account, interrupted transactions retry safely, unexpected users without a marker fail, and changed settings or removed/disabled admins never reopen bootstrap.
- [x] 2.5 Wire the bounded initialization worker into server startup/shutdown; verify HTTP liveness/public documents start during DB outages, mounted-secret/database recovery can finish setup without process restart, and cancellation/lock waiting respects the shutdown budget.
- [x] 2.6 Replace ping-only readiness with the shared bounded installation check and new safe JSON categories; verify fresh DB checks dominate stale worker state, GETs cause no initialization writes, existing success/database-outage bodies remain stable, and unready authentication fails closed.
- [x] 2.7 Define named application SQL and sqlc configuration targeting pgx v5 using Goose migrations as schema input; generate checked-in methods and replace handwritten authentication, bootstrap, readiness, audit and throttle queries/scanning while preserving transaction boundaries; verify generated-query real-PostgreSQL tests and no parallel application SQL path.
- [x] 2.8 Pin sqlc and add explicit generation, non-mutating whole-output consistency checks and a narrow Go-AST persistence boundary guard; verify stale/missing/extra output, wrong tools and direct application-query paths fail, server/build/mutation inputs include required SQL, generated sqlc code is excluded from mutation, and CLI-only builds stay Go-only.

## 3. Implement local authentication and protected adapters — backend

- [x] 3.1 Add opaque browser/CLI session issuance, digest-only persistence, fixed expiry and current-user authorization; verify transport kinds cannot be interchanged and expiry/revocation/disabled users/role removal affect subsequent requests.
- [x] 3.2 Add safe authentication event writes and transaction integration; verify bootstrap/session mutations cannot succeed without their events, denied/failed attempts are recorded when storage works, and raw secrets/paths/request data never enter events or logs.
- [x] 3.3 Add shared expiring login-failure limits, bounded verification concurrency and bounded counter cleanup; verify cross-replica limits, generic 429/retry responses, no permanent lockout, bounded state and rejection of spoofed forwarded-address assumptions.
- [x] 3.4 Mount strict JSON login/whoami/logout endpoints with the frozen DTO/error/body-size/content-type and five-second operation contracts; verify worst-case escaped valid passwords, no cookie authentication/HTML redirects/raw-response reflection, cross-origin or ambiguous-credential rejection, and held-lock timeout/rollback/recovery.
- [x] 3.5 Implement configured public-origin/TLS policy, browser session cookies, login/logout form adapters and admin authorization using the web view interface; verify strict Origin/Fetch Metadata CSRF rejection, framing protection, cookie rotation/clearing, every frozen browser failure outcome, and public documents bypassing DB access even with malformed/stale cookies.
- [x] 3.6 Implement administrator all-user session revocation and issuance/revocation serialization; verify browser and CLI sessions committed before revocation fail afterward, later logins remain distinct, non-admins cannot revoke, and self-targeted revocation is handled safely.

## 4. Build setup and authentication views — web, parallel after section 1

- [x] 4.1 Extend readiness view models/templates with initializing/setup-required/bootstrap-failed/schema-error states and deployment guidance; verify the existing five-second deadline, cancellation, fragment gates and no-polling behavior remain intact and no account-creation form is introduced.
- [x] 4.2 Add buffered public login and minimal protected admin templates with ordinary form POST/redirect controls and safe errors; verify escaped identity text, password non-reflection, usable labels/keyboard flow, appearance continuity and no placeholder management screens.
- [x] 4.3 Add dedicated fixture-backed browser tests for sign-in/out views, admin/member/unavailable states, focus and desktop/mobile layout; verify fixtures follow the frozen origin/cookie/response contracts and remain separate from the real backend evidence.
- [x] 4.4 Regenerate and commit matching templ Go alongside maintained templates; run generation checks and the existing readiness/browser suite, verifying checks do not rewrite tracked sources or weaken sentinel-secret tests.

## 5. Build authenticated CLI commands — CLI, parallel after section 1

- [x] 5.1 Add login/logout/whoami/session-revoke command registration and hidden-terminal/explicit-stdin input using injected I/O; verify bounded password parsing, no noninteractive hangs, all argument/output/timeout validations and one safe stdout result.
- [x] 5.2 Implement root-origin canonicalization and strict authentication HTTP transport; verify HTTPS/literal-loopback policy, no redirects or mutation retries, 64 KiB response limits, full body deadlines, safe response validation and no cross-origin credential reuse.
- [x] 5.3 Add private per-origin session cache and bounded interprocess locking; verify ownership/modes, symlink/nonregular/corrupt-state rejection, atomic writes, concurrent processes, failure preserving an existing token and bounded best-effort cleanup after failed persistence.
- [x] 5.4 Implement authoritative whoami, online/offline logout and administrator revocation results; verify expired/revoked credentials, idempotent absent-session logout, removal despite network failure without false remote-revocation claims and no token in JSON/text/errors.
- [x] 5.5 Extend doctor's allowlisted initialization errors without changing its data fields or existing URL/base-path rules; verify setup/schema failure is not mislabeled as database failure and legacy success/outage/timeout/invalid-response cases still pass.
- [x] 5.6 Add subprocess-level CLI authentication tests using isolated homes and test servers, plus existing unit regressions; verify prompt/stdout separation, exit 0/1/2, text formatting, cancellation, offline help/version and Go-only CLI builds.

## 6. Integrate, document and verify the complete flow — coordinator and reviewer

- [x] 6.1 Integrate the backend/web/CLI lanes and replace fixture-only assumptions with real contracts; run all contract tests and review shared route/config/dependency wiring, ensuring no production fixture or partial auth implementation is shipped.
- [x] 6.2 Extend isolated real-PostgreSQL smoke setup with generated, uncommitted bootstrap secrets and private CLI homes; verify copied-binary migrations/bootstrap, browser and CLI login/whoami/logout, multi-client admin revocation and non-admin denial on the same origin.
- [x] 6.3 Exercise real concurrent startups, transaction interruption, invalid/missing/repaired bootstrap inputs, initialized restart without any bootstrap file, and restart with changed credentials; verify exactly-once initialization and no implicit password/role reset.
- [x] 6.4 Preserve real database/server outage-recovery smoke, test expiry and credential redaction, and cover HTTPS proxy/browser Origin/cookie behavior as well as loopback development; verify bounded shutdown and both normal/injected-failure cleanup remove only owned resources, including secret/cache files.
- [x] 6.5 Update the concise README, environment placeholders and current PRD implementation-status sentence for unattended initialization, secret mounts, readiness categories, login commands and explicit recovery/rotation limitations; verify development/runtime prerequisites remain distinct and no real credentials, deployment-specific manifests or historical-spec rewrites are included.
- [x] 6.6 Run clean-checkout setup, templ/sqlc generated-source checks, persistence-boundary/static/Go/browser/build checks, full real-database smoke and focused handwritten mutation reporting; complete independent security review of Goose/bootstrap races, generated-query transaction boundaries, CSRF, session revocation and credential storage, keep execution evidence only in ignored reports, and verify no tracked source is rewritten by successful checks.

## 7. Apply review corrections and remove confirmed redundancy

- [x] 7.1 Classify transient bootstrap ledger-read failures through the existing schema/dependency distinction instead of stopping initialization; reproduce the exact failure window and verify recovery without process restart while genuine incompatible schemas remain terminal.
- [x] 7.2 Record safe audit events for failed bootstrap validation attempts when storage is available, preserving successful bootstrap atomicity, anonymous attribution, retry bounds and secret redaction; verify audit-write failure and repeated real attempts without inventing aggregation or retention policy.
- [x] 7.3 Omit unused sqlc table structs through the pinned generator's supported configuration, retain every used generated method/type and required generated file, and remove stale module checksums; verify isolated generation, complete-output checks, builds and tests without changing dependency versions.
- [x] 7.4 Remove confirmed obsolete maintained scaffolding and duplicate server/readiness composition, preserving the production/test boundary and service-owned fail-closed behavior; verify references, nil-service handling, unready responses and shutdown.
- [x] 7.5 Consolidate server/CLI origin rules without changing doctor URL behavior or ephemeral listener binding; reject invalid configured public origins, preserve safe error wrappers, and run both configuration and CLI regression tables.
- [x] 7.6 Remove other confirmed dead helpers/imports/icons and avoid repeatedly computing immutable migration metadata; regenerate any affected templates and preserve immutable ownership, attribution, checked-in generation and all meaningful tests.
- [x] 7.7 Independently review the fixes and rerun generated-source/boundary checks, Go/race/browser and real PostgreSQL smoke coverage, including bootstrap failure recovery/auditing and cleanup; record limitations honestly and leave unrelated policy choices unchanged.
