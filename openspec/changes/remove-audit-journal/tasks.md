Three slices in dependency order; implementation and independent acceptance review are separate tasks, and a reviewer never approves their own implementation. The change is a removal: expect roughly 400 to 600 handwritten lines removed and 100 to 200 changed, mostly tests and smoke; generated sqlc output reported separately.

## 1. Contracts, persistence and schema

Requirements: local-authentication (removed "Secret-free authentication events", modified "Explicit authentication transports"); platform-initialization ("sqlc-backed application persistence", "Atomic unattended administrator bootstrap"); user-administration, connection-management and connection-grants requirements as modified (behaviour unchanged, no events). Owned paths: `internal/auth/events.go` (delete), `internal/auth/*_test.go`, `internal/database/events.go` (delete), `internal/database/auth.go`, `admin.go`, `connections.go`, `grants.go`, `initialize.go`, `limits.go` if touched, `internal/database/migrations/005_drop_audit_events.sql`, `internal/database/queries/auth.sql` and `initialize.sql`, `internal/database/sqlc/`, `internal/database/*_test.go`. Verify: `make generate-db && make check-db-generated && make check-sql-boundaries && go test -race ./internal/auth/ && CLAVIS_BACKEND_TEST_DATABASE_URL=... go test -race -p 1 ./internal/database/`.

- [ ] 1.1 Delete the event contracts and the persistence file; add migration `005` dropping `auth_events`; remove the event query and readiness check; regenerate; simplify `administer`, the denial helpers, `recordRateLimited` and `bootstrapValidationFailure` so every mutation keeps its transaction shape, codes, hints, guards, locks and savepoint dry run without writing an event.
- [ ] 1.2 Update the database and auth tests: remove event assertions, fixtures and event-only tests; keep and, where an event assertion was the only proof of a behaviour (idempotent no-ops, dry runs leaving no rows, denials without mutation, bootstrap failures without a marker), replace it with a direct state assertion; verify fresh and initialized databases apply `005` once and readiness succeeds without the table.
- [ ] 1.3 Independent acceptance review of slice 1: confirm no non-event assertion was dropped, the transaction shape and lock order are unchanged, and no code path still references events; record the revision.

## 2. HTTP, CLI and wiring

Requirements: user-administration "JSON administration transport", connection-management "JSON connection routes", connection-grants "Grant routes and listing", cli-authentication "Connection management commands". Depends on slice 1. Owned paths: `internal/server/auth.go`, `server.go`, `*_test.go`, `cmd/server/main.go`, `internal/cli/*_test.go` if any test asserted events. Verify: `go test -race ./internal/server/ ./internal/cli/ && make build && CLAVIS_BACKEND_TEST_DATABASE_URL=... go test -race -p 1 ./internal/server/`.

- [ ] 2.1 Remove the adapter recorder, `rejectionAction` and the pre-service rejection recording; drop the `recorder` dependency from `HandlerWithAuth` and the server entry point; every rejection keeps its status and body.
- [ ] 2.2 Update server and CLI tests: remove event fixtures and assertions, keep every status, body, header and mutation assertion.
- [ ] 2.3 Independent acceptance review of slice 2; record the revision.

## 3. Smoke, documentation and whole-change verification

Requirements: project-bootstrap quality and smoke requirements; all delta specs end to end. Depends on slices 1 and 2. Owned paths: `scripts/smoke.mjs`, `README.md`, `docs/PRD.md` (section 12 status), `reports/` (ignored). Verify: `make check && make smoke && make test-mutation`.

- [ ] 3.1 Remove the event-count blocks and event-content checks from smoke; keep every behavioural assertion; confirm the `sql` helper is still needed or remove it.
- [ ] 3.2 Update README and PRD section 12; record accepted follow-ups.
- [ ] 3.3 Run clean-checkout `make setup`, `make check`, the real-database race suite, `make smoke` and `make test-mutation` (with the documented extended budget); report handwritten and generated line counts separately; confirm no tracked source is rewritten by successful checks.
- [ ] 3.4 Whole-change independent review against the six delta specs and the inherited transaction, guard and dry-run requirements; record the final revision and any exceptions for owner acceptance before archive.
