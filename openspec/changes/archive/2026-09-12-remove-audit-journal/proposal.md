## Why

The owner removed the audit journal from the MVP on 2026-09-12 (PRD 7.7, section 12): the platform will not record operations, administrative changes or denied attempts until a later stage. Three shipped changes built exactly that journal (the `auth_events` table, allowlists, the recorder boundary, denial events and the "mutation commits with its event" rule), so it has to be taken out now, before query execution builds on it, or every later change keeps paying for a feature the product no longer has.

## What Changes

- **BREAKING** Remove the audit journal: drop the `auth_events` table with a forward migration, delete the event contracts (`Event`, `EventAction`, `EventOutcome`, `EventRecorder`), the event queries, the audit and denial helpers, the adapter's rejection recorder and the readiness column check for events.
- Keep everything the journal was attached to: the transaction shape of mutations (deadline, readiness gate, advisory key, ordered row locks, session and role recheck, guards, savepoint dry run), every error code and hint, the rate limiter (`login_limits` is not an event), sessions, users, connections, grants and the authorization check. Denials keep their codes; they simply record nothing.
- Simplify `administer`: the body returns its result and the transaction commits; no success or denial event, so the "commit with event" and "audit write failure means unavailability" behaviours disappear.
- Bootstrap validation failures no longer write a failure event; they remain safe failures without a marker.
- Remove event counting from the smoke suite and event assertions from tests; keep every behavioural assertion.
- Update the specs: the `Secret-free authentication events` requirement is removed; every requirement that mentioned events, denial events, the adapter recorder or "records nothing" is rewritten without them.
- Update README and PRD status. The query change that follows is re-proposed without its audit requirement.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-authentication`: `Secret-free authentication events` removed; `Explicit authentication transports` no longer counts event writes in the deadline.
- `user-administration`: operations, blocking, role assignment, listing and transport no longer record events or denials.
- `connection-management`: registry, records, credentials, operations, check and routes no longer mention events; the check stores its outcome without an event; dry runs commit nothing and there is nothing else to record.
- `connection-grants`: grant records, member visibility, authorization and routes lose their event clauses; idempotency stays.
- `cli-authentication`: the dry-run scenario no longer claims "recorded nothing".
- `platform-initialization`: persistence no longer lists audit events; bootstrap commits the administrator and marker without a creation event and writes no failure event.

## Impact

- Backend: `internal/auth/events.go` deleted; `internal/database` (`events.go` deleted, `auth.go`, `admin.go`, `connections.go`, `grants.go`, `initialize.go`, migration `005_drop_audit_events.sql`, `queries/auth.sql`, `queries/initialize.sql`, regenerated sqlc); `internal/server` (`auth.go` recorder path, `server.go` and `cmd/server` wiring without the recorder).
- Tests across `internal/auth`, `internal/database`, `internal/server`; `scripts/smoke.mjs` event sections.
- Docs: README, PRD section 12, six main specs on archive.
- Dependencies: none.

## Inherited requirements and explicit departures

- PRD 7.7 (as amended 2026-09-12) is the source: no journal in the MVP. Every spec clause that required events derives from the previous PRD text and is removed on that basis, not weakened silently.
- The project-bootstrap quality and smoke requirements are unchanged: smoke keeps every behavioural check and drops only the event counts.

## Non-goals

Changing any error code, hint, guard, bound, transaction shape or route; adding logging as a substitute for the journal; retention or inspection features.
