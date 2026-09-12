## Context

The audit journal is one table (`auth_events`, migrations 001 to 004), one contract file (`internal/auth/events.go`: actions, outcomes, `Event`, `Event.Valid`, `EventRecorder`), one persistence file (`internal/database/events.go`: `RecordEvent`), four helpers in `internal/database/auth.go` (`audit`, `auditWith`, `deny`, `denyWith`), the event step of `administer`, `recordRateLimited`, `bootstrapValidationFailure`, the adapter's recorder (`authHTTP.recorder`, `rejectionAction`, the pre-service rejection path), the `recorder` parameter of `HandlerWithAuth`, the `CheckAuthEventsColumns` readiness check, event assertions in most database and server tests, and eight event-count blocks in smoke. Nothing else reads the table: the rate limiter uses `login_limits`, the admin page lists users, connections and grants.

The owner removed the journal from the MVP on 2026-09-12. This change deletes it and leaves the behaviour around it intact.

## Goals / Non-Goals

**Goals:**
- No event table, contracts, writes or readiness dependency remain.
- Every code, hint, guard, bound, lock order and dry-run semantic is unchanged and still tested.
- Smoke keeps every behavioural check.

**Non-Goals:**
- Replacing the journal with logs; changing routes, CLI output or the web page; retention.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Audit journal with allowlisted actions and outcomes, denial events, "mutation commits with its event" | local-authentication "Secret-free authentication events" and its extensions in three later changes | Explicitly removed (owner decision 2026-09-12, PRD 7.7) |
| Transaction shape of mutations: deadline, readiness, advisory key, ordered locks, recheck, guards, savepoint dry run | archived user-administration and connections designs | Retained without the event step |
| Rate limiting on `login_limits` | local-authentication | Retained; never used events |
| Forward-only Goose migrations, no rewriting applied ones | platform-initialization | Retained: migration `005` drops the table; earlier migrations stay as history |
| Readiness checks every application column | platform-initialization | Retained minus the events check |
| Smoke proves behaviour end to end | project-bootstrap | Retained; event counts removed, behavioural assertions kept |

No unresolved departure.

## Decisions

### 1. Drop, do not keep, the table

Migration `005_drop_audit_events.sql`: `DROP TABLE auth_events;`. Keeping the table empty would leave a readiness check and a sqlc model for nothing. Not in production, so the data loss is accepted (breaking change recorded in the proposal).

### 2. Contracts

Delete `internal/auth/events.go` entirely: `EventAction`, `EventOutcome`, `Event`, `Event.Valid`, `ValidEventAction`, `EventRecorder`. Error codes stay in `errors.go`. The string constants that named actions were used only for event writes and for `rejectionAction`; both go.

### 3. Persistence

- Delete `internal/database/events.go`, the `InsertAuthEvent` query, `CheckAuthEventsColumns` and their generated code.
- `administer`: the body returns `mutation{}` (target and outcome no longer needed; keep a minimal struct or return `error` only, the implementation chooses the simpler and updates every body), commits on success, returns the denial error on a guard or denial without writing anything. `outcomeNone` disappears. The savepoint dry run stays exactly as is.
- `deny`/`denyWith` become a plain `return &auth.Error{Code: code}` at each call site (the hint re-attachment through `hinted` stays).
- `recordRateLimited` becomes returning the rate-limited error with its retry hint.
- `bootstrapValidationFailure` becomes returning the safe failure state without a transaction write.
- `AuthorizeConnection`, member reads and grant listing keep their "no event" behaviour by construction.

### 4. HTTP

Remove `authHTTP.recorder`, `rejectionAction`, the pre-service rejection recording and the `recorder` argument of `HandlerWithAuth`; `cmd/server` passes one argument fewer. Rejections still produce the same JSON failures. The browser logout exemption for missing cookies stays as behaviour (there is nothing left to exempt from).

### 5. Tests and smoke

Every `eventCount`, `lastEvent`, `lastGrantEvent`, `f.events` and `assertBootstrapFailureEvents` assertion is removed together with its fixtures; tests that existed only to prove an event (for example "audit write failure rolls back") are deleted; tests that prove behaviour keep their behavioural assertions. The database test that installs a rejecting trigger on `auth_events` goes. Smoke drops its eight event-count blocks and the "no SQL in events" style checks; every CLI and HTTP assertion stays.

### 6. Docs

README: remove the sentences that say mutations, checks and denied attempts are audited. PRD section 12 status: implemented list notes the journal's removal; planned list drops request auditing and inspection.

## Risks / Trade-offs

- [Denied attempts leave no trace] → accepted by the owner; the codes still reach the caller.
- [Tests lose the "one event per mutation" cross-check that caught double recording] → those bugs cannot exist without recording.
- [Large diff across every layer] → mechanical; the reviewer checks that no non-event assertion was dropped alongside an event one.

## Migration Plan

1. Deploy; migration `005` drops the table once. Not in production; no data to preserve.
2. Rollback as before: previous binary and backup.

## Open Questions

None.
