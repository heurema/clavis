## Context

After `add-local-user-and-admin-role-management` the platform has users, sessions, an administration service pattern (`administer` in `internal/database/admin.go`: deadline, readiness, advisory key, row locks, recheck, one event, commit), bearer-only JSON routes with strict decoding, a CLI command group pattern (`users`), a read-only admin page and a secret-free audit table with check-constraint allowlists. There are no providers, connections or credentials. Configuration comes from `internal/config.Load` over environment variables; the bootstrap password file is read through `ReadBootstrapPassword`, which validates type, size and permissions and never leaks the path.

This change adds the connection record and the credential store. It deliberately stops before grants and execution so the encryption design gets its own review.

The CLI is agent-first. The design rules below were adopted after a sourced review of agent-facing CLI guidance (clig.dev, GitHub CLI, Cloudflare `cf`, Stripe, kubectl, Anthropic and OpenAI tool guidance): non-interactive by default, secrets never in argv, one envelope on stdout, errors with actionable hints, one verb vocabulary, names and IDs both accepted and both returned, `--dry-run` on mutations, bounded lists with explicit truncation, additive-only contract changes.

## Goals / Non-Goals

**Goals:**
- Give administrators a complete, audited lifecycle for connections through the CLI and API.
- Keep every external secret encrypted at rest under an operator-held key, with the plaintext confined to creation, replacement and probing.
- Prove reachability of both providers with a bounded probe that says exactly what it tested.
- Make the CLI shape a template the grant and provider changes copy.

**Non-Goals:**
- Grants and member visibility (`add-connection-grants`); query execution (`add-postgresql-provider`, `add-victoriametrics-provider`); key rotation; `clavis describe`; browser forms; mutual TLS or OAuth2 for VictoriaMetrics.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Five-second operation deadline, readiness gate, fail closed | local-authentication "Explicit authentication transports" | Retained; probes run inside the same deadline |
| Administration transaction shape: advisory key, ordered locks, recheck, one event, commit | archived `add-local-user-and-admin-role-management` design decision 2 | Retained; connections reuse `administer` with a connection-specific advisory key |
| Bearer-only JSON routes, strict 8 KiB bodies, no cookies, `no-store`, adapter-recorded rejections, service-owned outcomes | archived design decision 4 | Retained for `/api/admin/connections` |
| Secret-free events, allowlists as check constraints, forward migrations only | local-authentication "Secret-free authentication events"; platform-initialization | Extended by migration `003`; events never carry secrets or hosts |
| sqlc-only persistence, Goose-only migrations | platform-initialization | Retained |
| Bootstrap secret file rules: absolute path, regular file, `0600`, bounded, nonblocking open | platform-initialization "Safe bounded bootstrap secret handling" | Reused for the key file and for `--password-file` |
| CLI: no secrets in argv or environment for login | cli-authentication "Safe local CLI sign-in" | Explicitly extended: connection secrets add `--password-file` and `--password-env <NAME>`; a bare value flag remains refused; login is unchanged |
| CLI envelope `{schemaVersion, ok, data, error}`, exit 0/1/2 | project-bootstrap "Structured CLI diagnostics" | Explicitly extended: optional `error.hint`, additive, `schemaVersion` stays 1 |
| `users` command conventions: `--user <uuid>` flags, `list|create|...` verbs | cli-authentication "Administrative user commands" | Retained; connections use `--connection <id-or-name>` and the same verbs |
| PRD organization by environment, service and tags | PRD 5, CONN-02 | Explicitly changed (owner decision 2026-09-12): labels and selectors; PRD wording to be updated in the docs task |
| Listing bound 1,000 with `truncated`, listing-only 256 KiB body | user-administration | Retained for connections |
| Read-only admin page, no forms | user-administration | Retained |
| Pass-through data model, resource bounds per connection, defaults open in PRD 12 | PRD 4, 7.4, 12 | Defaults settled here: 30 s, 1,000 rows, 1 MiB; ceilings 120 s, 100,000 rows, 10 MiB; enforcement deferred to provider changes |

No unresolved departure requires owner approval; every departure above was decided in the grilling session of 2026-09-12.

## Decisions

### 1. Package layout

- `internal/provider`: the registry. `type Provider interface { Type() auth.ProviderType; ParseTarget(map[string]string) (map[string]string, error); ValidateSecret(map[string]string, auth.Secret) error; Probe(ctx, map[string]string, auth.Secret) auth.CheckOutcome }` plus `Lookup`, `Types` and `TypeHint`. Two implementations: `postgres.go` (pgx, `SELECT 1`) and `victoriametrics.go` (`net/http`, GET `/health`, header from auth method). Targets are provider-validated flat string maps: the raw submitted map goes in, the canonical stored map comes out. `Probe` returns only `reachable`, `auth_rejected` or `unreachable`; `credentials_unavailable` is the service's outcome. The probe respects the caller's deadline and closes its connection under an independent short deadline. Operator-controlled `PG*` environment variables can still influence unpinned libpq settings of the probe; host, port, user, database, sslmode, connect timeout and password are pinned. The package imports neither database, server, CLI nor secrets code.
- `internal/secrets`: `type Keyring struct` loaded from the key file; `Seal(plaintext, aad) (Envelope, error)` and `Open(Envelope, aad) (plaintext, error)`. Envelope on disk: `v1:` prefix, then base64 of nonce plus AES-256-GCM ciphertext. Associated data: `connection:<uuid>:v1`. The keyring holds one key now and a version map so `v2` can be added without a migration.
- `internal/auth`: `Connection`, `ConnectionList`, `CreateConnectionRequest`, `UpdateConnectionRequest`, `SetConnectionCredentialsRequest`, `CheckResult`, `ConnectionMutation` DTOs, the `Connections` service interface, paths, error codes, event actions, and `hint` on `ErrorResponse`.
- `internal/database`: migration `003_connections.sql`, `queries/connections.sql`, `connections.go` service on `LocalAuth` (renamed conceptually to the platform store but the type stays), reusing `administer`.
- `internal/server`: `connections.go` handlers; `internal/web`: connections table; `internal/cli`: `connections_commands.go`, secret inputs, dry-run and hint rendering.

### 2. Schema (migration 003)

```sql
CREATE TABLE connections (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9._-]{2,63}$'),
    title text NOT NULL CHECK (char_length(title) <= 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    scope text NOT NULL DEFAULT '' CHECK (char_length(scope) <= 2000),
    provider text NOT NULL CHECK (provider IN ('postgresql', 'victoriametrics')),
    target jsonb NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_envelope text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    statement_timeout_ms integer NOT NULL DEFAULT 30000 CHECK (statement_timeout_ms BETWEEN 1000 AND 120000),
    max_rows integer NOT NULL DEFAULT 1000 CHECK (max_rows BETWEEN 1 AND 100000),
    max_bytes integer NOT NULL DEFAULT 1048576 CHECK (max_bytes BETWEEN 1024 AND 10485760),
    last_check_outcome text CHECK (last_check_outcome IN ('reachable', 'auth_rejected', 'unreachable', 'credentials_unavailable')),
    last_check_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX connections_labels ON connections USING gin (labels);
```

Plus the `auth_events` action and outcome constraint replacements. `target` holds only non-secret settings as a flat string map validated by the provider; `labels` is a flat string map. The `grants` table does not exist yet, so the delete guard in this change requires only `enabled = false`; `add-connection-grants` extends the guard with the grant count and its test.

Selectors compile to SQL over `labels`: `key=value` → `labels @> '{"key":"value"}'`, `key!=value` → `NOT (labels @> ...)`, bare `key` → `labels ? 'key'`. At most 8 terms.

### 3. Service shape

Every mutation runs through `administer` with `connectionMutationLock` (a fourth advisory key), `LockMutationUsers(actor, "")` for the actor recheck, then `SELECT ... FOR UPDATE` on the connection row by id or name. Create: validate DTO, provider parses target, seal secret (needs the new UUID first, so generate the UUID before sealing), insert, event. Update: partial fields; `target` and `labels` are replaced whole when present (the CLI requires `--url` whenever any target flag is given on `update`, and sends only the given target keys), the provider re-parses the raw target map; the envelope is untouched. Set-credentials: seal, update envelope, null out the last check, event. Enable/disable: idempotent. Delete: guard then delete; event carries the UUID and the name in the event's target? The event schema has only UUID columns, so the name is not recorded; the deletion event's target is the UUID, which listings no longer resolve. Accept this: the audit records the actor and the UUID, and `connection.create` earlier recorded the same UUID.

Dry run: `administer` gains a `dryRun bool`; when set, authorization and the body run inside a savepoint that is released and then discarded with the outer transaction's rollback, so neither a success event nor a denial event is committed while the returned result or error (with its hint) is identical to a real run. The result carries `dryRun: true`. `administer` also takes the advisory key as a parameter (`adminMutationLock` for users, `connectionMutationLock` for connections), and its body reports the success-event outcome so a check can record `check_failed` without being an error. Validation that needs the row's provider (target re-parse on update, secret validation on credential replacement) runs inside the body and returns `INVALID_ARGUMENT` without an event, matching pre-transaction validation. Because `deny` rebuilds errors from the code alone, the connection service re-attaches its fixed hints after a denial. An empty secret, valid only for VictoriaMetrics `auth: none`, is sealed as a one-byte NUL sentinel (NUL is refused in real secrets, so there is no collision) and mapped back to empty on open. Two equality terms on the same key are unsatisfiable and short-circuit to an empty listing. The probe runs while the connection row, the actor's user row and the connection advisory key are held for up to the operation deadline, so other connection mutations queue behind a slow check.

Check: authorize, load the row, open the envelope (failure → store `credentials_unavailable` and return `CREDENTIALS_UNAVAILABLE`), run `Probe` with the remaining deadline, store the outcome and time, record `connection.check` with `success` or `check_failed`. The probe result never includes driver text; the provider maps errors to the four outcomes internally.

Hashing budget does not apply; no Argon2 here.

### 4. HTTP contract

| Method/path | Body | Success |
|---|---|---|
| `GET /api/admin/connections?selector=...&limit=N` | none | 200 `{connections:[...],truncated}` |
| `POST /api/admin/connections[?dryRun=true]` | create request incl. `secret` | 201 record (dry run: 200 `{connection, dryRun:true}`) |
| `GET /api/admin/connections/{connectionID}` | none | 200 record |
| `POST /api/admin/connections/{connectionID}/update[?dryRun=true]` | partial fields | 200 `{connection, dryRun}` |
| `POST /api/admin/connections/{connectionID}/credentials[?dryRun=true]` | `{secret}` | 200 `{connection, dryRun}` |
| `POST /api/admin/connections/{connectionID}/enable`, `/disable`, `/delete` `[?dryRun=true]` | empty | 200 `{connection, dryRun}` (delete: `{id, name, deleted:true, dryRun}`) |
| `POST /api/admin/connections/{connectionID}/check` | empty | 200 `{connection, check:{outcome, checkedAt}}` |

`{connectionID}` is a UUID or a name; the route validates it as one of the two shapes before the service call. A full listing of 1,000 connections can exceed the 256 KiB listing body shared with users (a record with long description, scope and 16 labels is several kilobytes), so the listing handler enforces a byte budget: it encodes records in name order and stops before the body would exceed `auth.MaxListingBody`, setting `truncated: true`. Truncation is therefore explicit whether the row bound or the byte budget applies, and the CLI keeps its single listing limit. Errors: 400 `INVALID_ARGUMENT`, 401, 403, 404 `CONNECTION_NOT_FOUND`, 409 `CONNECTION_EXISTS` / `CONNECTION_IN_USE`, 409 `CREDENTIALS_UNAVAILABLE`, 503. Every error may carry `hint`. `auditRejection` maps the routes to `connection.*` actions; pre-service rejections on update/credentials/enable/disable/delete use their own action; the check route maps to `connection.check`.

### 5. CLI

`connections` group beside `users`. Secret inputs: exactly one of prompt (interactive only), `--password-stdin`, `--password-file` (absolute, regular, `0600`, bounded, one trailing newline stripped; reuse the bootstrap reader's rules in a CLI-side copy since the CLI cannot import the database package), `--password-env NAME` (name validated as `[A-Z_][A-Z0-9_]*`, value read from the process environment, unset or empty → exit 2). `--dry-run` sets the query parameter. Text rendering: one line per connection for lists; a labelled block for records; `Hint:` line after `CODE: message` for errors. The transport's per-route allowlist gains the connection codes.

### 6. Key file and configuration

`config.Load` gains `EncryptionKeyFile` (required). Reading happens in `cmd/server` after configuration validation and before the listener, through a `secrets.LoadKeyFile(path)` that applies the bootstrap file rules (absolute, regular, no group/world bits, ≤ 66 bytes, one newline stripped, 64 hex chars). Failures map to the documented `config.Error` categories. The key never appears in logs; the path appears only in the configuration error's setting name, not its value.

### 7. Smoke

The smoke script generates a key file next to the bootstrap password, starts the server with `CLAVIS_ENCRYPTION_KEY_FILE`, then: create a `postgresql` connection pointing at the smoke database with a dedicated role and password, check → `reachable`; set wrong credentials, check → `auth_rejected`; point at a closed port via update, check → `unreachable`; create a `victoriametrics` connection against a local Node HTTP stub that requires a bearer token on `/health`, check with the right and wrong token; disable, delete guard, delete; selector listing; dry-run leaves no rows or events; event counts by action; a server restart without the key file fails with the configuration error; a restart with a different key makes check report `credentials_unavailable`.

## Risks / Trade-offs

- [Key loss means every stored secret is lost] → Document that the key belongs in the operator's secret manager next to the bootstrap password; connections can be re-credentialed but not recovered. Rotation is a later change; the envelope version makes it possible.
- [Probes contact production sources from the platform] → Bounded to the operation deadline, one connection each, no retries, explicit only.
- [Delete guard is incomplete until grants exist] → The grants change extends the guard and its test; until then delete only requires disabled.
- [Dry run of a denial rolls back the denial event] → Accepted: a dry run is a question, not an attempt; the spec says so.
- [`--password-env` still puts the value in the process environment] → The value never enters the agent's context or argv; the variable is set by the operator or the harness, which is the standard agent credential channel.
- [Label selector on JSONB without a schema] → Bounded to 8 terms and 16 labels; a GIN index covers containment.
- [Handwritten size well above the rescoping signal] → Sliced into six reviewable slices below; coupled behavior (record, secret, probe) stays together.

## Migration Plan

1. Operators generate a 32-byte key (`openssl rand -hex 32 > key; chmod 600 key`) and set `CLAVIS_ENCRYPTION_KEY_FILE` before deploying this release; the server refuses to start without it.
2. Deploy; migration `003` applies under the shared lock. No data rewrite.
3. Rollback: stop and restore a tested previous binary and backup, as before. Migration `003` is forward-only; a previous binary tolerates the extra table and the wider constraints.

## Open Questions

None. The remaining PRD items (which diagnostics helpers ship with the PostgreSQL provider, the pilot's first questions) belong to later changes.
