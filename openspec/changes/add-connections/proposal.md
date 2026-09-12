## Why

Clavis can now manage who signs in, but it has nothing for an administrator to grant or for an agent to query: no provider types, no connection records and no safe place to keep external credentials. Every remaining MVP capability (grants, PostgreSQL pass-through, VictoriaMetrics, audit inspection, the agent skill) needs the connection record and the credential store this change introduces, and the encryption-at-rest decision of 2026-09-11 deserves its own independent security review before authorization logic is layered on it.

## What Changes

- Add a provider registry with two provider types, `postgresql` and `victoriametrics`, each defining its non-secret target settings, its secret fields and its connectivity probe. No query execution ships here.
- Add connection records: a server-generated UUID identifier, a mutable unique slug name, a title, description and access-scope text, the provider, non-secret target settings, labels, an enabled flag, per-connection resource-bound columns with defaults and ceilings (enforced by the later provider changes), and the outcome and time of the last connectivity check.
- Encrypt connection secrets at rest with AES-256-GCM under a 32-byte key supplied through `CLAVIS_ENCRYPTION_KEY_FILE`, handled like the bootstrap password file and required at startup. Ciphertext carries a key-version prefix and binds the connection UUID as associated data. Secrets are decrypted only for a connectivity check (and, later, provider execution) and are never returned by any route.
- Add administrator-only operations: list, get, create, update, replace credentials, enable, disable, delete (only when disabled and holding no grants) and check. Creation never contacts the source; the check is explicit and records one of `reachable`, `auth_rejected`, `unreachable` or `credentials_unavailable`. Replacing credentials clears the last check.
- Replace the PRD's environment/service/tags with kubectl-style labels (`key=value`) and selectors for filtering, one grammar agents already know.
- Add the CLI group `connections` following the `users` conventions, addressing a connection by `--connection <uuid-or-name>`, taking secrets only through a hidden prompt, `--password-stdin`, `--password-file` or `--password-env <VAR>` (never a flag value), and offering `--dry-run` on every mutation.
- Add an optional `hint` field to the JSON error object across the server and CLI, so an agent can self-correct in one retry. Additive, so `schemaVersion` stays 1.
- Add JSON routes under `/api/admin/connections` for CLI bearer sessions, a forward migration for the `connections` table and the new audit actions, and a read-only connections table on the admin page.
- Cover the whole flow in smoke: create, check against the real PostgreSQL and a local VictoriaMetrics health stub, update, replace credentials, disable, delete guard, and event counts.

## Capabilities

### New Capabilities

- `connection-management`: provider registry, connection records, encrypted credential storage and key handling, administrator operations including connectivity checks and the guarded delete, the JSON administration routes and the read-only browser table.

### Modified Capabilities

- `local-authentication`: the secret-free event allowlist gains the `connection.*` actions and the `credentials_unavailable`, `connection_exists`, `connection_in_use` and `check_failed` outcomes through a forward migration; error responses may carry an optional `hint`.
- `cli-authentication`: the CLI gains the `connections` command group, the file and environment-variable secret inputs, the `--dry-run` convention and the `hint` field in results.
- `project-bootstrap`: server configuration gains the required encryption key file with the same protected-file rules as the bootstrap secret; startup fails fast without it.

## Impact

- Backend: `internal/config` (key file setting and validation), new `internal/secrets` (envelope encryption) and `internal/provider` (registry, PostgreSQL and VictoriaMetrics probes), `internal/database` (migration `003`, connection queries, connection service), `internal/server` (routes, admin page data), `internal/auth` (contracts, error codes, event actions, `hint`).
- UI: `internal/web` admin template and model, regenerated templ Go.
- Client: `internal/cli` connections commands, secret inputs, dry-run and hint rendering, transport allowlist.
- Tooling/docs: `scripts/smoke.mjs` (VictoriaMetrics health stub, connection flow), `.env.example`, README, PRD section 12 status.
- Dependencies: none added. AES-GCM is in the Go standard library; the PostgreSQL probe uses the existing pgx driver; the VictoriaMetrics probe uses `net/http`.

## Owner decisions (2026-09-12 grilling session)

- Connectivity checks ship now for both providers; they are the only end-to-end proof of the encryption path.
- Identity is a server UUID; the slug name is mutable and unique; commands accept either.
- The key is a mounted file, required at startup; no environment-variable key, no partially functional state.
- Non-secret target settings are visible to administrators; only secret values are encrypted.
- Labels and selectors replace environment, service and tags.
- Delete is allowed only for a disabled connection with no grants; a guard, not a confirmation flag.
- The CLI is agent-first: one verb vocabulary, flags over positionals to match `users`, `--dry-run` everywhere, error hints, secret values never in argv. The rationale and sources are recorded in the design.

## Non-goals

Grants, member visibility of connections and the per-request authorization check (`add-connection-grants`); query execution, discovery and result handling (`add-postgresql-provider`, `add-victoriametrics-provider`); `clavis describe` and `--fields` (`add-cli-describe`); key rotation; groups; audit inspection.
