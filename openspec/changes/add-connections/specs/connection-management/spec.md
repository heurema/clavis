## Purpose

Let administrators register external data-source connections with encrypted credentials, verify reachability, and manage their lifecycle, so later changes can grant and use them safely.

## ADDED Requirements

### Requirement: Provider registry

The system SHALL define a closed registry of provider types, initially `postgresql` and `victoriametrics`. Each provider SHALL declare its non-secret target settings, its secret fields, its supported authentication methods and a connectivity probe. Creating a connection with an unknown provider SHALL fail with `INVALID_ARGUMENT` and a hint listing the registered providers. The registry SHALL be the only place that knows provider-specific parsing; connection storage, authorization and audit SHALL be provider-neutral.

#### Scenario: Create with a registered provider
- **WHEN** an administrator creates a connection with provider `postgresql` and a valid target URL
- **THEN** the provider parses and validates the target, the connection is stored, and no source is contacted

#### Scenario: Unknown provider
- **WHEN** creation names a provider that is not registered
- **THEN** the request fails with `INVALID_ARGUMENT` and the hint lists `postgresql` and `victoriametrics`

### Requirement: Connection records

A connection SHALL have a server-generated UUID identifier, a unique mutable name matching `[a-z][a-z0-9._-]{2,63}`, a title of up to 128 characters, description and access-scope text of up to 2,000 characters each, a provider, provider-specific non-secret target settings, up to 16 labels of the form `key=value` where key and value match `[a-z0-9][a-z0-9._-]{0,62}`, an enabled flag defaulting to true, a statement timeout defaulting to 30 seconds with a ceiling of 120 seconds, a result cap defaulting to 1,000 rows and 1 MiB with ceilings of 100,000 rows and 10 MiB, creation and update times, and the outcome and time of the last connectivity check. Resource bounds are stored and validated in this change and enforced by the provider changes. A name that already exists SHALL fail creation with `CONNECTION_EXISTS` and a hint pointing at `update`. Operations SHALL address a connection by UUID or by name; because a valid name can never parse as a UUID, the lookup SHALL try UUID syntax first and fall back to the name without ambiguity. Every response SHALL include both `id` and `name`.

For `postgresql` the target SHALL be a `postgres://` or `postgresql://` URL carrying host, port, database, role and optional `sslmode`, and SHALL be rejected if it contains a password or unknown query parameters. For `victoriametrics` the target SHALL be an `http://` or `https://` base URL without credentials plus an authentication method of `none`, `basic`, `bearer` or `header`, with a non-secret basic username or header name where the method needs one.

#### Scenario: Create and read back
- **WHEN** an administrator creates a connection with a name, title, provider, target URL, labels and a secret
- **THEN** the result contains the UUID, name, every non-secret field, `enabled: true`, `lastCheck: null` and no secret value

#### Scenario: Address by name or by UUID
- **WHEN** an operation names a connection by its slug or by its UUID
- **THEN** both resolve to the same record and an unknown value fails with `CONNECTION_NOT_FOUND`

#### Scenario: Duplicate or invalid inputs
- **WHEN** creation reuses an existing name, exceeds a label or text bound, supplies a target URL with an embedded password, or sets a bound above its ceiling
- **THEN** it fails with `CONNECTION_EXISTS` or `INVALID_ARGUMENT`, a hint names the offending field or the valid range, and nothing is stored

#### Scenario: Rename keeps identity
- **WHEN** an administrator changes a connection's name
- **THEN** the UUID, credentials, labels and check history are unchanged and audit events continue to reference the UUID

### Requirement: Encrypted credentials at rest

The server SHALL require `CLAVIS_ENCRYPTION_KEY_FILE`, an absolute path to a protected regular file holding exactly 32 key bytes encoded as 64 hexadecimal characters with at most one terminal newline, read with the same type, size and permission rules as the bootstrap password file. Startup SHALL fail before listening when the setting is absent, unreadable or invalid. Connection secrets SHALL be encrypted with AES-256-GCM using a fresh random 96-bit nonce per write, the connection UUID and key version as associated data, and stored as a versioned envelope. Plaintext secrets SHALL exist in memory only during creation, credential replacement and a connectivity check, and SHALL never be returned by any route, rendered in HTML, written to audit events or logged. A stored envelope that cannot be decrypted SHALL make the dependent operation fail closed with `CREDENTIALS_UNAVAILABLE` without affecting readiness.

#### Scenario: Server starts without a key
- **WHEN** the server starts with no `CLAVIS_ENCRYPTION_KEY_FILE`, a group-readable file, a wrong length or a non-hexadecimal value
- **THEN** it exits with a configuration error naming the setting and the category, without listening and without reading the database

#### Scenario: Secret round trip
- **WHEN** a secret is stored and later used by a connectivity check
- **THEN** the check receives the original plaintext and the stored column holds only the versioned ciphertext, which differs between two writes of the same plaintext

#### Scenario: Envelope moved between rows or key changed
- **WHEN** a ciphertext is copied to another connection's row, or the key file is replaced with a different key
- **THEN** decryption fails, the operation reports `CREDENTIALS_UNAVAILABLE`, an event records the failure and readiness remains unaffected

#### Scenario: Secret in an internal error
- **WHEN** a probe or driver error contains a sentinel secret or the target host
- **THEN** neither responses, events, logs nor CLI output contain them

### Requirement: Administrator-only connection operations

Listing, getting, creating, updating, replacing credentials, enabling, disabling, deleting and checking connections SHALL require a current administrator session rechecked inside the operation, following the transaction shape, deadline, readiness gate and denial-event rules of user administration. Members SHALL receive `FORBIDDEN` with a denial event and no mutation. Update SHALL change only the supplied fields. Replacing credentials SHALL clear the last check result. Disabling SHALL be idempotent. Delete SHALL succeed only when the connection is disabled and holds no grants, otherwise fail with `CONNECTION_IN_USE` and a hint naming the blocking condition. Every mutation SHALL support a dry run that performs validation, authorization and guards inside a transaction that is rolled back, returning the same result shape marked `dryRun: true` and recording no event. Listing SHALL be bounded to 1,000 connections ordered by name with a `truncated` flag, SHALL support label selectors with equality, inequality and existence terms combined with AND, and SHALL record no success event.

#### Scenario: Update a subset of fields
- **WHEN** an administrator updates only the statement timeout
- **THEN** every other field, the credentials and the last check are unchanged and one `connection.update` event is recorded

#### Scenario: Guarded delete
- **WHEN** delete targets an enabled connection, or a disabled one that still has grants
- **THEN** it fails with `CONNECTION_IN_USE`, the hint says to disable it or revoke its grants, and nothing is removed
- **AND** delete of a disabled, grant-free connection removes the row and records `connection.delete` with the UUID and name

#### Scenario: Dry run
- **WHEN** any mutation runs with `--dry-run`
- **THEN** it returns the outcome it would have had, including denials and guard failures, commits nothing and records no event

#### Scenario: Filter by selector
- **WHEN** an administrator lists with `env=prod,service!=legacy,team`
- **THEN** only connections carrying `env=prod`, not carrying `service=legacy`, and having any `team` label are returned in name order

#### Scenario: Member attempts an operation
- **WHEN** a member session invokes any connection operation
- **THEN** it is refused with `FORBIDDEN`, a denial event is recorded and nothing changes

### Requirement: Explicit connectivity check

A check SHALL run only on request, never on creation. It SHALL decrypt the secret in memory, run the provider's probe against the stored target within the five-second operation deadline, and store one outcome of `reachable`, `auth_rejected`, `unreachable` or `credentials_unavailable` with the check time, replacing the previous outcome. For `postgresql` the probe SHALL open one connection and execute `SELECT 1`; for `victoriametrics` it SHALL send one GET to the health endpoint with the configured authentication. The stored and returned result SHALL carry a safe category only, never the source's error text. A check SHALL claim nothing about which data the credentials can access. The check outcome SHALL be recorded as a `connection.check` event with outcome `success` for `reachable` and `check_failed` otherwise.

#### Scenario: Reachable source
- **WHEN** the target accepts the credentials
- **THEN** the result is `reachable` with a timestamp and the connection's last check is updated

#### Scenario: Rejected credentials or unreachable target
- **WHEN** the source rejects authentication, or the host does not answer within the deadline
- **THEN** the result is `auth_rejected` or `unreachable` respectively, the connection remains enabled, and the response contains no driver text

#### Scenario: Check after credential replacement
- **WHEN** credentials are replaced
- **THEN** the last check becomes null until the next explicit check

### Requirement: JSON connection routes

The server SHALL expose the operations as JSON routes under `/api/admin/connections` for CLI bearer sessions only, following the transport rules of the user-administration routes: bearer-only sessions, configured-origin check, strict bounded JSON bodies, no cookies, no redirects, `Cache-Control: no-store`, adapter-recorded pre-service rejections and service-owned outcomes. Error bodies MAY carry an optional `hint` string alongside `code` and `message`; hints SHALL be application-owned text and never echo submitted values. Secrets SHALL arrive only in request bodies for create and credential replacement and SHALL be bounded like passwords. Dry runs SHALL be requested with a documented query parameter. The listing response SHALL stay under the listing body limit shared with users.

#### Scenario: Create through the API
- **WHEN** an administrator's bearer request posts a valid connection body
- **THEN** the response is 201 with the record and no secret field

#### Scenario: Error with hint
- **WHEN** a request fails with `CONNECTION_EXISTS`, `CONNECTION_IN_USE`, `INVALID_ARGUMENT` or `CONNECTION_NOT_FOUND`
- **THEN** the error object carries `code`, `message` and a `hint` that names the next action or valid values without reflecting submitted data

#### Scenario: Cookie on a connection route
- **WHEN** a connection request carries only a browser session cookie
- **THEN** it receives an unauthenticated JSON response and no mutation occurs

### Requirement: Read-only connections table in the browser

The protected administrator page SHALL list connections with name, title, provider, labels, status and last check outcome and time, escaped, bounded like the user list, with a truncation notice and no management forms. It SHALL fail closed when the list cannot be loaded and SHALL never show target hosts, roles or secrets.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests the administration page
- **THEN** the connections table renders below the users table with the documented columns and nothing more

#### Scenario: List unavailable
- **WHEN** the connection listing fails
- **THEN** the page returns safe 503 rather than rendering without current data
