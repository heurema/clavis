## MODIFIED Requirements

### Requirement: Provider registry

The system SHALL define a closed registry of provider types, initially `postgresql` and `victoriametrics`. Each provider SHALL declare its non-secret target settings, its secret fields, its supported authentication methods, a connectivity probe and an execute operation that runs one request against the source under a decrypted secret and the connection's bounds. Creating a connection with an unknown provider SHALL fail with `INVALID_ARGUMENT` and a hint listing the registered providers. A provider whose execute operation is not implemented SHALL report `PROVIDER_UNSUPPORTED` without contacting the source. The registry SHALL be the only place that knows provider-specific parsing and execution; connection storage, authorization and audit SHALL be provider-neutral.

#### Scenario: Create with a registered provider
- **WHEN** an administrator creates a connection with provider `postgresql` and a valid target URL
- **THEN** the provider parses and validates the target, the connection is stored, and no source is contacted

#### Scenario: Unknown provider
- **WHEN** creation names a provider that is not registered
- **THEN** the request fails with `INVALID_ARGUMENT` and the hint lists `postgresql` and `victoriametrics`

#### Scenario: Provider without execution
- **WHEN** a query targets a `victoriametrics` connection before its execution change ships
- **THEN** the request fails with `PROVIDER_UNSUPPORTED` and a hint, and no credential is opened

### Requirement: Connection records

A connection SHALL have a server-generated UUID identifier, a unique mutable name matching `[a-z][a-z0-9._-]{2,63}`, a title of up to 128 characters, description and access-scope text of up to 2,000 characters each, a provider, provider-specific non-secret target settings, up to 16 labels of the form `key=value` where key and value match `[a-z0-9][a-z0-9._-]{0,62}`, an enabled flag defaulting to true, a statement timeout defaulting to 30 seconds with a ceiling of 120 seconds, a result cap defaulting to 1,000 rows and 1 MiB with ceilings of 100,000 rows and 10 MiB, creation and update times, and the outcome and time of the last connectivity check. Resource bounds SHALL be enforced by every execute operation as the statement timeout set on the source session and the row and byte caps applied to the response with explicit truncation. A name that already exists SHALL fail creation with `CONNECTION_EXISTS` and a hint pointing at `update`. Operations SHALL address a connection by UUID or by name; because a valid name can never parse as a UUID, the lookup SHALL try UUID syntax first and fall back to the name without ambiguity. Every response SHALL include both `id` and `name`.

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

#### Scenario: Bounds applied to an execution
- **WHEN** a connection with a 2 s timeout and a 50-row cap executes a slow or wide query
- **THEN** the slow one ends with `SOURCE_TIMEOUT` and the wide one returns 50 rows marked truncated
