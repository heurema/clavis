## MODIFIED Requirements

### Requirement: Provider registry

The system SHALL define a closed registry of provider types, initially `postgresql`, `victoriametrics` and `victorialogs`. Each provider SHALL declare its non-secret target settings, its secret fields, its supported authentication methods, a connectivity probe and an execute operation that runs one request against the source under a decrypted secret and the connection's bounds. Creating a connection with an unknown provider SHALL fail with `INVALID_ARGUMENT` and a hint listing the registered providers. All registered providers implement execution: PostgreSQL as SQL pass-through, VictoriaMetrics as PromQL and metadata pass-through, and VictoriaLogs as LogsQL and metadata pass-through. The `victorialogs` target SHALL carry `url`, `auth` and the method's non-secret half exactly as `victoriametrics` does, plus optional `accountId` and `projectId`, each an unsigned 32-bit decimal integer selecting the tenant, sent as the `AccountID` and `ProjectID` request headers on every probe and execution beside the stored authentication; an omitted setting sends no header, and a custom authentication header named `AccountID` or `ProjectID` SHALL be refused. A provider whose execute operation is not implemented SHALL report `PROVIDER_UNSUPPORTED` without contacting the source. The registry SHALL be the only place that knows provider-specific parsing and execution; connection storage and authorization SHALL be provider-neutral.

#### Scenario: Create with a registered provider
- **WHEN** an administrator creates a connection with provider `postgresql` and a valid target URL
- **THEN** the provider parses and validates the target, the connection is stored, and no source is contacted

#### Scenario: Unknown provider
- **WHEN** creation names a provider that is not registered
- **THEN** the request fails with `INVALID_ARGUMENT` and the hint lists `postgresql`, `victoriametrics` and `victorialogs`

#### Scenario: Tenant settings on a log connection
- **WHEN** an administrator creates a `victorialogs` connection with `accountId` 12 and `projectId` 3
- **THEN** both are stored as target settings, shown in the record, and sent as the `AccountID` and `ProjectID` headers on every check and query; a negative, non-integer or oversized value, or a custom header named like either, fails with `INVALID_ARGUMENT`

#### Scenario: Provider without execution
- **WHEN** a query targets a connection whose provider lacks the execution capability
- **THEN** the request fails with `PROVIDER_UNSUPPORTED` and a hint, and no credential is opened

### Requirement: Explicit connectivity check

A check SHALL run only on request, never on creation. It SHALL decrypt the secret in memory, run the provider's probe against the stored target within the five-second operation deadline, and store one outcome of `reachable`, `auth_rejected`, `unreachable` or `credentials_unavailable` with the check time, replacing the previous outcome. For `postgresql` the probe SHALL open one connection and execute `SELECT 1`; for `victoriametrics` and `victorialogs` it SHALL send one GET to the health endpoint with the configured authentication, and for `victorialogs` with the tenant headers when configured. The stored and returned result SHALL carry a safe category only, never the source's error text. A check SHALL claim nothing about which data the credentials can access.

#### Scenario: Reachable source
- **WHEN** the target accepts the credentials
- **THEN** the result is `reachable` with a timestamp and the connection's last check is updated

#### Scenario: Rejected credentials or unreachable target
- **WHEN** the source rejects authentication, or the host does not answer within the deadline
- **THEN** the result is `auth_rejected` or `unreachable` respectively, the connection remains enabled, and the response contains no driver text

#### Scenario: Check after credential replacement
- **WHEN** credentials are replaced
- **THEN** the last check becomes null until the next explicit check
