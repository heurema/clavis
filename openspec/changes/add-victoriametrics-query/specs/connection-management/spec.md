## MODIFIED Requirements

### Requirement: Provider registry

The system SHALL define a closed registry of provider types, initially `postgresql` and `victoriametrics`. Each provider SHALL declare its non-secret target settings, its secret fields, its supported authentication methods, a connectivity probe and an execute operation that runs one request against the source under a decrypted secret and the connection's bounds. Creating a connection with an unknown provider SHALL fail with `INVALID_ARGUMENT` and a hint listing the registered providers. Both registered providers implement execution: PostgreSQL as SQL pass-through and VictoriaMetrics as PromQL and metadata pass-through. A provider whose execute operation is not implemented SHALL report `PROVIDER_UNSUPPORTED` without contacting the source. The registry SHALL be the only place that knows provider-specific parsing and execution; connection storage and authorization SHALL be provider-neutral.

#### Scenario: Create with a registered provider
- **WHEN** an administrator creates a connection with provider `postgresql` and a valid target URL
- **THEN** the provider parses and validates the target, the connection is stored, and no source is contacted

#### Scenario: Unknown provider
- **WHEN** creation names a provider that is not registered
- **THEN** the request fails with `INVALID_ARGUMENT` and the hint lists `postgresql` and `victoriametrics`

#### Scenario: Provider without execution
- **WHEN** a query targets a connection whose provider lacks the execution capability
- **THEN** the request fails with `PROVIDER_UNSUPPORTED` and a hint, and no credential is opened
