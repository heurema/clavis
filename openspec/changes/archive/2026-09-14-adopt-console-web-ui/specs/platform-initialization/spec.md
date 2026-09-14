## MODIFIED Requirements

### Requirement: Initialization does not withhold public diagnostics

The server SHALL start public HTTP diagnostics and documents independently of initialization. Initialization attempts, lock waits, retries and cleanup SHALL be bounded and cancellation-aware. Transient database recovery SHALL permit initialization without restarting the process. Read-only HTTP requests SHALL NOT cause migrations or administrator creation. Readiness and authenticated operations SHALL fail closed until schema and installation state are usable.

#### Scenario: Start while PostgreSQL is unavailable
- **WHEN** valid server configuration is supplied but the database cannot be reached
- **THEN** liveness, the root redirect, the sign-in document and embedded assets remain available
- **AND** readiness and authentication report safe unavailability

#### Scenario: Database and mounted secret recover
- **WHEN** the database becomes available or an invalid mounted secret is repaired while the process is running
- **THEN** bounded worker retries can finish initialization and a subsequent readiness request observes the committed result

#### Scenario: Shut down during a blocked initialization attempt
- **WHEN** termination arrives while migration, bootstrap or retry is pending
- **THEN** the worker is canceled and the process exits within the existing overall shutdown budget
