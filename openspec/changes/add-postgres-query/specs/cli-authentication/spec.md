## MODIFIED Requirements

### Requirement: Bounded and non-disclosing authentication transport

Authentication requests SHALL use a single documented whole-request deadline, bounded request and response bodies, strict status/body validation and no redirects or automatic mutation retries. Bounds SHALL be per route: the general request and response limits apply everywhere except the documented listings, which read up to the listing limit, and the query route, whose request carries up to 256 KiB of SQL and whose response is read up to the connection's byte cap plus the envelope allowance; a body above its route's bound SHALL be reported as `INVALID_RESPONSE` (response) or refused locally with `INVALID_ARGUMENT` (request). Credentials SHALL never be forwarded to a redirect destination. Malformed responses and transport errors SHALL be mapped to application-owned errors without exposing raw server content.

#### Scenario: Credential request redirects
- **WHEN** login or a bearer request receives a redirect
- **THEN** the CLI does not contact the destination and reports `INVALID_RESPONSE`

#### Scenario: Stalled or malformed authentication response
- **WHEN** the response body stalls, exceeds its limit or contains an undocumented status/body combination with sentinel secrets
- **THEN** the CLI terminates within the deadline with a safe timeout/invalid-response result and does not display the body

#### Scenario: Query bodies use their own bounds
- **WHEN** a query sends 200 KiB of SQL and receives a 5 MiB result on a connection capped at 8 MiB
- **THEN** both pass, while the same result on a connection capped at 1 MiB is reported as `INVALID_RESPONSE` rather than partially displayed

## ADDED Requirements

### Requirement: Query command

The CLI SHALL provide `query --connection <ref> (--sql <text> | --sql-stdin | --sql-file <path>) [--max-rows N]`, where `<ref>` is a UUID or name, exactly one SQL input is required, `--sql-file` takes an absolute path, and the SQL is bounded to 256 KiB before any request. The command SHALL use the stored session, the shared flags, transport, envelope and hint conventions of the other groups, SHALL send one request to the query route and SHALL render the results document in JSON or as `psql`-style text tables. `SOURCE_ERROR`, `SOURCE_TIMEOUT`, `SOURCE_UNREACHABLE`, `SOURCE_AUTH_REJECTED`, `CREDENTIALS_UNAVAILABLE`, `PROVIDER_UNSUPPORTED`, `CONNECTION_NOT_FOUND`, `CONNECTION_DISABLED`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through; undocumented responses SHALL map to `INVALID_RESPONSE`. A truncated result SHALL exit 0 with the truncation visible in both outputs; every failure code SHALL exit 1; invalid arguments SHALL exit 2. The SQL SHALL NOT be echoed in results or errors.

#### Scenario: Inline query as JSON
- **WHEN** an agent runs `query --connection payments-prod-reporting --sql 'select count(*) from orders'`
- **THEN** the CLI prints one envelope whose `data.results[0]` carries the column list and one row of strings, exit 0

#### Scenario: Source error as text
- **WHEN** a text-output query fails with a PostgreSQL syntax error
- **THEN** the CLI prints `ERROR: <sqlstate> <message>` with the position line and the statement index, exits 1, and the SQL is not repeated

#### Scenario: Invalid inputs
- **WHEN** the reference is invalid, `--max-rows` is not a positive integer, two SQL inputs are given, or the file path is relative
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server
