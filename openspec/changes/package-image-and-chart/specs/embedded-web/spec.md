## MODIFIED Requirements

### Requirement: Distinct HTML and JSON representations

JSON health routes SHALL retain their paths, success/database-failure bodies and cache prevention behavior, with the explicit initialization failures defined in project-bootstrap, regardless of browser-specific request headers. HTML documents SHALL prevent caching of operational state. Dynamic text SHALL be escaped. JSON authentication routes SHALL return their documented JSON rather than redirecting to login or becoming HTML under browser headers.

#### Scenario: A CLI request encounters the new web server
- **WHEN** the CLI requests `/readyz` from the combined server
- **THEN** it receives the documented JSON readiness contract including any explicit initialization failure

#### Scenario: Browser headers reach a JSON endpoint
- **WHEN** a request to `/readyz` or `/healthz` includes `Accept: text/html` or headers used for partial page requests
- **THEN** the endpoint still returns its documented JSON representation

#### Scenario: Browser headers reach JSON identity
- **WHEN** a JSON authentication endpoint receives browser/partial-request headers without a valid CLI bearer credential
- **THEN** it returns a safe documented JSON failure without a login redirect or HTML response
