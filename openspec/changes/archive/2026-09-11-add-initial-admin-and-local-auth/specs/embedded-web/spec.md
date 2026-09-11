## MODIFIED Requirements

### Requirement: Self-contained server distribution

The server executable SHALL contain the rendered interface implementation, platform migrations and every required browser asset, including styles, scripts, icons and applicable attribution notices. With valid configuration, a compatible operating system and access to the configured PostgreSQL service, it SHALL run without the source checkout, external template, SQL or asset directories, frontend executables, or asset downloads at startup. PostgreSQL SHALL remain an external dependency. The CLI SHALL remain a separate optional client executable. A deployment-managed password file SHALL be an explicit first-initialization credential input, not a companion application asset; initialized installations SHALL NOT require that file.

#### Scenario: Run a copied executable
- **WHEN** an operator copies only the built server executable to an otherwise empty working directory and supplies valid environment configuration for an initialized platform database
- **THEN** the server starts and serves the complete styled, interactive setup/login pages and JSON health endpoints
- **AND** it does not read application templates, SQL or browser assets from the working directory or require development tools in its executable search path

#### Scenario: Browser assets work without third-party network access
- **WHEN** the browser can reach Clavis but third-party HTTP requests are blocked
- **THEN** the page's styles, icons, appearance control and readiness retry work using assets supplied by Clavis
- **AND** no CDN, external font service or other asset origin is required

#### Scenario: Initialize with an explicit mounted secret
- **WHEN** the copied executable runs against a fresh platform database with a configured protected bootstrap password file
- **THEN** schema and account initialization use embedded implementation/SQL and the explicit secret input without external application assets

### Requirement: One origin for the interface and API

The server SHALL serve the interface at `GET /`, its HTML readiness fragment at `GET /ui/readiness`, public assets below `/assets/`, the JSON health endpoints and the documented authentication pages/API on the same configured listener. The browser SHALL use same-origin URLs. An independently deployed frontend or development proxy SHALL NOT be required. Public setup/login documents and assets SHALL remain available while the process is running with an unavailable database; protected content SHALL fail closed.

#### Scenario: Open the application with its database unavailable
- **WHEN** the server is running with valid configuration and the configured database cannot be reached
- **THEN** the browser can load the public setup/login documents and assets from the server's origin
- **AND** the readiness check reports the dependency failure without blocking the initial document on database access

#### Scenario: Request an unknown public resource
- **WHEN** a client requests an unknown asset, a directory listing or a path outside the public asset set
- **THEN** the server returns a not-found response without serving a filesystem listing, private files or the setup document as a fallback

#### Scenario: Protected content during an outage
- **WHEN** an authenticated browser requests administrator content while session storage is unavailable
- **THEN** the server returns safe unavailability rather than serving content using stale authentication

### Requirement: Distinct HTML and JSON representations

JSON health routes SHALL retain their paths, success/database-failure bodies and cache prevention behavior, with the explicit initialization failures defined in project-bootstrap, regardless of browser-specific request headers. The HTML readiness route SHALL return a complete, safe fragment with HTTP 200 for a ready installation and HTTP 503 for dependency or initialization failure. HTML documents and readiness fragments SHALL prevent caching of operational state. Dynamic text SHALL be escaped, and unexpected response bodies SHALL NOT be displayed as diagnostic text. JSON authentication routes SHALL return their documented JSON rather than redirecting to login or becoming HTML under browser headers.

#### Scenario: A CLI request encounters the new web server
- **WHEN** the CLI requests `/health/ready` from the combined server
- **THEN** it receives the documented JSON readiness contract including any explicit initialization failure

#### Scenario: Browser headers reach a JSON endpoint
- **WHEN** a request to `/health/ready` includes `Accept: text/html` or headers used for partial page requests
- **THEN** the endpoint still returns its documented JSON representation

#### Scenario: Render a known dependency failure
- **WHEN** a browser requests `/ui/readiness` and the database check fails
- **THEN** the response is HTTP 503 with a safe HTML readiness fragment and cache prevention headers
- **AND** it contains no connection string or raw dependency error

#### Scenario: An unexpected response contains private text
- **WHEN** a readiness request receives an unexpected status, content type or unrecognized fragment response containing a sentinel secret
- **THEN** the loaded page presents an application-owned error message without inserting the response body into the document

#### Scenario: Render initialization failure
- **WHEN** the database is reachable but the installation is not ready
- **THEN** the HTML readiness response uses the same safe initialization category as JSON and the existing application fragment marker

#### Scenario: Browser headers reach JSON identity
- **WHEN** a JSON authentication endpoint receives browser/partial-request headers without a valid CLI bearer credential
- **THEN** it returns a safe documented JSON failure without a login redirect or HTML response
