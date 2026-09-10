# embedded-web Specification

## Purpose

Let an operator run the Clavis API and usable web interface from one server executable, with complete browser assets and predictable behavior independent of the source checkout.

## Requirements

### Requirement: Self-contained server distribution

The server executable SHALL contain the rendered interface implementation and every required browser asset, including styles, scripts, icons and applicable attribution notices. With valid configuration, a compatible operating system and access to the configured PostgreSQL service, it SHALL run without the source checkout, external template or asset directories, frontend executables, or asset downloads at startup. PostgreSQL SHALL remain an external dependency. The CLI SHALL remain a separate optional client executable.

#### Scenario: Run a copied executable
- **WHEN** an operator copies only the built server executable to an otherwise empty working directory and supplies valid environment configuration
- **THEN** the server starts and serves the complete styled, interactive setup page and JSON health endpoints
- **AND** it does not read application templates or browser assets from the working directory or require development tools in its executable search path

#### Scenario: Browser assets work without third-party network access
- **WHEN** the browser can reach Clavis but third-party HTTP requests are blocked
- **THEN** the page's styles, icons, appearance control and readiness retry work using assets supplied by Clavis
- **AND** no CDN, external font service or other asset origin is required

### Requirement: One origin for the interface and API

The server SHALL serve the interface at `GET /`, its HTML readiness fragment at `GET /ui/readiness`, public assets below `/assets/`, and the existing JSON health endpoints on the same configured listener. The browser SHALL use same-origin URLs. An independently deployed frontend or development proxy SHALL NOT be required. The setup document and its assets SHALL remain available while the process is running with an unavailable database.

#### Scenario: Open the application with its database unavailable
- **WHEN** the server is running with valid configuration and the configured database cannot be reached
- **THEN** the browser can load the setup document and assets from the server's origin
- **AND** the readiness check reports the dependency failure without blocking the initial document on database access

#### Scenario: Request an unknown public resource
- **WHEN** a client requests an unknown asset, a directory listing or a path outside the public asset set
- **THEN** the server returns a not-found response without serving a filesystem listing, private files or the setup document as a fallback

### Requirement: Distinct HTML and JSON representations

Existing JSON health routes SHALL retain their paths, status codes, response bodies and cache prevention behavior regardless of browser-specific request headers. The HTML readiness route SHALL return a complete, safe fragment with HTTP 200 for a ready database and HTTP 503 for an unavailable database. HTML documents and readiness fragments SHALL prevent caching of operational state. Dynamic text SHALL be escaped, and unexpected response bodies SHALL NOT be displayed as diagnostic text.

#### Scenario: A CLI request encounters the new web server
- **WHEN** the CLI requests `/health/ready` from the combined server
- **THEN** it receives the existing JSON contract and the same diagnostic outcome as before the migration

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

### Requirement: Interactive controls survive partial updates

Partial page replacement SHALL preserve usable controls, accessible names, keyboard behavior and status announcements. Initialization of newly inserted controls SHALL NOT duplicate handlers or reset unrelated appearance preferences. A status update SHALL NOT leave keyboard focus on a removed element when a stable retry control is available.

#### Scenario: Repeat partial updates using the keyboard
- **WHEN** a user performs several checks and retries with keyboard controls
- **THEN** each activation starts one intended request, focus remains usable, and each final readiness state is announced
- **AND** appearance remains unchanged by the status replacements

#### Scenario: Insert an interactive component after the initial page load
- **WHEN** a partial update inserts a supported interactive control
- **THEN** the control initializes and responds to its documented keyboard interaction
- **AND** subsequent initialization does not attach duplicate action handlers

### Requirement: Reproducible generated assets

The documented server build SHALL generate or verify its templates and browser assets from pinned inputs before packaging the executable. Missing inputs, failed generation or inconsistent generated files SHALL cause a failed build or check instead of a successful executable containing stale assets. Routine setup and builds SHALL NOT fetch an unpinned component release. Required attribution notices SHALL travel with the embedded distribution.

#### Scenario: Build from a clean checkout
- **WHEN** a contributor follows the documented setup and server build commands from a clean checkout
- **THEN** required generation runs in dependency order and produces a server executable containing matching code and browser assets

#### Scenario: Asset generation fails
- **WHEN** a required template or stylesheet fails to generate
- **THEN** the build exits unsuccessfully and does not present an older executable as the successful result of that build

#### Scenario: Check generated source consistency
- **WHEN** a maintained template changes without its checked-in generated source being updated
- **THEN** the consistency check fails without silently rewriting maintained or checked-in generated source
