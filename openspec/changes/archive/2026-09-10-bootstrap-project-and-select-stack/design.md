## Context

See `proposal.md` for motivation and `specs/project-bootstrap/spec.md` for the behavior contract. The project has `docs/PRD.md`, OpenSpec configuration, generated agent workflow files, and a local Git repository. It has no application source, package manifests, or database schema.

The selected direction is Go for the server and CLI, a regular React application, and Tremor. The stack discussion selected chi, pgx, sqlc, Goose, caarlos0/env, urfave/cli, Testify, and Gremlins. The frontend selections are TanStack Router, TanStack Query, Ky, Zod, React Hook Form, TanStack Table, and Sonner, with React's built-in APIs for local UI state and no Zustand in the MVP. The user requested the latest stable versions throughout and selected TypeScript 7 with Oxlint after reviewing the typescript-eslint compatibility constraint. The version baseline below records the selected releases and their verification sources. Detailed execution results, reviews, and validation notes remain local and are excluded from version control. The product is Clavis, with repository and CLI name `clavis`, owned by the `heurema` GitHub organization.

## Goals / Non-Goals

**Goals:**

- Establish a small, runnable path from both browser and CLI to the server and its own database.
- Start with the latest stable releases, verify them together, and record exact installed versions when implementing.
- Make the normal development loop explicit and make failure conditions observable from the first executable version.
- Keep shared operational behavior small enough to understand before adding product features.

**Non-Goals:**

- No production deployment topology, hosted service, Kubernetes resources, release publishing, or hosted CI configuration.
- No database application schema, ORM, migration execution, generated query code, provider framework, generated SDK, or authentication implementation yet. Goose and sqlc are selected now and integrated with the first real schema.
- No general dashboard, chart library, workflow editor, embedded agent, or MCP interface.
- No frontend component framework in addition to Tremor. Add only the primitives and libraries used by implemented screens; forms, advanced tables, and toast notifications are selected now but integrated when first needed.

## Decisions

### 1. One repository, one Go module, one frontend package

Use `heurema/clavis` on GitHub, initially private, and a local `main` branch with `origin` set to `git@github.com:heurema/clavis.git`. Repository initialization creates an empty remote only. Do not push commits, branches, or tags until the user explicitly authorizes pushing; bootstrap implementation does not grant that authorization.

Use a root Go module and a `web/` package, with independently buildable server and CLI entry points:

```text
cmd/
  server/
  clavis/
internal/
  config/
  server/
  cli/
  database/
  buildinfo/
web/
  src/
    app/
    routes/
    components/ui/
    lib/
docs/
  PRD.md
openspec/
compose.yaml
Makefile
.env.example
.gitignore
go.mod
go.sum
README.md
```

The Go module path is `github.com/heurema/clavis`. Build outputs are `bin/server`, `bin/clavis`, and `web/dist/`; these are ignored by version control. Use Clavis in the web shell and documentation, and `CLAVIS_` for application environment variables. The CLI calls HTTP endpoints and does not import server configuration or database packages. Do not create empty product/domain packages merely to anticipate future features.

**Alternatives:** Separate repositories would add coordination and versioning work before the first feature. Multiple Go modules or a frontend monorepo orchestrator provide little value for these three entry points.

### 2. Initial stack and version policy

| Area | Selection | Reason / alternative considered |
|---|---|---|
| Server | Go 1.27, standard `net/http` server + chi v5 routing | Chi preserves standard handlers and adds route groups and middleware composition for the planned authenticated/admin API. Standard routing remains adequate, but chi is the selected organization layer. |
| Environment configuration | caarlos0/env v11 | Typed environment parsing with defaults and required fields; application validation still enforces semantic constraints. |
| Operational logs | Standard `log/slog`, JSON output | Structured logs without an additional logging framework. These are service logs, not the future persistent audit trail. |
| CLI | Go + urfave/cli v3 | Nested commands, flags, and help with a standard-library-only core. Cobra is a capable alternative; urfave/cli is the selected lightweight command layer. |
| Platform database | PostgreSQL 18 + pgx v5 connection pool | One shared storage technology for later accounts/configuration/audit; no embedded-database-specific behavior. This is unrelated to the future external PostgreSQL provider. |
| Query generation | sqlc targeting pgx v5; integrated with the first schema | Typed Go methods generated from explicit application SQL. Dynamic queries against external provider databases use a separate execution path. |
| Database migrations | Goose v3 with SQL files; integrated with the first schema | Versioned SQL migrations that sqlc can read as schema input. golang-migrate and Tern are alternatives; Goose is the selected migration tool. |
| Web app | React 19 + TypeScript + Vite 8 | A client-rendered application that can call the Go server; server rendering is not needed for the private administration UI. |
| UI | Tremor Raw source components + Tailwind CSS 4 | Follows the user's visual preference while keeping a modern React/Tailwind baseline. See compatibility details below. |
| Frontend runtime/tools | Node.js 26 Current + pnpm | The latest stable release line follows the user's preference; use frozen dependency installs and one lockfile format. |
| Routing and URL state | TanStack Router with its Vite plugin | File-based routes, typed navigation, and validated search parameters for future administration filters. React Router is an alternative; TanStack Router is the selected client-side router. |
| Server state | TanStack Query | One owner for API data, request state, caching, and invalidation; route loading can coordinate with the same Query client. |
| HTTP requests | Ky over browser `fetch` | Shared request configuration, HTTP errors, JSON, deadlines, and cancellation behind small typed API functions. |
| Local UI state | React `useState`, `useReducer`, and small contexts | Adequate for dialogs and shared appearance preferences. Zustand and other standalone global stores are excluded from the MVP. |
| Validation | Zod | Runtime validation of API responses and URL parameters; form validation when forms are introduced. |
| Forms | React Hook Form + `@hookform/resolvers` with Zod | Field state, validation feedback, and submission behavior; install with the first real form. |
| Tables | TanStack Table + Tremor presentation | Headless sorting, filtering, pagination, and selection with the selected visual layer; install with the first table that needs these behaviors. |
| Notifications | Sonner | Action feedback through toast notifications; install with the first screen that needs toasts. |
| Local infrastructure | Docker Compose for the database; native Go and Vite development processes | Fast edit/reload loops without requiring containerized source builds. |
| Go testing | Standard `testing` + Testify `require`/`assert` + `httptest` | Plain test functions and table-driven cases with readable assertions; small fakes first, optional Testify mocks when interaction expectations help. |
| Mutation testing | Gremlins, a separate pinned development tool | Existing Go tests, JSON reports, file exclusions, and diff filtering; focus on selected handwritten behavior. |
| Other quality checks | golangci-lint (including govet), gofmt; TypeScript 7, Oxlint with type-aware support, Prettier, Vitest + Testing Library; Playwright smoke test | Separate static checks, behavior tests, and one real integration path. |

**Version snapshot — September 9, 2026.** The following are the latest stable releases found in official release feeds and package registries. Version links identify the verification sources. Standard-library packages share the Go version; browser `fetch` has no npm dependency. Tremor Raw is copied source and is pinned by commit instead of an npm version.

| Backend component | Exact baseline |
|---|---|
| Go, including `net/http`, `slog`, `testing`, `httptest`, `gofmt`, and `vet` | [1.27.1](https://go.dev/dl/) |
| `github.com/go-chi/chi/v5` | [5.3.2](https://github.com/go-chi/chi/releases/tag/v5.3.2) |
| `github.com/urfave/cli/v3` | [3.11.0](https://github.com/urfave/cli/releases/tag/v3.11.0) |
| `github.com/jackc/pgx/v5`, including `pgxpool` | [5.11.0](https://github.com/jackc/pgx/releases/tag/v5.11.0) |
| `github.com/caarlos0/env/v11` | [11.4.1](https://github.com/caarlos0/env/releases/tag/v11.4.1) |
| PostgreSQL | [18.6](https://www.postgresql.org/support/versioning/); local image `postgres:18.6@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280` |
| sqlc, selected for the first schema | [1.31.1](https://github.com/sqlc-dev/sqlc/releases/tag/v1.31.1) |
| Goose, selected for the first schema | [3.28.0](https://github.com/pressly/goose/releases/tag/v3.28.0) |
| `github.com/stretchr/testify` | [1.12.1](https://github.com/stretchr/testify/releases/tag/v1.12.1) |
| Gremlins, development executable | [0.6.0](https://github.com/go-gremlins/gremlins/releases/tag/v0.6.0) |
| golangci-lint, development executable added September 10, 2026 | [2.13.2](https://github.com/golangci/golangci-lint/releases/tag/v2.13.2), latest stable verified on that date |

| Frontend component | Exact baseline |
|---|---|
| React / React DOM | [19.3.0](https://registry.npmjs.org/react/latest) / [19.3.0](https://registry.npmjs.org/react-dom/latest) |
| TypeScript | [7.0.2](https://registry.npmjs.org/typescript/latest) |
| Vite / `@vitejs/plugin-react` | [8.2.2](https://registry.npmjs.org/vite/latest) / [6.1.1](https://registry.npmjs.org/@vitejs/plugin-react/latest) |
| Tailwind CSS / `@tailwindcss/vite` | [4.3.3](https://registry.npmjs.org/tailwindcss/latest) / [4.3.3](https://registry.npmjs.org/@tailwindcss/vite/latest) |
| Tremor Raw | Source commit [`ca4d588f47820ff3d514d37fa4ee08a4222dec11`](https://github.com/tremorlabs/tremor/commit/ca4d588f47820ff3d514d37fa4ee08a4222dec11) |
| TanStack Router / `@tanstack/router-plugin` | [1.170.33](https://registry.npmjs.org/@tanstack/react-router/latest) / [1.168.36](https://registry.npmjs.org/@tanstack/router-plugin/latest) |
| TanStack Query | [5.102.8](https://registry.npmjs.org/@tanstack/react-query/latest) |
| Ky | [2.1.0](https://registry.npmjs.org/ky/latest) |
| Zod | [4.6.0](https://registry.npmjs.org/zod/latest) |
| React Hook Form / `@hookform/resolvers`, selected for the first form | [7.87.0](https://registry.npmjs.org/react-hook-form/latest) / [5.9.1](https://registry.npmjs.org/@hookform/resolvers/latest) |
| TanStack Table, selected for the first interactive table | [9.2.4](https://registry.npmjs.org/@tanstack/react-table/latest) |
| Sonner, selected for the first toast notification | [2.0.8](https://registry.npmjs.org/sonner/latest) |
| Oxlint / `oxlint-tsgolint` | [1.82.0](https://registry.npmjs.org/oxlint/latest) / [7.0.2001](https://registry.npmjs.org/oxlint-tsgolint/latest) |
| Prettier | [3.9.6](https://registry.npmjs.org/prettier/latest) |
| Vitest | [5.0.0](https://registry.npmjs.org/vitest/latest) |
| Testing Library React / DOM | [16.3.3](https://registry.npmjs.org/@testing-library/react/latest) / [10.4.1](https://registry.npmjs.org/@testing-library/dom/latest) |
| Testing Library jest-dom / user-event | [7.0.1](https://registry.npmjs.org/@testing-library/jest-dom/latest) / [14.6.7](https://registry.npmjs.org/@testing-library/user-event/latest) |
| jsdom, component-test DOM environment | [30.0.1](https://registry.npmjs.org/jsdom/latest) |
| Playwright Test | [1.63.0](https://registry.npmjs.org/@playwright/test/latest) |
| `@types/react` / `@types/react-dom` | [19.3.0](https://registry.npmjs.org/@types/react/latest) / [19.3.0](https://registry.npmjs.org/@types/react-dom/latest) |
| `@types/node`, matching Node 26 | [26.5.1](https://registry.npmjs.org/@types/node/26.5.1) |

The selected Tremor controls import the following small dependency set. Install a listed primitive only when a copied control uses it; the appearance switch uses the Radix switch primitive.

| Tremor component dependency | Exact baseline |
|---|---|
| `@radix-ui/react-slot` | [1.3.3](https://registry.npmjs.org/@radix-ui/react-slot/latest) |
| `@radix-ui/react-switch` | [1.3.7](https://registry.npmjs.org/@radix-ui/react-switch/latest) |
| `@remixicon/react` | [4.9.0](https://registry.npmjs.org/@remixicon/react/latest) |
| `clsx` | [2.1.1](https://registry.npmjs.org/clsx/latest) |
| `tailwind-merge` | [3.6.0](https://registry.npmjs.org/tailwind-merge/latest) |
| `tailwind-variants` | [3.3.1](https://registry.npmjs.org/tailwind-variants/latest) |

| Development tool | Latest stable reference |
|---|---|
| Node.js | [26.8.2 Current](https://nodejs.org/en/download) |
| pnpm | [12.3.4](https://registry.npmjs.org/pnpm/latest) |
| Docker Engine | [29.8.0](https://github.com/moby/moby/releases/tag/docker-v29.8.0) |
| Docker Compose | [5.5.1](https://github.com/docker/compose/releases/tag/v5.5.1) |
| GNU Make | [4.4.1](https://ftp.gnu.org/gnu/make/) |
| OpenSpec | [1.12.0](https://registry.npmjs.org/@fission-ai/openspec/latest), already installed |

**Release policy:** Latest means a stable, non-prerelease release at the time the baseline is chosen. Node 26.8.2 is the latest Current release; Node 24.21.0 remains the latest LTS but is not this baseline. PostgreSQL 19 beta releases are excluded. For packages with unusual registry tags, inspect stable versions as well as `latest`: `@types/node` 26.5.1 matches Node 26 even though its registry `latest` tag points to the 22.x line. Host tools are documented prerequisites, not automatic global upgrades; on macOS, document the GNU Make executable if it is exposed as `gmake`.

Recheck the snapshot when implementation begins, record any newly selected releases, and commit exact runtime/package-manager versions, Go module metadata, `go.sum`, and `web/pnpm-lock.yaml`. Pin direct frontend dependencies and the PostgreSQL image version/digest; use frozen frontend installation. Resolve transitive dependencies within supported ranges and retain their lockfile resolutions. Do not use floating `latest` tags in committed build or runtime configuration. Routine setup reproduces the committed baseline instead of upgrading it on every run. Major-version or UI-distribution changes require a design revision; routine compatible patch updates do not change the behavior spec.

**Compatibility findings:** All inspected Go modules declare minimum Go versions at or below 1.26, so Go 1.27.1 meets their declared minimums. Current Vite, its React/Tailwind plugins, Vitest, jsdom, Testing Library, and the selected Radix packages admit the selected runtime/React major in their engine or peer ranges. The checked TanStack Router/plugin, Query, Table, Ky, React Hook Form/resolvers, Zod, and Sonner metadata does not declare a peer/engine conflict with the chosen React 19, Node 26, and TypeScript 7 baseline. Router and its plugin have different release numbers; the selected plugin's router peer range admits the selected router version. These declarations are not evidence that the assembled application has already passed installation, type checking, rendering, or tests. Verify each selected library when it enters the application. In particular, Gremlins must complete a real mutation run with Go 1.27.1 before the bootstrap task is complete.

**TypeScript 7 linting decision:** The checked [typescript-eslint 8.70.0 metadata](https://registry.npmjs.org/typescript-eslint/latest) restricts its TypeScript peer to `>=4.8.4 <6.1.0`. The user chose the latest TypeScript 7 with Oxlint. Replace the earlier ESLint proposal with Oxlint 1.82.0 and its `oxlint-tsgolint` 7.0.2001 companion for [type-aware linting](https://oxc.rs/docs/guide/usage/linter/type-aware), which supports the TypeScript 7 baseline. Configure applicable TypeScript/React rules, retain a separate compiler type check, and use Prettier for formatting. Do not bypass peer constraints or silently downgrade TypeScript. Any compatibility failure must be resolved and recorded before claiming a working baseline.

**TypeScript declaration compatibility:** The selected Vitest 5 declarations reference unresolved vendor types, so TypeScript uses `skipLibCheck`. This skips dependency declaration internals; strict compiler checks still cover application source, tests, generated routes, and configuration. Runtime tests and type-aware Oxlint run separately. No peer override or TypeScript downgrade is needed.

**Gremlins compatibility:** Gremlins 0.6.0 constructs an invalid single `-cpu 1` argument when `--test-cpu` is nonzero and misclassifies the resulting Go failures as detected mutations. Use `--test-cpu 0` with `GOMAXPROCS=1` and two workers. Before application analysis, require a compatibility probe to distinguish a detected negation from a surviving boundary mutation. Keep mutation outcomes and reviewed survivors in ignored local reports and notes.

**Selected database tools, deferred integration:** Goose 3.28.0 and sqlc 1.31.1 are recorded now; their configuration, migration execution, and generated query code will be introduced with the first persisted domain model, with versions rechecked then. Use SQL schema migrations as sqlc's schema input, keep applied migrations immutable, and apply them through an explicit deployment step. Goose can use pgx's `database/sql` adapter while application queries continue using native pgxpool. These migrations affect only the platform's own database. Bootstrap readiness uses pgx directly and needs no placeholder tables or queries.

**Selected frontend tools, deferred integration:** React Hook Form 7.87.0, `@hookform/resolvers` 5.9.1, TanStack Table 9.2.4, and Sonner 2.0.8 are decided. Keep these versions recorded in this design and recheck them when their first screens are implemented; do not install them or create placeholder forms, tables, or notifications during bootstrap. Remix Icon is already used by the selected Tremor Button.

**Deferred selections:** OAuth/OIDC libraries, session storage, credential encryption, provider execution, and audit persistence need their own designs. Generated API clients remain deferred until the API contract is defined. The checked [openapi-typescript 7.13.0 metadata](https://registry.npmjs.org/openapi-typescript/latest) declares a TypeScript `^5.x` peer dependency, so it is not part of this TypeScript 7 baseline. This does not reject OpenAPI as a future contract format. The bootstrap uses small typed API functions with Zod runtime validation and installs no speculative authentication or generation dependencies.

### 3. Use Tremor Raw with Tailwind 4

Use the free source components from `tremorlabs/tremor`, added under `web/src/components/ui/`. The checked repository head is `ca4d588f47820ff3d514d37fa4ee08a4222dec11` (October 10, 2025). Start with only the components used by the setup screen: Button, Card, Badge, Callout, and Switch for appearance selection, plus their shared utilities. Record each upstream source URL and commit, retain required notices, and keep local styling changes in the shared component layer. Use a system font initially; do not make runtime font downloads a dependency of the application.

There are two different Tremor distributions. The current Raw installation page specifies React 18.2+ and Tailwind 4+. The published `@tremor/react` 3.18.7 package declares a React `^18.0.0` peer dependency, and its setup instructions use Tailwind 3. The Raw Vite guide is also marked as awaiting an update and still contains Tailwind 3 steps. Therefore use current Vite/Tailwind 4 installation instructions with current Raw source components, rather than combining snippets from the two installation paths.

The upstream demo package still uses React 18 and tailwind-variants 1; it is not the application's dependency manifest. Copy the narrow component set and adapt its source where required for the selected React 19 and tailwind-variants 3 releases. Before building the shell, verify that the components compile and render with the pinned React/Tailwind versions, have visible keyboard focus, and work in light/dark appearance. Add only their actual imported dependencies. Do not add Recharts, data grids, paid templates, or the complete Tremor dependency list during bootstrap.

**Alternatives:** The npm package with React 18/Tailwind 3 is a viable different baseline, but would deliberately choose older major versions. Mantine and shadcn/ui were considered in the preceding discussion; the user's Tremor preference determines the visual foundation for this proposal. The Raw route means the project maintains its copied component code and reviews upstream changes explicitly.

### 4. Small server lifecycle and readiness contract

Parse server environment configuration into a typed struct using `caarlos0/env/v11`, followed by explicit validation of addresses, connection settings, log levels, and positive durations. Require a non-empty database URL without a default. Map parsing/validation errors to safe field names and categories instead of logging raw library errors or the configuration struct. Loading a local `.env` file remains the development command's responsibility.

The configuration contract is:

| Setting | Default / rule |
|---|---|
| `CLAVIS_HTTP_ADDR` | `127.0.0.1:8080` |
| `CLAVIS_DATABASE_URL` | Required; never logged or returned |
| `CLAVIS_DB_CHECK_TIMEOUT` | `2s`; positive duration |
| `CLAVIS_SHUTDOWN_TIMEOUT` | `10s`; positive duration |
| `CLAVIS_LOG_LEVEL` | `info`; validated known level |

Missing/malformed settings fail before listening. A valid connection string pointing at a temporarily unavailable database does not prevent the HTTP server from starting. Use a pool configured without an eager startup ping; readiness performs a bounded ping using the request context and database-check timeout. Each request checks current readiness so that recovery is visible without a process restart.

Register health routes on chi while keeping handlers and middleware as standard `http.Handler` values. Grouping future routes can compose authentication and authorization middleware without changing the handler model; no identity or permission middleware is implemented in this bootstrap. Retain the allowed-field logging policy rather than adopting request logging that prints raw URLs.

Use the success responses specified in the delta spec. The complete 503 response is `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Database unavailable"}}`. Set JSON content type and disable caching for readiness. Configure finite HTTP read/header/write/idle timeouts, with the write timeout longer than the database-check bound. On termination, stop accepting work, drain within the shutdown bound, cancel remaining work, and close the pool.

Use a small logging wrapper with allowed fields such as severity, message, known route, method, status, duration, and error category. Do not log a raw request URL, arbitrary query values, connection configuration, request/response bodies, or raw dependency errors. Health endpoints are public only because their response contains no application data; they do not establish any future authorization convention.

**Alternatives:** Returning a single health state would make a database outage indistinguishable from a dead process. Requiring database connectivity before binding would prevent local readiness diagnostics from explaining startup dependency failures.

### 5. CLI foundation validates the future agent interface style

Use `urfave/cli/v3` for the `clavis` executable, with `help`, `version`, and `doctor`. Its nested command model supports the future `clavis command subcommand` shape; those additional product commands are outside bootstrap scope. Version is local build metadata with `dev`/`unknown` defaults for unversioned builds. The diagnostic command calls `/health/ready`; it never receives or reads the platform database URL.

Use `--server` with precedence over `CLAVIS_SERVER_URL`, then `http://127.0.0.1:8080`. Accept an HTTP(S) base URL without embedded credentials, query, or fragment. Use `--timeout` with a default of `5s`; it covers the entire request and response read. Bound health response reads to 64 KiB, validate the status/body pair, and discard unexpected bodies from diagnostics.

`--output=json` is the default for version/doctor/errors. `--output=text` is an optional human-readable rendering of the same result. Explicit help is conventional text. Invalid invocation always uses the default JSON error format, including an unsupported output-format argument. Configure urfave/cli's usage/error/exit handling and writers so all operational and parsing failures pass through one result writer and one process-exit mapping. Preserve one JSON document on stdout; do not allow automatic help, suggestions, or logging to corrupt it. Commands never prompt for missing operational input.

Use the version 1 envelope and exit codes in the spec. Doctor data uses `api: reachable|unreachable|unknown` and `database: ready|unavailable|unknown`. A response-format error has `api: reachable` and `database: unknown`; timeout has `api: unknown` and `database: unknown`; a connection failure has `api: unreachable` and `database: unknown`. Invalid arguments have `data: null`. Error objects contain a stable `code` and safe `message`.

**Alternatives:** Human-only output would defer the most important CLI interaction contract. Generating SDKs or defining every future command would lock in API behavior before identity and provider requirements are designed. This envelope is a bootstrap convention to evaluate, not a declaration that every future provider response is already specified.

### 6. A real setup screen using the selected frontend stack

Create one page at `/` with a small navigation/header shell and a main setup/status card. Show server/database readiness, retry, and local CLI usage guidance. Use TanStack Router with a root layout and index route under `web/src/routes/`. The Vite router plugin generates the route tree as an ignored build artifact; ensure generation completes before compiler checks on a clean workspace. Exclude generated route code from manual formatting/linting while retaining it in compiler and build validation. Generation may write build artifacts, but checks must not rewrite handwritten source. Do not include fabricated users, integration counts, metrics, extra business routes, or functional-looking controls for unimplemented features.

Create one TanStack Query client for the browser application and use it for the readiness query. The query calls a small API function through a shared Ky client, with Zod schemas validating the response. Keep HTTP details in `web/src/lib/`; components consume the query's data and request state. Do not copy query results into React context or another store. The bootstrap route does not independently preload readiness; later route loaders can coordinate through the same Query client when preloading is useful.

Request `/health/ready` through Vite's development proxy. Configure the proxy using a server-side development setting with a default target of `http://127.0.0.1:8080`; never put the database URL or any secret in `VITE_*` variables. A five-second request deadline covers the response body as well as connection time. Forward Query cancellation through Ky and ensure a superseded response cannot overwrite the latest result. A valid documented 503 is a dependency-unavailable result; inspect that status/body pair before Ky's generic HTTP-error handling can hide it. Unexpected status/body combinations and schema failures become safe diagnostic errors without rendering or logging raw responses or validation errors.

Ky retries are disabled. TanStack Query owns retry policy; the bootstrap readiness query also disables automatic retries, polling, and focus/reconnect refetches. Check readiness on page entry and explicit Retry, showing a checking state while the fresh check is pending instead of treating a cached ready result as current evidence. Cancel or supersede an outstanding check before retrying. Later administration reads can define bounded retry/freshness policies; administrative mutations and 401/403 responses have no automatic retries by default.

State responsibilities for the MVP are:

| State | Owner |
|---|---|
| Server responses: users, connections, permissions, audit records | TanStack Query |
| Shareable filters, sorting, pagination, selected resource | TanStack Router URL state, validated at the route boundary |
| Form values, dirty state, and validation feedback | React Hook Form with Zod through `@hookform/resolvers`, introduced with forms |
| Component-local dialogs, menus, and temporary selections | React `useState` / `useReducer` |
| Shared appearance preference | A small React context using local state |

No Zustand, Redux, or other standalone global store is required. Revisit that decision only when a concrete feature needs substantial shared client state. Keep Query caches in memory; persistent UI preferences are limited to non-sensitive appearance/layout settings. Future identity work must clear user-scoped cache state on logout/account changes; frontend cache or route state never grants backend permissions.

Follow the operating-system appearance initially and persist an explicit light/dark selection locally. Status labels and explanatory text supplement colors. Ensure keyboard access, visible focus, accessible names, and loading announcements for these controls. Later screens use React Hook Form for forms, TanStack Table for table behavior with Tremor presentation, and Sonner for action notifications. Bootstrap readiness remains visible inline and does not require a toast library.

The frontend builds static assets. Vite is a development tool, and its preview server is used only for local verification. How assets are served in production is deliberately outside this change; do not add a Next.js server, Go asset embedding, or a production reverse proxy now.

**Alternatives:** React Router's Data mode can support this SPA; TanStack Router is selected for typed navigation/search parameters and coordination with Query. Plain `fetch` would suffice for one endpoint, but Ky establishes shared HTTP handling for the administration API. Query handles the server-data lifecycle without a second store. Zustand would be reasonable for substantial shared client state, but the MVP's identified UI state is covered by React, the router, Query, and forms. These decisions keep the frontend a React/Vite SPA calling Go; they do not introduce TanStack Start or server rendering.

### 7. Local development and validation commands

Keep the README short: purpose and current scope, prerequisites, quick start, essential commands, and one CLI example. Include explicit browser setup and explain that resetting the local database deletes its data. Keep detailed stack choices and tool behavior in OpenSpec; `docs/` contains maintained product and project documentation. Store review results, validation notes, and scratch files in `.local/notes/`, and generated tool reports in `reports/`. Both local directories are Git-ignored and must not contain tracked files. Do not append execution histories or review reports to the README, maintained docs, or design artifacts.

Use Compose only for a dedicated `clavis` development database, with a named volume and a loopback port binding. Make the database port configurable to avoid clashing with an existing local PostgreSQL. Provide `.env.example` with clearly local-only credentials and document creating a git-ignored `.env`. Development commands load that file without printing its values; the Go executable itself reads its process environment. Document prerequisites for macOS and Linux, the two environments targeted by this local setup.

Use the pinned golangci-lint release for Go static analysis, including tests.
Keep its standard errcheck, govet, ineffassign, staticcheck and unused linters;
do not enable every optional style rule. Install official release binaries
under `.tools` after checking pinned SHA-256 hashes. Bound analysis to three
minutes and two workers, keep module metadata read-only, and exclude generated
source by Go's standard marker. A lint failure stops ordinary quality checks.

Expose these root commands:

| Command | Behavior |
|---|---|
| `make setup` | Check documented toolchain versions, install Go/frontend dependencies using committed resolutions, and install the pinned golangci-lint locally; no global tool installation or shell reconfiguration |
| `make dev-db` | Start the local database |
| `make dev-api` | Start the Go server using local environment settings |
| `make dev-web` | Start Vite on loopback with a configured API proxy |
| `make build` | Build both Go executables and the web bundle |
| `make check` | Check formatting, run golangci-lint (including govet), Go tests, frontend lint/type checks/tests, and production builds; do not rewrite source during checks |
| `make lint-go` | Run the pinned golangci-lint against all Go packages and tests |
| `make test-mutation` | Run Gremlins against selected handwritten Go logic, separately from `make check` and `make smoke`, and write a JSON report |
| `make smoke` | Run an isolated database/server/browser/CLI smoke test with bounded startup waits |
| `make down` | Stop local Compose resources without deleting the development volume |
| `make reset-db` | Explicitly delete only this project's development database volume; document that this loses its local data |

The smoke runner creates its own Compose project name and temporary database volume, chooses available host ports once and retains the database binding across restart, starts the compiled API and a local frontend server, and cleans up those resources using an exit trap. It must not reuse or reset the normal development database. Use Playwright for real browser loading/readiness/retry and keyboard/appearance checks, and Go tests or the smoke runner for dependency failure/recovery and CLI behavior. Installing Playwright's browser binaries is an explicit documented setup step, not an implicit system package-manager operation.

Use ordinary Go test functions and table-driven cases, with Testify `require` for prerequisites and `assert` for independent outcomes. Keep fatal assertions in the test's goroutine. Use `httptest` and small fakes for fast tests of invalid configuration, malformed HTTP responses, timeouts, and output redaction; use Testify mocks only where call expectations add useful evidence. The real smoke path verifies database readiness, CLI JSON/exit codes, frontend readiness, and recovery after the temporary database stops and restarts. Later SQL/migration integration tests run against real PostgreSQL. Test lifecycle and error contracts; do not add snapshot tests for every copied visual component.

**Alternatives:** A full application Compose stack adds image-build overhead to ordinary editing. Git hosting is GitHub under `heurema`; CI remains a separate decision. The non-interactive commands provide future CI entry points without adding hosted workflows now.

### 8. Focused mutation testing with Gremlins

Use Gremlins 0.6.0 as a repository-pinned development executable, installed locally without modifying global tools. Bootstrap must demonstrate a complete mutation run on real application tests before considering this task complete; an incompatible tool or failed analysis is a visible failure, never a skipped success.

Run `make test-mutation` from the module root against configuration validation, CLI diagnostics/error handling, and server readiness interpretation. Configure file exclusions to limit mutation targets to those areas and exclude test files, generated files, and future sqlc output. Document the exact target/exclusion patterns. `--coverpkg` controls coverage analysis and is not a substitute for target selection. Permission checks and connection access become additional targets in their respective future changes.

Use existing Go/Testify tests with ordinary package-level execution. The mutation command does not start the database or browser smoke stack. Bound workers to two by default and the overall run to ten minutes, with documented positive overrides; retain bounded per-mutant execution. Allow cancellation and clean up only the run's temporary resources. Mutation execution must not leave changed application source behind.

Write a fresh machine-readable report under the ignored `reports/` directory, with locations and the native detected/surviving/uncovered/timed-out/non-viable outcomes. Ensure failed or partial runs cannot leave an older report appearing to be the successful current result. Report an empty eligible scope explicitly. Start in reporting mode: a completed analysis may succeed with surviving mutants; baseline failures, tool failures, and an overall timeout exit nonzero. A per-mutant timeout remains distinguishable from an assertion detecting a mutation.

Review survivors to identify missing assertions and equivalent mutations before defining numerical thresholds in a later change. Keep the initial report in ignored `reports/` and reviewed observations in ignored `.local/notes/`; do not claim test effectiveness from an empty run. Gremlins supports JSON output, exclusions, and thresholds; git-diff filtering is available for future CI once the repository and base reference are defined. Keep its mutation analysis separate from normal fast checks and database/browser smoke checks.

**Alternatives:** go-mutesting and its successor forks were considered. Gremlins provides the selected local workflow and report controls without requiring a different test framework. The tool's pre-1.0 status makes version pinning and a real compatibility check part of the bootstrap work.

### 9. Keep the product boundaries intact

The database infrastructure introduced here stores no application entities yet. Do not invent placeholder migrations or user tables solely to demonstrate a connection. Operational logs are transient service output; persisted user-attributed audit events will be introduced with identity and operation execution. No handler bypasses future authorization because the only routes in this change are health routes.

The following changes should cover identity and sessions (including local, optional Google, and generic OIDC), grants and connections, external provider execution and audit, then the user-facing agent skill. Each needs a separate reviewed behavior contract. Bootstrap completion does not imply completion of any of those MVP capabilities.

## Risks / Trade-offs

- **Tremor documentation mixes installation generations** -> Use current Raw components and official Tailwind 4/Vite setup; verify the small selected component set before building the shell. Record source provenance and tested versions.
- **Source components require local maintenance** -> Keep a narrow shared UI layer and avoid copying unused components. Review upstream updates deliberately.
- **Router, Query, and HTTP defaults can duplicate requests or hide readiness failures** -> Keep one Query client, disable Ky retries and readiness background refetching, validate the documented 503 explicitly, and test cancellation and manual recovery through the real client.
- **Latest stable releases may differ from a contributor's machine and lack ecosystem support** -> Pin and document the baseline, verify the real build and tests, fail setup clearly for incompatible versions, and do not change global runtimes automatically. Node Current has a shorter support window than LTS and needs a deliberate future update.
- **Health checks expose dependency availability** -> Keep responses minimal and default local bindings to loopback. Authentication and production network exposure require later designs.
- **A shared database direction could be mistaken for an implemented storage model** -> Limit this change to the pool and readiness; integrate the selected Goose/sqlc tools with the first persistent feature.
- **Mutation analysis can be slow or incompatible with a newer Go toolchain** -> Pin and verify Gremlins on real tests, use a narrow target scope and resource bounds, and surface failed/incomplete runs clearly.
- **Local smoke tests need a container engine and browser binaries** -> Keep fast checks independent and document the additional smoke prerequisites and bounded cleanup.

## Migration Plan

There is no existing application or schema to migrate. Implementation adds the foundation alongside the existing PRD and OpenSpec files, documents the selected stack, and verifies the clean-setup path. The authorized repository setup is local Git and an empty private `heurema/clavis` remote. Do not push repository contents, publish an image, or deploy a service as part of this change.

Rollback consists of reverting the bootstrap application files and stopping its local processes. Preserve the normal development volume unless explicit local reset is desired. There are no production data changes.

## Open Questions

- CI provider and workflow configuration; the bootstrap's validation commands are independent of that selection.
- Production distribution and static-asset serving; this change provides build outputs and a local development path only.

## References

- [Go releases](https://go.dev/dl/)
- [Node.js release policy](https://nodejs.org/en/about/previous-releases)
- [PostgreSQL version support](https://www.postgresql.org/support/versioning/)
- [Chi](https://github.com/go-chi/chi)
- [urfave/cli v3 subcommands](https://cli.urfave.org/v3/examples/subcommands/basics/)
- [caarlos0/env](https://github.com/caarlos0/env)
- [pgx](https://github.com/jackc/pgx)
- [sqlc migration parsing](https://docs.sqlc.dev/en/latest/howto/ddl.html)
- [Goose](https://github.com/pressly/goose)
- [pgx database/sql adapter](https://pkg.go.dev/github.com/jackc/pgx/v5/stdlib)
- [Testify](https://github.com/stretchr/testify)
- [Gremlins](https://github.com/go-gremlins/gremlins)
- [Gremlins command and report options](https://gremlins.dev/latest/usage/commands/unleash/)
- [Vite getting started](https://vite.dev/guide/)
- [TanStack Router type safety](https://tanstack.com/router/latest/docs/guide/type-safety)
- [TanStack Router external data loading](https://tanstack.com/router/latest/docs/guide/external-data-loading)
- [TanStack Query and client state](https://tanstack.com/query/latest/docs/framework/react/guides/does-this-replace-client-state)
- [Ky](https://github.com/sindresorhus/ky/tree/v2.1.0)
- [React Hook Form](https://github.com/react-hook-form/react-hook-form)
- [Zod](https://github.com/colinhacks/zod)
- [TanStack Table](https://github.com/TanStack/table)
- [Sonner](https://github.com/emilkowalski/sonner)
- [Tailwind CSS with Vite](https://tailwindcss.com/docs/installation/using-vite)
- [Tremor Raw installation](https://www.tremor.so/docs/getting-started/installation)
- [Tremor Vite guide with older Tailwind steps](https://www.tremor.so/docs/getting-started/installation/vite)
- [Tremor source repository](https://github.com/tremorlabs/tremor)
- [Published Tremor package metadata, including peer dependencies](https://registry.npmjs.org/@tremor/react/3.18.7)

Version numbers above were checked against official release feeds and package metadata on September 9, 2026. The design distinguishes installed dependencies from deferred selections; execution records remain in ignored local notes and reports.
