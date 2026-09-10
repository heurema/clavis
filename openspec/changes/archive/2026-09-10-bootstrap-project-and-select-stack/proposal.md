## Why

The project currently contains the PRD and OpenSpec configuration, but no runnable application or reproducible development environment. A small, verifiable foundation will let subsequent changes add identity, access management, and integrations without repeatedly choosing the repository structure and basic technologies.

## What Changes

- Record the selected technology stack, rationale, compatibility constraints, and deferred integration work in this change's OpenSpec design. Go, React, and Tremor follow the product direction. The backend uses chi, pgx, urfave/cli, caarlos0/env, and Testify; sqlc and Goose are selected for the first persisted domain model, and Gremlins is selected for mutation testing. Use the latest stable releases, record a dated exact-version baseline, and verify compatibility during implementation.
- Establish the frontend foundation with TypeScript 7, Oxlint, TanStack Router, TanStack Query, Ky, and Zod. Use React's built-in APIs for local UI state; Zustand is excluded from the MVP. Select React Hook Form with its Zod resolver, TanStack Table, and Sonner for the first forms, tables, and notifications that need them.
- Establish Clavis in `heurema/clavis` on GitHub, with Go module `github.com/heurema/clavis`, a Go server, the `clavis` CLI, and a React/TypeScript web application. Initialize Git and the empty private remote without pushing any commits; pushing requires a later explicit instruction.
- Provide server liveness and database readiness endpoints, graceful shutdown, environment configuration, and structured operational logging.
- Provide CLI help, version information, and a diagnostic command with predictable JSON output and exit status.
- Provide a minimal Tremor application shell with a file-based root route and real server readiness loaded through the selected Query/Ky client, preserving useful loading, unavailable, and manual-retry states.
- Provide local PostgreSQL for platform metadata infrastructure, reproducible dependency installation, documented development commands, and automated bootstrap checks.
- Keep the README short and focused on getting started. Keep maintained product documentation in `docs/`, technical decisions in OpenSpec, local review and validation notes in ignored `.local/notes/`, and generated reports in ignored `reports/`.
- Provide a separate mutation-testing command for selected handwritten Go logic, with machine-readable results and explicit reporting of survivors and incomplete analysis.
- Keep the change limited to the development foundation. It does not implement authentication, connection grants, external PostgreSQL/VictoriaMetrics providers, persisted audit events, or the product's agent skill. Those remain required MVP work in subsequent changes.

## Capabilities

### New Capabilities

- `project-bootstrap`: A reproducible development environment with buildable server, CLI, and web entry points, observable readiness, a Tremor UI foundation, and repeatable validation commands.

### Modified Capabilities

None. There are no existing application capability specifications.

## Impact

- Planned application areas: `cmd/`, `internal/`, and `web/`.
- Planned supporting files: Go module metadata, frontend package metadata and lockfile, local Compose configuration, environment examples, development commands, and README.
- Backend foundations: Go standard HTTP/logging packages, chi v5, urfave/cli v3, pgx v5, PostgreSQL, caarlos0/env v11, Testify, and Gremlins. sqlc and Goose v3 are recorded choices whose integration begins with the first real database schema.
- Frontend foundations: React, Vite, TypeScript 7, Tremor Raw, Tailwind CSS, Remix Icon, TanStack Router with its Vite plugin, TanStack Query, Ky, Zod, Node.js Current, pnpm, and Oxlint. React Hook Form, its validation resolvers, TanStack Table, and Sonner are recorded selections whose installation begins with the first screens that use them. No separate global state library is required. Exact releases, state responsibilities, and compatibility findings are recorded in the design.
- New unauthenticated endpoints expose only process/dependency readiness. There are no business-data endpoints, authentication bypasses, or external-system credentials in the bootstrap.
- Local PostgreSQL supports the platform itself; it is separate from the future PostgreSQL integration used to query company databases.
- Existing product requirements and OpenSpec configuration are preserved. This proposal introduces no change to the CLI + skill product model or the MVP's access and data-retention boundaries.
