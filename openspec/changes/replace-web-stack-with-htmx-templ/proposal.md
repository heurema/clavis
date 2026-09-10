## Why

Clavis needs a minimal administration UI alongside its Go API and CLI, but its current React application requires a separate frontend build and serving arrangement. Replace that foundation while it contains only the setup/status screen, and make the complete server application deployable as one executable.

## What Changes

- Replace React, Vite, TanStack Router/Query, Ky, Zod and Tremor Raw with server-rendered templ components, htmx 4, templUI and Tailwind CSS. Keep JavaScript limited to htmx, the selected component scripts and small application interactions.
- Embed all required browser assets in the Go server binary and serve the UI, assets and existing JSON endpoints from the same listener. Running the built application requires no Node.js, frontend process, asset directory or CDN access.
- Preserve the setup screen's real readiness states, bounded checks, retry behavior, light/dark appearance and keyboard accessibility. Keep existing JSON health responses and CLI behavior compatible.
- **BREAKING:** Replace the independently served web application with the Go-served UI. An already-loaded page can report a lost connection and recover, but a fresh navigation while the server is stopped receives the browser's connection error rather than an independently served Clavis status page.
- **BREAKING:** Replace the Vite development commands, proxy settings and deployable web bundle with one server development path and an embedded-asset build. Retain development-only tooling for CSS, scripts and browser verification where useful.
- Prune the old web application before the replacement is served, as explicitly approved by the user. Intermediate commits may have no browser UI; preserve working API/CLI workflows and identify the temporary API/CLI-only smoke scope. Final browser acceptance requirements remain unchanged.
- Keep PostgreSQL external and the `clavis` CLI independently buildable. “Single binary” means one deployable API-and-web server, not an embedded database or a combined server/CLI command.
- Update maintained stack documentation and validation commands during implementation. This change does not implement authentication, administration screens, providers or audit persistence.

## Capabilities

### New Capabilities

- `embedded-web`: A templ/htmx/templUI interface served with all browser assets from a standalone Go server binary, with explicit HTML/JSON boundaries and reproducible asset generation.

### Modified Capabilities

- `project-bootstrap`: Change build outputs, the web readiness contract under single-process hosting, and smoke verification to exercise the embedded UI directly.

## Impact

- Server: `cmd/server`, `internal/server`, and a dedicated Go web package for templates, copied components and embedded assets. The database lifecycle and CLI JSON contracts remain intact.
- Frontend: replace `web/src`, React-specific dependencies and configuration, route generation and component tests. Retain a small development package for pinned asset tooling and browser tests.
- Tooling: update `Makefile`, setup/dev/check/smoke scripts, generated-code exclusions, dependency metadata and asset provenance. Keep copied-source provenance and required permission notices inline in source comments; do not add a web README, separate notice Markdown files or standalone license files.
- Documentation: update `README.md`, the selected-stack statement in `docs/PRD.md`, and environment examples. The archived bootstrap design remains historical; this change supersedes its React/Vite/Tremor and separate-serving decisions.
