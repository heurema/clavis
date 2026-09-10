# Clavis

Clavis is a CLI-first platform by heurema for controlled access to operational
systems by people and agents.

Currently, it provides a Go API and CLI with external PostgreSQL, plus a minimal
server-rendered setup page. The old web application has been removed; automatic
readiness checks, in-page retry and appearance controls are still being rebuilt.
Authentication, permissions, and external integrations are planned.

## Quick start

Requires Go **1.27.1**, Node.js **26.8.2**, pnpm **12.3.4**, Docker with Compose,
and GNU Make on macOS or Linux.

```sh
make setup
cp -n .env.example .env
make dev-db
```

Run `make dev` to start the Go server (`make dev-api` remains an alias).
Development commands load settings from `.env`; stop the server with Ctrl-C.
Open `http://127.0.0.1:8080` for the setup page and its readiness link.
The same server exposes JSON health endpoints at `/health/live` and
`/health/ready`, independently of HTML rendering.

## Commands

| Command | Purpose |
| --- | --- |
| `make build` | Build the server and CLI |
| `make build-server` | Verify generated templates, rebuild embedded assets and build the server |
| `make build-cli` | Build only the CLI using Go, without web tools |
| `make generate-web` | Explicitly regenerate checked-in templ Go source and ignored assets |
| `make build-web-assets` | Rebuild only ignored CSS, scripts and embedded attribution notices |
| `make check-web-generated` | Check template formatting and generated-source consistency without rewriting files |
| `make check` | Run formatting checks, linters, tests, and builds |
| `make lint-go` | Run golangci-lint |
| `make format` | Format maintained Go, templates and JavaScript; regenerate templ Go source |
| `make smoke` | Test the real database, API and CLI, including outage/recovery and cleanup |
| `make test-mutation` | Run Go mutation testing and report survivors |
| `make down` | Stop the database and keep its data |
| `make reset-db` | Delete the local Clavis database and its data |

Browser smoke verification will return with the interactive setup page. The
current smoke report explicitly identifies its API/CLI-only scope. Build tests
already run a copied server in an otherwise empty directory without frontend
tools and verify its HTML, assets and JSON endpoints.

`web/` now holds only pinned development dependencies for CSS, htmx and code
validation. UI source lives in `internal/web/`; commit `.templ` files together
with generated `*_templ.go` files. Copied-source attribution is in source comments,
including upstream copyright and permission notices.

Node.js, pnpm and templ are development tools, not runtime requirements for the
built Go executables. `make build-server` uses `CGO_ENABLED=0`; copy `bin/server`
alone to a compatible OS/architecture and run it from any directory with
`CLAVIS_DATABASE_URL` and optional settings from `.env.example` supplied in its
environment. The executable does not load `.env`. PostgreSQL remains an external
server dependency; the CLI is a separate optional executable.

Builds publish binaries only after successful compilation. A failed build returns
nonzero and leaves any previous binary untouched; do not deploy it as a new build.
Missing or stale generated templates fail the server build without rewriting them.
Run `make generate-web` explicitly after editing templates.

The setup document and assets remain available when PostgreSQL is unavailable.
HTML readiness at `/ui/readiness` returns 200 or a safe 503 fragment. If the Go
server is stopped, fresh navigation receives the browser's connection error;
there is no independent frontend or offline fallback.

After building, check the running API with:

```sh
./bin/clavis doctor
```

For a custom API address, add `--server <url>`; the CLI does not load `.env`.
