# Clavis

Clavis is a CLI-first platform by heurema for controlled access to operational
systems by people and agents.

Currently, it provides a Go API and CLI with external PostgreSQL. The old web
application has been removed; the templ/htmx replacement is not served yet.
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
The default API address is `http://127.0.0.1:8080`, with JSON health endpoints at
`/health/live` and `/health/ready`. There is currently no browser UI.

## Commands

| Command | Purpose |
| --- | --- |
| `make build` | Build the server and CLI |
| `make build-cli` | Build only the CLI using Go, without web tools |
| `make generate-web` | Explicitly regenerate checked-in templ Go source |
| `make check-web-generated` | Check template formatting and generated-source consistency without rewriting files |
| `make check` | Run formatting checks, linters, tests, and builds |
| `make lint-go` | Run golangci-lint |
| `make format` | Format maintained Go, templates and JavaScript; regenerate templ Go source |
| `make smoke` | Test the real database, API and CLI, including outage/recovery and cleanup |
| `make test-mutation` | Run Go mutation testing and report survivors |
| `make down` | Stop the database and keep its data |
| `make reset-db` | Delete the local Clavis database and its data |

Browser smoke verification will return with the embedded UI. The current smoke
report explicitly identifies its API/CLI-only scope.

`web/` now holds only pinned development dependencies for CSS, htmx and code
validation. UI source lives in `internal/web/`; commit `.templ` files together
with generated `*_templ.go` files. Copied-source attribution is in source comments,
including upstream copyright and permission notices.

Node.js, pnpm and templ are development tools, not runtime requirements for the
built Go executables. PostgreSQL remains an external server dependency; the CLI
is a separate optional executable.

After building, check the running API with:

```sh
./bin/clavis doctor
```

For a custom API address, add `--server <url>`; the CLI does not load `.env`.
