# Clavis

Clavis is a CLI-first platform by heurema for controlled access to operational
systems by people and agents.

Currently, it provides a Go API and CLI, a React setup page, and local PostgreSQL.
Authentication, permissions, and external integrations are planned.

## Quick start

Requires Go **1.27.1**, Node.js **26.8.2**, pnpm **12.3.4**, Docker with Compose,
and GNU Make on macOS or Linux.

```sh
make setup
cp -n .env.example .env
make dev-db
```

In separate terminals, run `make dev-api` and `make dev-web`.
Open [localhost:5173](http://127.0.0.1:5173) to check readiness.
Development commands load settings from `.env`; stop the API and web server
with Ctrl-C.

## Commands

| Command | Purpose |
| --- | --- |
| `make build` | Build the server, CLI, and web app |
| `make check` | Run formatting checks, linters, tests, and builds |
| `make lint-go` | Run golangci-lint |
| `make format` | Format Go and frontend code |
| `make smoke` | Test the real database, API, CLI, and browser together |
| `make test-mutation` | Run Go mutation testing and report survivors |
| `make down` | Stop the database and keep its data |
| `make reset-db` | Delete the local Clavis database and its data |

Run `make setup-browser` once before smoke tests to install Chromium.

After building, check the running API with:

```sh
./bin/clavis doctor
```

For a custom API address, add `--server <url>`; the CLI does not load `.env`.
