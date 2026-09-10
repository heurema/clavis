# Clavis

Clavis is a CLI-first platform by heurema for controlled access to operational
systems by people and agents.

Currently, it provides a Go API and CLI with external PostgreSQL, plus an
embedded templ/htmx setup page with readiness checks, in-page retry and light/dark
appearance. There is no separate frontend server or deployable web bundle.
Authentication, permissions, and external integrations are planned.

## Quick start

Requires Go **1.27.1**, Node.js **26.8.2**, pnpm **12.3.4**, Docker with Compose,
and GNU Make on macOS or Linux.

```sh
make setup
cp -n .env.example .env
make dev-db
```

Run `make dev` to build and start the Go server (`make dev-api` is an alias).
Development commands load `.env` as data, not shell code; existing environment
values take precedence. Stop the server with Ctrl-C. There is no file watcher:
after editing Go or browser scripts/styles, stop and rerun `make dev`. After
editing `.templ` files, run `make generate-web` before restarting.
Open `http://127.0.0.1:8080` for the setup page.
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
| `make check` | Run non-mutating source checks, linters, tests, and builds |
| `make test-web` | Build the server and run Chromium behavior/layout tests |
| `make lint-go` | Run golangci-lint |
| `make format` | Format maintained Go, templates and JavaScript; regenerate templ Go source |
| `make smoke` | Test the standalone server in Chromium with real database/API/CLI outage, recovery and cleanup |
| `make test-mutation` | Prepare embedded inputs, run isolated Go mutation testing and report survivors |
| `make down` | Stop the database and keep its data |
| `make reset-db` | Delete the local Clavis database and its data |

`make setup` installs pinned Playwright Chromium under `.tools/playwright`.
`make test-web` exercises the built server, with controlled readiness responses
for deadlines, stalled bodies, cancellation and safe failure handling. It also
checks appearance, keyboard controls and desktop/mobile layouts. Screenshots and
traces are written under ignored `reports/`.

`make smoke` copies only the server executable into a fresh temporary directory
and runs it there with an empty executable search path. Chromium, JSON health
requests and the CLI use that server's origin; third-party browser requests are
blocked. It verifies embedded assets, notices, keyboard controls and appearance,
then stops/restarts an isolated PostgreSQL database and the copied server.
The loaded page must recover through explicit retry without a reload. The runner
has a 180-second execution deadline, followed by cleanup of its own resources.
It leaves existing development processes, database containers and volumes alone.
Logs, screenshots, a browser trace and `smoke-summary.json` go under `reports/`.

To exercise failure cleanup, run `CLAVIS_SMOKE_FAIL=after-start make smoke` or
`CLAVIS_SMOKE_FAIL=after-restart make smoke`. These deliberately exit nonzero;
the summary must still report `"cleanup": "passed"`, removed temporary runtime
files and stopped server processes. The second case covers the restarted server.

`make test-mutation` checks generated templates and prepares assets before
copying Go sources and embedded inputs into an isolated temporary directory.
It targets handwritten configuration, CLI, server and web behavior, excluding
generated templates, copied UI components and test fixtures. A compatibility
probe must distinguish a known detected mutation from a known survivor before
the application run is accepted. Results and survivors go to ignored
`reports/mutation-summary.json` and `reports/mutations.json`; a completed run
is not a claim that every mutation was detected. Tool failures or the default
600-second deadline return nonzero. Optional `CLAVIS_MUTATION_WORKERS` and
`CLAVIS_MUTATION_TIMEOUT_SECONDS` adjust concurrency and the execution bound.

`web/` holds pinned development dependencies, styles, application scripts and
browser tests, not a separately deployed application. UI source lives in
`internal/web/`; commit `.templ` files together
with generated `*_templ.go` files. Copied-source attribution is in source comments,
including upstream copyright and permission notices; the build packages those
notices at `/assets/notices.txt`.

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
Checks run on page entry and explicit retry, not polling or focus/reconnect.
Each check has a five-second deadline including body reads; a new retry cancels
the previous check. HTML readiness at `/ui/readiness` returns 200 or a safe 503
fragment. Only recognized HTML responses can replace the status region.

An already-loaded page can report server loss and recover through retry once the
server returns. If the Go server is stopped, fresh navigation receives the
browser's connection error; there is no independent frontend or offline fallback.
Appearance is the only persisted browser preference (`clavis.appearance`); with
storage blocked, the switch still works for the lifetime of the loaded page.

After building, check the running API with:

```sh
./bin/clavis doctor
```

For a custom API address, add `--server <url>`; the CLI does not load `.env`.

## OpenSpec workflow

Use the standard `spec-driven` schema and the policy in
[`openspec/config.yaml`](openspec/config.yaml), regardless of agent tool.
Relevant maintained specs plus the change's explicit, approved deltas define the
requirements; an omitted architectural decision is not an approved departure.
The repository instruction files direct agents to read that policy themselves:
some CLI builds return artifact rules but omit context and operation guidance
from apply instructions. Do not assume that a successful CLI call delivered them.

1. **Plan and reconcile.** Review the proposal, inherited decisions, scenarios,
   slice ownership and dependencies before implementation.
2. **Assign a bounded slice.** Invoke the apply workflow with an explicit request:
   “Implement slice 2 of `<change>` only, run its checks, and stop for independent
   review. Leave acceptance and later slices untouched.” Parallel workers are
   optional; without delegation, execute sequentially.
3. **Review independently.** Give a fresh agent context or human reviewer the
   exact code revision, referenced maintained requirements, delta specs, design,
   and test evidence. Review correctness, failure scenarios and conventions.
   The coordinator records implementation and acceptance-review tasks separately;
   workers do not self-approve. Resolve findings and re-review affected code before
   dependent work. Store detailed results in the conversation or ignored `reports/`,
   not in tracked review ledgers.
4. **Verify and finish.** After slice reviews and integration checks, run
   `/opsx:verify <change>` (Claude command) or the `openspec-verify-change` skill
   in a fresh review context, explicitly including inherited requirements.
   Resolve requirement violations even when reported as warnings, then obtain
   owner acceptance before sync/archive.

Native verification is change-wide, not a per-task review command. It may report
unfinished tasks as critical, but neither its report nor a task checkbox enforces
approval or blocks the archive CLI. Configuration is prompt-level guidance:
confirm that the agent stops at the requested boundary during a single-slice
pilot before relying on parallel operation. Keep normal lint, generation,
architectural and test checks; model review is not a substitute for them.

The native verify integrations are checked in alongside the core workflows.
Before regenerating OpenSpec integrations, use `openspec config profile` to keep
the core workflows and add `verify`, then run `openspec update`. Profile selection
is machine-global; regenerating with core alone can remove optional integrations.
Codex command generation also writes global prompts under `~/.codex/prompts/`
(or `CODEX_HOME`); review existing customizations before regenerating.
See OpenSpec's [configuration](https://openspec.dev/docs/project-config) and
[profiles](https://openspec.dev/docs/profiles) documentation.
