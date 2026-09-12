# Clavis

Clavis is a CLI-first platform by heurema for controlled access to operational
systems by people and agents.

Currently, it provides automated initial administrator setup, local browser/CLI
sign-in, revocable sessions, administrator-managed local users and registered
data-source connections with encrypted credentials and connectivity checks, with
external PostgreSQL. Goose manages embedded migrations and sqlc generates the pgx
application queries. The embedded templ/htmx interface includes setup/readiness,
sign-in and a protected admin page with read-only user and connection lists.
There is no separate frontend server. Connection grants, query execution,
groups and audit inspection remain planned; Google/OIDC sign-in, self-service password change and
account recovery are outside the MVP.

## Quick start

Requires Go **1.27.1**, Node.js **26.8.2**, pnpm **12.3.4**, Docker with Compose,
and GNU Make on macOS or Linux.

```sh
make setup
cp -n .env.example .env
mkdir -p "$HOME/.config/clavis" && (umask 077 && openssl rand -hex 32 > "$HOME/.config/clavis/encryption-key")
make dev-db
```

Every installation needs `CLAVIS_ENCRYPTION_KEY_FILE`: the absolute path to a
protected regular file holding a 32-byte key as 64 hexadecimal characters. Connection
credentials are encrypted under it at rest, the server refuses to start without
it, and losing it makes every stored connection credential unrecoverable, so keep
it in the operator's secret manager next to the bootstrap password. The command
above creates one with owner-only permissions; point `.env` at that path.

For the first installation, supply these settings in `.env`:

- `CLAVIS_BOOTSTRAP_USERNAME`: your personal administrator username (3–64 lowercase
  letters, digits, `.`, `_` or `-`, starting with a letter).
- `CLAVIS_BOOTSTRAP_PASSWORD_FILE`: an absolute path to a protected regular file
  supplied by your secret manager or local credential setup. Use owner-only
  permissions such as `0600`; do not put the password in `.env`, arguments or Git.
  The password must be 15–1,024 UTF-8 bytes; one terminal LF/CRLF is removed.

Normal startup applies migrations and creates the initial administrator once.
There is no bootstrap command or browser account-creation form. Subsequent starts
ignore changed or missing bootstrap inputs; they do **not** reset credentials.
Keep the owner's password safely available: recovery and rotation are not yet
implemented. The mounted bootstrap file can be removed after successful setup.

Run `make dev` to build and start the Go server (`make dev-api` is an alias).
Development commands load `.env` as data, not shell code; existing environment
values take precedence. Stop the server with Ctrl-C. There is no file watcher:
after editing Go or browser scripts/styles, stop and rerun `make dev`. After
editing `.templ` files, run `make generate-web` before restarting; after editing
application queries, migration schema inputs or `sqlc.yaml`, run `make generate-db`.
Open `http://127.0.0.1:8080` for the setup page.
The same server exposes JSON health endpoints at `/health/live` and
`/health/ready`, independently of HTML rendering.

## Commands

| Command | Purpose |
| --- | --- |
| `make build` | Build the server and CLI |
| `make build-server` | Verify generated templates/queries, rebuild embedded assets and build the server |
| `make build-cli` | Build only the CLI using Go, without web or SQL tools |
| `make install-templ` / `make install-golangci-lint` | Install the exact template compiler / Go linter pin |
| `make install-sqlc` | Install the exact development sqlc pin |
| `make generate-db` | Explicitly regenerate checked-in pgx query methods |
| `make check-db-generated` | Check the complete generated query tree without rewriting files |
| `make check-sql-boundaries` | Check generated queries and the handwritten persistence boundary |
| `make generate-web` | Explicitly regenerate checked-in templ Go source and ignored assets |
| `make build-web-assets` | Rebuild only ignored CSS, scripts and embedded attribution notices |
| `make check-web-generated` | Check template formatting and generated-source consistency without rewriting files |
| `make check` | Run non-mutating source checks, linters, tests, and builds |
| `make lint-go` | Run golangci-lint |
| `make format` | Format maintained Go, templates and JavaScript; regenerate templ Go source |
| `make smoke` | Test standalone server HTTP/API/CLI behavior with real database outage, recovery and cleanup |
| `make test-mutation` | Prepare embedded inputs, run isolated Go mutation testing and report survivors |
| `make down` | Stop the database and keep its data |
| `make reset-db` | Delete the local Clavis database and its data |

`make setup` installs templ, golangci-lint and sqlc with versioned `go install`
commands into ignored `.tools/<tool>/bin/`, and frontend development dependencies
with pnpm's frozen lockfile. Pins come from the templ runtime in `go.mod`,
`GOLANGCI_VERSION` in `Makefile`, and `.sqlc-version`. Go verifies downloaded
modules using its normal module integrity checks; no remote installer is executed
and application Go dependencies are not changed. Package managers and pinned
install arguments own tool versions; builds/checks do not add custom version gates
or install tools.
Rerun the relevant installation target after changing a pin.

`make check` retains Go unit, render, HTTP, authentication, cookie and CSRF tests,
Node build/tooling regression tests, generated-source checks, formatting, lint and
builds. It does not run browser automation or visual/layout tests, and setup does
not install browser binaries.

`make smoke` copies only the server executable into a fresh temporary directory
and runs it there with an empty executable search path. HTTP requests verify the
login document and availability of its referenced embedded assets. JSON API
requests and the CLI exercise concurrent initialization, authentication, expiry,
multi-client revocation, user administration (creation, listing, blocking,
password reset, role changes and self-protection) and connection management
(creation with an encrypted secret, connectivity checks against the real database
and a local VictoriaMetrics health stub, updates, credential replacement, the delete
guard, selector listing, dry runs and a restart with a different key), then
outage/recovery by stopping and restarting an isolated PostgreSQL database and the
copied server. Test credentials
and CLI homes are private temporary inputs, not companion application assets,
and are removed during cleanup. An additional loopback HTTPS proxy uses an
in-memory test certificate to verify that the CLI rejects a self-signed
certificate; no OS trust settings are changed. This smoke test does not launch a
browser or verify JavaScript interactions, appearance, layout, or browser cookie
and Origin behavior. The runner has a 180-second execution deadline, followed by
cleanup of its own resources.
It leaves existing development processes, database containers and volumes alone.
Logs and `smoke-summary.json` go under `reports/`.

To exercise failure cleanup, run `CLAVIS_SMOKE_FAIL=after-start make smoke`,
`CLAVIS_SMOKE_FAIL=after-restart make smoke` or
`CLAVIS_SMOKE_FAIL=after-https make smoke`. These deliberately exit nonzero;
the summary must still report `"cleanup": "passed"`, removed temporary runtime
files and stopped processes. The latter cases cover restarted servers and the
HTTPS fixture, including private credential/cache cleanup.

`make test-mutation` checks generated templates/queries and prepares assets before
copying Go sources and embedded inputs into an isolated temporary directory.
It targets handwritten authentication, persistence, configuration, CLI, server
and web behavior, excluding generated templ/sqlc code, copied UI components and
test fixtures. A compatibility probe must distinguish a known detected mutation
from a known survivor before
the application run is accepted. Results and survivors go to ignored
`reports/mutation-summary.json` and `reports/mutations.json`; a completed run
is not a claim that every mutation was detected. Tool failures or the default
600-second deadline return nonzero. Optional `CLAVIS_MUTATION_WORKERS` and
`CLAVIS_MUTATION_TIMEOUT_SECONDS` adjust concurrency and the execution bound.

`web/` holds pinned development dependencies, styles and application scripts,
not a separately deployed application. UI source lives in
`internal/web/`; commit `.templ` files together
with generated `*_templ.go` files. Copied-source attribution is in source comments,
including upstream copyright and permission notices; the build packages those
notices at `/assets/notices.txt`.

Commit SQL queries, Goose migration sources and `sqlc.yaml` with matching
`internal/database/sqlc/` output. Applied migrations are immutable; checks
regenerate in isolation instead of repairing the checkout. Native sqlc parses the
maintained YAML configuration and runs with `--no-remote`; Make compares the
complete output tree, including unexpected files. Explicit generation replaces
the old tree only after generation succeeds. The fixed SQL input/output paths
must not contain symlinks; configuration is trusted build input, not sandboxed
untrusted YAML. Goose owns version tracking; handwritten migration metadata is
limited to its ledger/checksum/locks.

Node.js, pnpm, templ and sqlc are development tools, not runtime requirements for the
built Go executables. `make build-server` uses `CGO_ENABLED=0`; copy `bin/server`
alone to a compatible OS/architecture and run it from any directory with
`CLAVIS_DATABASE_URL` and optional settings from `.env.example` supplied in its
environment. The executable does not load `.env`. PostgreSQL remains an external
server dependency; the CLI is a separate optional executable. Goose runs as an
embedded Go library. First initialization additionally needs the explicit
bootstrap secret file, not an external SQL directory or migration executable.

Non-loopback authentication requires `CLAVIS_PUBLIC_URL` set to the HTTPS public
origin, without a base path. Terminate TLS in your deployment and prevent
untrusted direct access to the HTTP backend listener. Clavis does not infer its
public origin from forwarded headers. Literal loopback HTTP is the development
exception.

Builds publish binaries only after successful compilation. A failed build returns
nonzero and leaves any previous binary untouched; do not deploy it as a new build.
Missing or stale generated templates/queries fail the server build without
rewriting them. Run the relevant explicit generation command after source edits.

The public setup/login documents and assets remain available when PostgreSQL is
unavailable; protected requests fail closed. These diagnostics require no sign-in
but do not change your deployment's network exposure. Readiness requires a
reachable database, supported schema and completed initialization, distinguishing
`INITIALIZING`, `SETUP_REQUIRED`, `BOOTSTRAP_FAILED`, `SCHEMA_ERROR` and
`DEPENDENCY_UNAVAILABLE` using safe messages.
Checks run on page entry and explicit retry, not polling or focus/reconnect.
Each check has a five-second deadline including body reads; a new retry cancels
the previous check. HTML readiness at `/ui/readiness` returns 200 or a safe 503
fragment. Only recognized HTML responses can replace the status region.

An already-loaded page can report server loss and recover through retry once the
server returns. If the Go server is stopped, fresh navigation receives the
browser's connection error; there is no independent frontend or offline fallback.
Appearance is the only persisted browser preference (`clavis.appearance`); with
storage blocked, the switch still works for the lifetime of the loaded page.

## CLI authentication

After building and initializing the server:

```sh
./bin/clavis doctor
./bin/clavis login --username alice
./bin/clavis whoami
./bin/clavis logout
```

Login prompts without echo; automation can use `--password-stdin` with redirected
protected input. Passwords and tokens are never command-line values or normal
output. Results default to one JSON document; `--output text` is also available.
Sessions are stored privately under the user's configuration directory and keyed
by server origin. `whoami` verifies the session with the server rather than
trusting cached identity.

An administrator can run `./bin/clavis sessions revoke --user <user-id>` to revoke
that user's existing browser and CLI sessions. Sessions have a fixed eight-hour
default lifetime (`CLAVIS_SESSION_TTL`, 5 minutes through 24 hours), with no
automatic refresh. Logout revokes the current session; offline CLI logout removes
the local credential but returns failure because remote revocation is unconfirmed.

## User administration

Administrators manage local users through the CLI; the browser admin page only
lists them:

```sh
./bin/clavis users list
./bin/clavis users create --username bob
./bin/clavis users block --user <user-id>
./bin/clavis users unblock --user <user-id>
./bin/clavis users reset-password --user <user-id>
./bin/clavis users set-role --user <user-id> --role admin
```

`create` and `reset-password` read the password without echo, or from
`--password-stdin`, exactly like `login`; the administrator chooses every
password. New users are members. Blocking and password reset revoke all of the
target's sessions; unblocking does not restore them. Administrators are peers:
any administrator can manage any other, an administrator cannot block or demote
their own account (`SELF_TARGET`), and the installation always keeps at least
one enabled administrator. Every mutation and every denied attempt is recorded
as a safe audit event without passwords or query text; a successful listing
records none. Listing is bounded to 1,000 users and reports
`truncated` when more exist.

The MVP has no self-service password change and no account recovery: a lost
password is replaced by an administrator with `reset-password`, and a lost
administrator password is replaced by another administrator.

## Connections

A connection is a registered external data source: a stable UUID, a unique
mutable name, a provider (`postgresql` or `victoriametrics`), non-secret target
settings, labels, resource bounds and one encrypted secret. Administrators manage
them through the CLI; the browser admin page only lists them. The commands follow
the same conventions as `users` and are designed for agents: one verb vocabulary,
`--connection <uuid-or-name>` everywhere, `--dry-run` on every mutation, machine
readable errors with a `hint` naming the next step, and secrets that never appear
on the command line.

```sh
clavis connections create --name payments-prod-reporting --provider postgresql \
  --url 'postgres://reporting@db.payments.internal:5432/payments?sslmode=require' \
  --label env=prod --label service=payments --title "Payments (reporting)" \
  --password-file /run/secrets/reporting
clavis connections check --connection payments-prod-reporting
clavis connections list --selector env=prod,service=payments
clavis connections update --connection payments-prod-reporting --statement-timeout 60s
clavis connections set-credentials --connection payments-prod-reporting --password-env REPORTING_PW
clavis connections disable --connection payments-prod-reporting
clavis connections delete --connection payments-prod-reporting --dry-run
```

Secrets come from exactly one of a hidden terminal prompt, `--password-stdin`,
`--password-file <absolute owner-only file>` or `--password-env <NAME>` (the CLI
reads the named variable; the agent never sees the value). The PostgreSQL target
is a URL without a password; VictoriaMetrics takes a base URL plus `--auth
none|basic|bearer|header` with `--auth-user` or `--auth-header` where needed.
Labels are `key=value` pairs; `--selector` accepts comma-separated `key=value`,
`key!=value` and `key` terms combined with AND. Creation never contacts the
source; `check` runs one probe and records `reachable`, `auth_rejected`,
`unreachable` or `credentials_unavailable` with its time, claiming nothing about
which data the credentials can read. Replacing credentials clears the last check.
Delete requires a disabled connection with no grants. Listing is bounded to 1,000
connections and to the response body limit, always with an explicit `truncated`
flag. Statement timeout and result caps default to 30 s, 1,000 rows and 1 MiB
with ceilings of 120 s, 100,000 rows and 10 MiB; they are enforced once query
execution ships. Every mutation, check and denied attempt is audited without
secrets or target hosts; a dry run records nothing.

For a custom API address, add `--server <url>` or export `CLAVIS_SERVER_URL`; the
CLI does not load `.env`. Authentication requires a root-origin HTTPS URL except
for literal loopback HTTP. Help/version and CLI-only builds work offline.
