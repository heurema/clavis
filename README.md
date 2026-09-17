<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/clavis-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/clavis-light.svg">
  <img src="docs/assets/clavis-light.svg" width="264" height="96" alt="Clavis">
</picture>

Clavis is a CLI-first platform by heurema for controlled access to operational
systems by people and agents.

Currently, it provides automated initial administrator setup, local browser/CLI
sign-in, revocable sessions, administrator-managed local users and groups, and
registered data-source connections with encrypted credentials and connectivity
checks, with external PostgreSQL. Goose manages embedded migrations and sqlc
generates the pgx application queries. The embedded templ interface includes
sign-in and administration pages for users, groups, connections and grants, each
a read-only list inside one shell; `/admin` redirects to `/admin/users`. There is
no separate frontend server. Queries run against PostgreSQL, VictoriaMetrics
and VictoriaLogs connections, and the agent skill installs through the CLI;
an audit journal, Google/OIDC sign-in, self-service password change and
account recovery are outside the MVP.

## Quick start

Requires Go **1.27.1**, Node.js **26.8.2**, pnpm **12.3.4**, Docker with Compose,
and GNU Make on macOS or Linux. Helm, kind and kubeconform are not separate
prerequisites: `make setup` installs the pinned versions into `.tools/`. Only
`make verify-kind` needs one more, `kubectl` on the search path, which setup does
not install.

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
Open `http://127.0.0.1:8080` to sign in; signing in lands on the Users page, and
the sidebar reaches Connections and Grants.
The same server exposes JSON health endpoints at `/livez`, `/readyz` and the
aggregate `/healthz`, which reports the build version alongside both checks,
independently of HTML rendering.

## Commands

| Command | Purpose |
| --- | --- |
| `make build` | Build the server and CLI |
| `make build-server` | Verify generated templates/queries, rebuild embedded assets and build the server |
| `make compile-server` | Compile only the server, stamping `VERSION`, `COMMIT` and `DATE`, without the generated-source gates or the asset build |
| `make build-cli` | Build only the CLI using Go, without web or SQL tools |
| `make install-templ` / `make install-golangci-lint` / `make install-deadcode` | Install the exact template compiler / Go linter / dead-code tool pin |
| `make install-sqlc` | Install the exact development sqlc pin |
| `make install-helm` / `make install-kind` / `make install-kubeconform` | Install the exact Helm / kind / kubeconform pin |
| `make install-kube-schemas` | Download and verify the pinned Kubernetes and Gateway API JSON schemas the chart check reads |
| `make generate-db` | Explicitly regenerate checked-in pgx query methods |
| `make check-db-generated` | Check the complete generated query tree without rewriting files |
| `make check-sql-boundaries` | Check generated queries and the handwritten persistence boundary |
| `make generate-web` | Explicitly regenerate checked-in templ Go source and ignored assets |
| `make build-web-assets` | Rebuild only ignored CSS, scripts and embedded attribution notices |
| `make check-web-generated` | Check template formatting and generated-source consistency without rewriting files |
| `make check` | Run non-mutating source checks, linters, tests, and builds |
| `make lint-go` | Run golangci-lint |
| `make check-dead-code` | Fail on any Go function no executable reaches, test-only helpers included |
| `make chart-lint` | Lint the Helm chart and schema-validate every representative value set |
| `make format` | Format maintained Go, templates and JavaScript; regenerate templ Go source |
| `make smoke` | Test standalone server HTTP/API/CLI behavior with real database outage, recovery and cleanup |
| `make image` | Build the server container image, stamping the identity from Git, tagged `$(IMAGE)` (default `clavis:local`) |
| `make smoke-image` | Build the image and test it against an isolated compose database over a published loopback port |
| `make verify-kind` | Install the chart on a throwaway kind cluster and drive the bootstrap, restart and migration-upgrade lifecycle, then delete the cluster |
| `make test-mutation` | Mutation-test the handwritten Go files changed against `main` in an isolated copy and report survivors |
| `make test-mutation-full` | Mutation-test the whole handwritten scope with the extended bound |
| `make down` | Stop the database and keep its data |
| `make reset-db` | Delete the local Clavis database and its data |

`make setup` installs templ, golangci-lint, deadcode, sqlc, Helm, kind and
kubeconform with versioned `go install` commands into ignored
`.tools/<tool>/bin/`, and frontend development dependencies
with pnpm's frozen lockfile. Pins come from the templ runtime in `go.mod`,
`GOLANGCI_VERSION`, `DEADCODE_VERSION`, `HELM_VERSION`, `KIND_VERSION` and
`KUBECONFORM_VERSION` in `Makefile`, and `.sqlc-version`. Setup also downloads the
Kubernetes and Gateway API JSON schemas `make chart-lint` validates against into
ignored `.tools/kube-schemas/`, pinned by repository commit and verified against
a checksum per file in `Makefile`, so a repeat run re-verifies them and the chart
check itself needs no network. Go verifies downloaded modules using its normal
module integrity checks; no remote installer is executed
and application Go dependencies are not changed. Package managers and pinned
install arguments own tool versions; builds/checks do not add custom version gates
or install tools.
Rerun the relevant installation target after changing a pin.

`make check` retains Go unit, render, HTTP, authentication, cookie and CSRF tests,
Node build/tooling regression tests, generated-source checks, formatting, lint,
builds and the chart lint. It does not run browser automation or visual/layout
tests, and setup does not install browser binaries.

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

`make smoke-image` builds the image and runs it the way a deployment does, under
its own compose project and the `app` profile no other command activates: a
read-only root filesystem, uid 65532, an isolated PostgreSQL, and the encryption
key and bootstrap password bind-mounted read-only at mode `0440` from a temporary
directory whose group the container joins. It waits for `/livez` then `/readyz`,
checks `/healthz`, the sign-in document and an asset the document references,
confirms the process runs as uid 65532 with a read-only root filesystem, and runs
`clavis doctor`, `login` and `whoami` over the published loopback port. The
container's public URL is HTTPS, as a deployment's is, so browser sign-in is out
of scope here. Per-check results go to `reports/smoke-image-summary.json`, and the
project, its volume and the temporary secrets are removed afterwards; the
development database and its volume belong to a different project and are untouched.
On macOS Docker hosts the bind-mounted secret files appear owned by the container
user, so the group-read branch is exercised on Linux hosts and by the kind
verification, while the refusal of a world-readable file holds everywhere.

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
is not a claim that every mutation was detected. By default only the eligible
files that differ from `main` (committed, uncommitted or untracked) are mutated,
which keeps a per-change run to minutes; the summary's `scope` names the base
ref and `targets` the files. `make test-mutation-full` mutates every eligible
file with a 3,600-second bound and is the run recorded before a change is
archived. Tool failures, an unknown base ref or the deadline (600 seconds by
default) return nonzero. `CLAVIS_MUTATION_DIFF` sets another base ref, or the
full scope when empty; `CLAVIS_MUTATION_WORKERS` (default: available cores
minus two) and `CLAVIS_MUTATION_TIMEOUT_SECONDS` adjust concurrency and the
execution bound.

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

The public sign-in document and the assets remain available when PostgreSQL is
unavailable; protected requests fail closed. `GET /` and `GET /admin` redirect
into the administration pages without reading the database. Readiness is reported by
`GET /readyz` and `clavis doctor`, which require no sign-in but do not
change your deployment's network exposure. Readiness requires a reachable
database, supported schema and completed initialization, distinguishing
`INITIALIZING`, `SETUP_REQUIRED`, `BOOTSTRAP_FAILED`, `SCHEMA_ERROR` and
`DEPENDENCY_UNAVAILABLE` using safe messages. `GET /healthz` aggregates
liveness and the same readiness check for a person or an uptime monitor and
reports the build version; `GET /livez` reports liveness alone. There is no
browser status page.

If the Go server is stopped, fresh navigation receives the browser's connection
error; there is no independent frontend or offline fallback.
Appearance is the only persisted browser preference (`clavis.appearance`); with
storage blocked, the appearance control still works for the lifetime of the
loaded page.

## Deployment

A Helm chart for the server lives in `deploy/charts/clavis`. It installs one
Deployment, one Service and one ServiceAccount, with an optional Ingress or
Gateway API HTTPRoute, NetworkPolicy and PodDisruptionBudget, and it owns no
database. The server image is `ghcr.io/heurema/clavis`, listening on port 8080
as a non-root user with a read-only root filesystem.

The chart takes the database URL, the encryption key and the bootstrap password
as references to Secrets you already have, and requires `publicURL`, the HTTPS
origin you terminate TLS on. `make chart-lint` lints the chart and
schema-validates every value set in `deploy/charts/clavis/ci/`, and runs inside
`make check`.

Three commands verify the artifacts locally, all of them requiring Docker.
`make image` builds the server image and `make smoke-image` runs it against an
isolated compose database. `make verify-kind` additionally needs `kubectl`: it
creates a throwaway kind cluster with a pinned node image and a plain PostgreSQL
Deployment, builds one image from the checkout and a second one carrying an extra
migration, installs the chart with bootstrap enabled, signs in with the CLI over
a port-forward, upgrades with bootstrap disabled and the bootstrap Secret deleted,
then upgrades across the migration and signs in again. It records every step in
`reports/verify-kind.json` and deletes the cluster, the two images and its
temporary copy even when a step fails; `--keep-cluster` keeps the cluster for
debugging.

Read `deploy/charts/clavis/README.md` before installing or upgrading: it carries
the operator contract, including the bootstrap lifecycle, why an upgrade across
a migration interrupts service and cannot be rolled back, and why the database
and the encryption key must be backed up together.

### Releases

Pushing a `vX.Y.Z` tag, or a `vX.Y.Z-rc.N` candidate, is the whole release.
The workflow in `.github/workflows/release.yml` runs `make check` on the tagged
commit, then publishes the CLI for macOS and Linux on both architectures with a
`SHA256SUMS` file on a GitHub Release, the server image at
`ghcr.io/heurema/clavis`, and the chart at `oci://ghcr.io/heurema/charts/clavis`.
A tag carrying a hyphen becomes a pre-release. The image tag, the chart version
and its `appVersion` drop the leading `v`; the executables, `/healthz` and the
image labels keep it, so a release reports `v1.2.3` while its image is
`ghcr.io/heurema/clavis:1.2.3`. Nothing is tagged `latest`. After the first
release an owner has to make both GHCR packages public once, which the workflow
cannot do for itself.

Install the CLI either way; both report the release version:

```sh
go install github.com/heurema/clavis/cmd/clavis@<tag>   # for example v0.1.0-rc.2
```

```sh
curl -fsSLO https://github.com/heurema/clavis/releases/download/<tag>/clavis_<version>_darwin_arm64
curl -fsSLO https://github.com/heurema/clavis/releases/download/<tag>/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
install -m 755 clavis_<version>_darwin_arm64 /usr/local/bin/clavis
```

A build made any other way carries no stamped identity and falls back to what
the Go toolchain recorded: a checkout build reports its own revision, and a
source export reports `dev`.

## Agents

Agents use the CLI plus a skill that teaches it. The skill ships inside the
CLI binary and installs into the agent directories found under your home:

```sh
clavis skill install                 # ~/.claude/skills/clavis and ~/.codex/skills/clavis, whichever exist
clavis skill install --agent codex   # one agent, its directory created if needed
clavis skill install --scope project # .claude/skills and .codex/skills in the current repository
clavis skill show                    # print the entry document; --file victorialogs.md for a reference
```

The skill is a `SKILL.md` entry (what Clavis is, setup, finding a connection,
the envelope, exit codes, truncation, data versus instructions) and one
reference per provider (`postgresql.md`, `victoriametrics.md`,
`victorialogs.md`) with the discovery-first workflow, the query recipes, the
bounds and the pitfalls of that source. Its files live in
`internal/skill/clavis/` and a test fails the build when the prose names a
command, flag or hint the CLI does not have. `install` stamps the CLI version
into the entry's frontmatter (`x-clavis-skill`), updates a skill it installed
before, reports each target as written, updated, unchanged or refused, and
refuses to overwrite a `clavis` skill directory it did not write unless
`--force`. Reinstalling from a newer CLI is the update; delete the directory to
remove it. Both commands work offline and never touch the server or the
session. Install through the CLI only: a second copy of the skill leaves it
undefined which one an agent loads.

Once a person has configured a profile (see [CLI profiles](#cli-profiles)),
the agent logs in like any other user and follows the skill. The skill tells it
to name the server every result reports, to target another configured server
with `--profile` or `CLAVIS_PROFILE`, and never to create, switch or remove a
profile itself:

```sh
clavis login --username <name> --password-stdin < /path/to/secret
clavis connections list
clavis query --connection <ref> --logsql 'error | sort by (_time) desc' --start -1h --limit 20
```

## CLI authentication

After building and initializing the server, name it once as a profile:

```sh
./bin/clavis profiles set local --server http://127.0.0.1:8080
./bin/clavis doctor
./bin/clavis login --username alice
./bin/clavis whoami
./bin/clavis logout
```

Login prompts without echo; automation can use `--password-stdin` with
redirected protected input. Passwords and tokens are never command-line values
or normal output. Results default to one JSON document; `--output text` is also
available. Sessions are stored privately under `~/.clavis/sessions` and keyed by
server origin, so two profiles naming one server share its session. `whoami`
verifies the session with the server rather than trusting cached identity, and
for members it lists the names of the connections they can use (`connections`,
with `connectionsTruncated` when the list is cut), direct grants and group
grants together; administrators see no list because they need no grants. Every
caller's group names come back as `groups` (with `groupsTruncated`), so an
agent's first call already says which groups it belongs to; the two lists are
bounded independently.

An administrator can run `./bin/clavis sessions revoke --user <uuid-or-username>`
to revoke that user's existing browser and CLI sessions. Sessions have a fixed eight-hour
default lifetime (`CLAVIS_SESSION_TTL`, 5 minutes through 24 hours), with no
automatic refresh. Logout revokes the current session; offline CLI logout removes
the local credential but returns failure because remote revocation is unconfirmed.

## CLI profiles

The CLI keeps its state in one directory, `~/.clavis`, or wherever the absolute
path in `CLAVIS_HOME` points: `config.toml` holds named profiles and `sessions/`
the stored sessions. A profile is a name and a server root origin, and
`current` names the profile used when nothing else is chosen:

```toml
current = "local"

[profiles.local]
server = "http://127.0.0.1:8080"

[profiles.fce]
server = "https://clavis.example.com"
```

The file holds no secrets and may be written by hand; it is read strictly, so
an unknown key, an invalid name or server, or a `current` naming no profile
fails every command that reads the file (a one-off `--server` does not) with
`INVALID_ARGUMENT` naming the file and key, and nothing from it is used. The
home must be owned by you and not group- or world-writable, `sessions` must be
mode 0700, and no component of either path may be a symlink. The `profiles`
commands manage the file the way `kubectl config` manages contexts, and never
contact a server:

| Command | kubectl counterpart | Effect |
|---|---|---|
| `clavis profiles set <name> --server <url>` | `config set-context` | Creates the profile or changes its server; it becomes current when no profile is current, as after `profiles remove` cleared `current` |
| `clavis profiles use <name>` | `config use-context` | Makes the profile current; an unknown name fails |
| `clavis profiles current` | `config current-context` | Shows the profile in effect and whether `CLAVIS_PROFILE` or the file chose it |
| `clavis profiles list` | `config get-contexts` | Lists profiles, marks the current one, shows each stored session's user and expiry |
| `clavis profiles remove <name>` | `config delete-context` | Removes the profile, clearing `current` if it named it; stored sessions stay |

A write takes a lock beside the file and replaces it atomically, and it drops
hand-written comments and sorts the profiles by name. A write that fails exits
1: `CREDENTIAL_STORAGE_FAILED` for an unsafe home, `TIMEOUT` when the lock is not
taken within five seconds, and `CONFIGURATION_WRITE_FAILED` otherwise.

Every networked command, `doctor` and `login` included, resolves its server in
this order: `--server <url>` for a one-off server or `--profile <name>` (not
both), then the profile named by `CLAVIS_PROFILE`, then `current`. There is no
default server: with none of them the command exits 2 with the hint
`clavis profiles set <name> --server <url>` before reading any input or
contacting anything, and an unknown profile name exits 2 as well. `login` only
signs in to the resolved server; it never writes the file. `CLAVIS_PROFILE` pins
one terminal or agent without changing the machine's current profile. The CLI
does not load `.env`, and a server must be a root-origin HTTPS URL except for
literal loopback HTTP. Help, version, `skill` and CLI-only builds work offline
and read no configuration.

Every networked result names the server it used in top-level `server` and
`profile` fields (`profile` is empty for a one-off `--server`), and
`--output text` prints `Server: <origin> (profile <name>)` as its first line,
before any failure.

Upgrading from an earlier release: `CLAVIS_SERVER_URL` and the loopback default
are gone, so replace an exported `CLAVIS_SERVER_URL` with a profile
(`clavis profiles set <name> --server <url>`) or with `CLAVIS_PROFILE`. Sessions
moved to `~/.clavis/sessions`, so sign in again; the former directory
(`~/Library/Application Support/clavis` on macOS, `~/.config/clavis` on Linux)
may be deleted.

## User administration

Administrators manage local users through the CLI; the browser's Users page only
lists them:

```sh
./bin/clavis users list
./bin/clavis users create --username bob
./bin/clavis users block --user bob
./bin/clavis users unblock --user bob
./bin/clavis users reset-password --user bob
./bin/clavis users set-role --user <uuid-or-username> --role admin
```

`--user` accepts a user UUID or a username everywhere; usernames are never
UUID-shaped, so the two cannot be confused, and results always return both.
`create` and `reset-password` read the password without echo, or from
`--password-stdin`, exactly like `login`; the administrator chooses every
password. New users are members. Blocking and password reset revoke all of the
target's sessions; unblocking does not restore them. Administrators are peers:
any administrator can manage any other, an administrator cannot block or demote
their own account (`SELF_TARGET`), and the installation always keeps at least
one enabled administrator. Listing is bounded to 1,000 users and reports
`truncated` when more exist. The MVP keeps no audit journal: no mutation, denial
or sign-in is recorded.

The MVP has no self-service password change and no account recovery: a lost
password is replaced by an administrator with `reset-password`, and a lost
administrator password is replaced by another administrator.

## Connections

A connection is a registered external data source: a stable UUID, a unique
mutable name, a provider (`postgresql`, `victoriametrics` or `victorialogs`), non-secret target
settings, labels, resource bounds and one encrypted secret. Administrators manage
them through the CLI; the browser's Connections page only lists them. The commands follow
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
Delete requires a disabled connection with no grants; the `CONNECTION_IN_USE`
hint names what still blocks it, including the number of remaining grants.
Listing is bounded to 1,000 connections and to the response body limit, always
with an explicit `truncated` flag. Statement timeout and result caps default to 30 s, 1,000 rows and 1 MiB
with ceilings of 120 s, 100,000 rows and 10 MiB; query execution enforces them.
A dry run commits nothing.

## Groups

A group is a named set of users that a grant can name instead of one user, so
access is described per team. Administrators manage groups through the CLI; the
browser's Groups page only lists them. Group names follow the username grammar
(`[a-z][a-z0-9._-]{2,63}`, never UUID-shaped) but live in their own namespace,
so a user and a group may share a name and `--user` and `--group` keep every
reference unambiguous. `--group` accepts a group UUID or a name everywhere:

```sh
clavis groups create --name finance-managers --description "Reads the payments sources"
clavis groups list
clavis groups get --group finance-managers
clavis groups update --group finance-managers --name finance-analysts
clavis groups add-member --group finance-analysts --user alice
clavis groups members --group finance-analysts
clavis groups remove-member --group finance-analysts --user alice
clavis groups delete --group finance-analysts --dry-run
```

Membership is idempotent for retrying agents (`added: false` when the user was
already a member, `removed: false` when there was nothing to remove), records
who added the member, and survives blocking and renames. A member inherits every
connection the group holds a grant on the moment they join and loses it on their
next request after leaving or after the group's grant is revoked; nothing is
materialized, so there is no stale derived row. Renaming a group moves no
access, and a group has no enabled flag.

Deleting a group requires zero grants: `GROUP_IN_USE` refuses it and the hint
counts the grants that remain, on the real run and on the dry run alike.
Deletion drops the memberships with the group, because membership alone confers
nothing, and a group recreated under the same name is a new record that
inherits nothing. Listings are bounded to 1,000 groups and 1,000 members with
an explicit `truncated` flag, and a dry run commits nothing.

The `groups` commands are administrator-only, like `users`: every attempt by a
member is refused with `FORBIDDEN`. A member learns their own groups from
`clavis whoami`, which names them, and never sees another member through a
group, because no roster is readable to them.

## Grants

A grant lets one recipient, a user or a group, use one connection.
Administrators use any connection without a grant; members may only use, list
and inspect the connections they have effective access to, the union of their
direct grants and the grants of every group they belong to. Grants reference
users, groups and connections by UUID or name, are idempotent for retrying
agents, and return the recipient as `recipient` with its `kind` (`user` or
`group`), `id` and `name`:

```sh
clavis grants create --user alice --connection payments-prod-reporting
clavis grants create --group finance-managers --connection payments-prod-reporting
clavis grants list --connection payments-prod-reporting
clavis grants list --group finance-managers
clavis grants list --user alice --output text
clavis grants list --user alice --effective
clavis grants revoke --group finance-managers --connection payments-prod-reporting --dry-run
```

`create` and `revoke` take exactly one of `--user` or `--group` beside
`--connection`; `list` filters on at most one of them. `grants list --effective`
answers where one user's access comes from: it returns that user's own record
(their role and whether they are blocked, which is what explains an
administrator's bypass) and one entry per connection and configured path,
`direct` or the group it came through, so revoking one path visibly leaves the
others. It describes configuration, never usability: only the authorization
check a query runs says whether a connection can be used now. An administrator
must name the subject with `--user`; a member may omit it and read their own
paths, and naming anyone else is `FORBIDDEN`. `--effective` and `--group` cannot
be combined, because a group has no access of its own to report.

`create` returns the grant with both identifiers and names (`created: false`
when it already existed); `revoke` reports
`revoked: false` when there was nothing to remove. A member's `connections list`
and `connections get` return only the connections they have effective access to,
each listed once however many paths supply it, in a reduced projection
(`id`, `name`, `title`, `description`, `scope`, `provider`, `labels`, `enabled`,
`lastCheck`) that never carries a target, bounds or credentials; a connection
they have no access to is `CONNECTION_NOT_FOUND`, and a disabled one stays
listed with `enabled: false`, and the authorization check that later query operations run refuses it with `CONNECTION_DISABLED`. Members
may run `grants list` and see only their own direct grants; every administrative
attempt by a member is refused with `FORBIDDEN`. Revocation takes
effect on the member's next request, and grants survive blocking and renames.
Listing is bounded to 1,000 grants with an explicit `truncated` flag, and the
effective listing to 1,000 entries. The browser's Grants page lists grants
read-only, naming the recipient and marking a group one.

## Queries

`clavis query` runs a query on a connection the caller may use, SQL for
PostgreSQL and PromQL for VictoriaMetrics (see below). For PostgreSQL:
administrators on any enabled connection, members on the ones they hold a grant
on. The SQL is forwarded unchanged under the connection's credentials; the
platform does not parse, filter or wrap it, so the external role decides what
succeeds, and a script with several statements runs in order inside
PostgreSQL's implicit transaction (all or nothing unless the script has its own
transaction control).

```sh
clavis query --connection payments-prod-reporting --sql 'select count(*) from orders'
clavis query --connection payments-prod-reporting --sql-stdin <<'SQL'
create temp table recent as select * from orders where created_at > now() - interval '1 day';
select status, count(*) from recent group by 1 order by 2 desc;
SQL
clavis query --connection payments-prod-reporting --sql-file /tmp/report.sql --max-rows 50 --output text
```

Exactly one of `--sql`, `--sql-stdin` or `--sql-file <absolute path>` supplies
the SQL, bounded to 256 KiB. The result is always a list, one entry per
statement, each with `command`, `columns` (name and PostgreSQL type), `rows` as
arrays of strings exactly as PostgreSQL renders them (`null` for NULL, never a
JSON number), `rowCount` and `truncated`; the response also carries `provider`
(`postgresql`), `truncated` and `durationMs`. Text output prints one aligned table per result with `∅` for
NULL. The connection's statement timeout is set on the source session and
aborts the statement (`SOURCE_TIMEOUT`); the row and byte caps limit what comes
back, never what the database does: past the cap the remaining rows are read and
dropped, the response is marked truncated and the exit code stays 0.
`--max-rows` may lower the cap for one request. PostgreSQL applies the timeout to
each statement of a script separately, so `query` waits up to ten times the
connection's timeout plus five seconds before treating the connection as hung;
its `--timeout` therefore defaults to that budget at the 120 s ceiling rather
than the five seconds of the other commands. Failures are distinct codes:
`SOURCE_ERROR` (422) with the source's `sqlstate`, `message`, `detail`, `hint`,
`position` and the index of the failing statement under `error.source`,
`SOURCE_TIMEOUT` (504), `SOURCE_UNREACHABLE` and `SOURCE_AUTH_REJECTED` (502),
`CREDENTIALS_UNAVAILABLE`, `PROVIDER_UNSUPPORTED`, and the authorization codes `CONNECTION_NOT_FOUND`,
`CONNECTION_DISABLED`, `FORBIDDEN` and `UNAUTHENTICATED`. The source's message
may contain values from your own SQL; it is returned to you and never logged. To
learn a database's structure, query its catalog through the same command, for
example `select table_schema, table_name, column_name, data_type from
information_schema.columns where table_schema not in ('pg_catalog',
'information_schema') order by 1, 2, ordinal_position`.

### VictoriaMetrics

The same command queries a VictoriaMetrics connection with PromQL, forwarded to
the source's Prometheus API exactly as typed:

```sh
clavis query --connection payments-metrics --promql 'sum(rate(http_requests_total[5m])) by (job)'
clavis query --connection payments-metrics --promql 'rate(errors_total[5m])' --start -1h --step 1m
clavis query --connection payments-metrics --label-values __name__ --match 'http_requests_total'
clavis query --connection payments-metrics --labels --match '{job="api"}' --output text
clavis query --connection payments-metrics --series '{__name__=~"http_.*"}' --start -15m
```

`--promql` alone is an instant query at the source's now; `--at` pins it;
`--start` with `--step` makes it a range query and `--end` defaults to now.
Time strings, steps and selectors are not parsed by the platform: RFC 3339,
Unix seconds and the source's relative forms such as `-1h` all work, and the
source's own rules decide the rest (a reversed range is clamped, not refused).
Discovery forwards the source's metadata endpoints: `--label-values <name>`
lists values of a label (metric names are `--label-values __name__`),
`--labels` lists label names and `--series <selector>` lists matching series,
each bounded by the row cap and narrowed with `--match`, `--start` and `--end`.
`--promql-stdin` and `--promql-file` take the expression like their SQL twins.

The response carries `provider: "victoriametrics"`, `resultType` and `result`
in the Prometheus format with values as strings, plus the source's `warnings`,
`infos` and `isPartial` when present; nothing is reformatted. The connection's
timeout is sent to the source as the API `timeout` (the source caps it at its
own maximum) and bounds the request plus a five-second grace. The row cap counts
samples across all series: past it, remaining matrix series keep the samples
read so far and are marked `truncated`, and vector entries beyond it are
dropped; the byte cap counts kept label and value text and drops later series
whole once spent; and a body beyond four times the byte cap plus 1 MiB fails as
`SOURCE_ERROR` with `errorType: response_too_large` and a hint to narrow the
range or coarsen the step, rather than returning partial data.
Failures are the source's own: `SOURCE_ERROR` carries its `errorType` (a
Prometheus server says `bad_data` for an expression that does not parse,
VictoriaMetrics says `422`, also when it aborts an evaluation at the forwarded
timeout) and message; HTTP 401 or 403 is `SOURCE_AUTH_REJECTED`; only a source
that stops answering is `SOURCE_TIMEOUT`, cut at the timeout plus the grace. `--sql` on a metrics connection, or
`--promql` on a PostgreSQL one, is refused with a hint before anything is sent.

### VictoriaLogs

A VictoriaLogs connection takes the same `--url` and `--auth` settings plus
optional tenant settings, sent as the `AccountID` and `ProjectID` headers on
every request:

```sh
clavis connections create --name payments-logs --provider victorialogs \
  --url http://logs.payments.internal:9428 --auth bearer --account-id 12 \
  --password-env LOGS_TOKEN
clavis query --connection payments-logs --logsql 'error _time:1h | sort by (_time) desc' --limit 50
clavis query --connection payments-logs --logsql '_stream:{app="api"} | stats by (level) count() as n'
clavis query --connection payments-logs --field-names --match '*'
clavis query --connection payments-logs --field-values level --match 'app:api' --filter err
clavis query --connection payments-logs --streams --match '*' --start -1h --output text
clavis query --connection payments-logs --stream-field-values app --match '*'
```

`--logsql` (or `--logsql-stdin`, `--logsql-file`) is forwarded to the source's
query endpoint exactly as typed, with `--start`, `--end` and `--limit`. The
platform never adds a limit, a sort or a time range: without `--limit` or a
sort pipe the source streams rows in arbitrary order, and `--limit N` makes it
sort by `_time` descending before cutting, so put the sort pipe in the query
when the order matters. `--limit` is the source's own limit and `--max-rows`
is the platform's cap on what comes back: they are different knobs. Discovery
forwards the source's metadata endpoints with `--match <query>` as the
required query: `--field-names`, `--field-values <name>`, `--streams`,
`--stream-field-names` and `--stream-field-values <name>`, each with
`--start` and `--end`, `--filter <substring>` where the source takes it (the
field-name and field-value endpoints) and `--limit` where it takes it (the
field-value, stream and stream-field-value endpoints); the answer keeps the
source's `value` and `hits` pairs, and under a `--limit` the hit counts are
not observed (the source returns a subset with zero hits).

The response carries `provider: "victorialogs"` and `resultType: "logs"` with
`result` as an array of the source's rows exactly as it wrote them (every value
is a string, `_stream` and `_stream_id` included); rows of a `| stats` pipe
carry only the fields the query produced. Text output prints one physical line
per row: `_time`, `_msg`, the other fields as sorted `key=value` pairs and
`_stream` last, quoting a name or value that is empty or contains whitespace,
quotes, backslashes, control characters or `=`, so a multi-line message stays
on one line. The log stream is
unbounded unless `--limit` bounds it, so the row and byte caps are applied by
stopping: once a cap is reached the platform closes the connection and returns
the complete rows kept with `truncated: true`, which means the source's
completion was not observed and more rows may exist (a count landing exactly
on the cap is truncated too unless the stream ended right there); pass
`--limit` with a sort pipe to choose which rows you get. A single row beyond four times the byte cap plus 1 MiB fails as
`SOURCE_ERROR` with `errorType: response_too_large`. Discovery answers are one
document and are read to the end under the same ceiling. Failures are the
source's own: `SOURCE_ERROR` carries `errorType: http_400` and the source's
text for a query it rejects, `http_503` when it aborts a query at the forwarded
timeout, and `malformed_response` when a line of the stream is not a JSON row
(the source can write an error after rows, and one arriving right where the
cap would have cut the stream counts as such an error, not as truncation; no
rows are returned then). The platform reads one line past a full cap to learn
whether the stream ended there, so a row beyond the ceiling or a source that
stalls at that point is reported as that failure rather than as a truncated
answer. Only a source that stops answering is
`SOURCE_TIMEOUT`. `--sql` or `--promql` on a
log connection, or `--logsql` elsewhere, is refused with a hint before
anything is sent.

Each request opens one connection to the source and closes it afterwards; the
platform keeps no pool and imposes no concurrency limit, so a runaway agent is
throttled where it belongs: give the role a `CONNECTION LIMIT` in PostgreSQL.

Queries reach the server the CLI resolves from its profiles; see
[CLI profiles](#cli-profiles).
