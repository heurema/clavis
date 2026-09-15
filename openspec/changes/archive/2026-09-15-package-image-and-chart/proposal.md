## Why

The server is a single static executable with embedded assets, migrations and health endpoints, but the only documented way to run it is `make dev` on a contributor's machine. The PRD delivery model is self-hosted, single tenant, one Go server plus an external PostgreSQL (section 12), and the pilot needs an operator-facing artifact that runs on the Flux-managed Kubernetes clusters the pilot team already operates. Nothing today produces a container image or an installable chart, and two startup rules block a straightforward Kubernetes deployment: both secret-file readers reject every group permission bit, which no Kubernetes Secret volume mounted into a non-root container can satisfy, and the server carries no build identity, so a running pod cannot say which revision it is.

## What Changes

- Add a multi-stage `Dockerfile` that runs the documented asset generation and generated-source checks in a builder stage and packages the server on a pinned `distroless/static` non-root runtime with CA certificates and time zone data. The image is multi-architecture (`linux/amd64`, `linux/arm64`) and carries version, commit and date through `internal/buildinfo`. A `.dockerignore` keeps local secrets, tools, binaries, reports and stale assets out of the build context.
- Split the Makefile server build into `compile-server` (compile only, honours `GOOS`/`GOARCH`, stamps build info) and `build-server` (gates, assets, then `compile-server`), so the Dockerfile and contributors share one compile recipe. Add `image`, `chart-lint`, `smoke-image` and `verify-kind` targets.
- **BREAKING**: rename the health endpoints to the Kubernetes convention and add an aggregate. `GET /livez` replaces `/health/live` with the same body, `GET /readyz` replaces `/health/ready` with the same contract, and `GET /healthz` is new: HTTP 200 with `{"status":"ok","version":…,"checks":{"live":…,"ready":…}}` when the process is live and ready, HTTP 503 with `status` `unhealthy` and the same shape otherwise. The old paths are removed, not redirected; nothing is in production. `clavis doctor`, the smoke scripts, the README and the PRD follow.
- Record build identity: the server startup log carries `version`, `commit` and `date`, and `/healthz` carries `version`. `/livez` and `/readyz` bodies stay minimal.
- **Secret-file permission rule (both readers)**: a regular file with owner permissions only stays accepted; a file that is also group-readable is accepted only when its group is the process's effective group or one of its supplementary groups; group-write, group-execute and any world bit are still refused with the existing error categories. This is what a Kubernetes Secret volume mounted with `fsGroup` produces, and it keeps an owner-only development key file working unchanged. The maintained scenarios that say "a group-readable file" is refused are narrowed to "a file readable by an unrelated group or by others".
- Add a hand-written Helm chart at `deploy/charts/clavis`: Deployment, Service, ServiceAccount, optional Ingress or Gateway API HTTPRoute, optional NetworkPolicy and PodDisruptionBudget, liveness and readiness probes on the existing health endpoints, a restrictive pod security context, `values.schema.json` and a README. Configuration is environment variables set by the chart; the database URL, the encryption key and the bootstrap password come from operator-supplied existing Secrets, referenced by name and key, never as chart values. The chart owns no database: PostgreSQL is external, as the PRD and `embedded-web` already require.
- Add a compose profile that runs the built image against the compose database and a health-only smoke script for it, and a kind-based verification script that installs the chart on a throwaway cluster, bootstraps, restarts with bootstrap disabled, upgrades across a migration and signs in through the CLI over a port-forward.
- Document the image, the chart and the operator contract: required HTTPS public URL, external database, brief interruption on upgrades that carry a migration, no image rollback across a migration, no key rotation.

Deferred to a following change: GitHub Actions for checks and release, publishing to GHCR, cosign signing of image and chart, CLI archives for Linux and macOS.

## Capabilities

### New Capabilities

- `deployment-packaging`: the container image contract (contents, runtime user, build identity, what the image build verifies), the Helm chart contract (resources, secret references, bootstrap lifecycle, public URL, upgrade behaviour, no database ownership), and the local verification commands (image smoke, chart lint, kind verification).

### Modified Capabilities

- `project-bootstrap`: "Independent liveness and readiness" moves to `/livez` and `/readyz` and gains the `/healthz` aggregate with the version; "Required encryption key configuration" accepts a group-readable key file whose group the process belongs to; "Repeatable quality and smoke checks" gains the documented image and chart verification commands and the pinned chart tooling.
- `platform-initialization`: "Safe bounded bootstrap secret handling" defines protected POSIX permissions as owner-only or owner plus a group the process belongs to.
- `connection-management`: "Encrypted credentials at rest" keeps the same rules as the bootstrap file, so its refusal scenario names an unrelated group or others rather than any group-readable file.
- `embedded-web`: "Distinct HTML and JSON representations" names `/readyz` and `/healthz` instead of `/health/ready`.

## Impact

- Build and packaging: `Dockerfile`, `.dockerignore`, `Makefile` (`compile-server`, `build-server`, `image`, `chart-lint`, `smoke-image`, `verify-kind`, tool pins), `compose.yaml` (an `app` service behind a profile), `scripts/smoke-image.mjs`, `scripts/verify-kind.sh` or `.mjs`, script tests.
- Server: `internal/server/server.go` (the three health routes, `server_started` with build info), `cmd/server/main.go` (ldflags contract), `internal/cli/doctor.go` (`/readyz`), `internal/secrets/keyfile.go` and `internal/database/initialize.go` (shared permission rule, likely a small helper in `internal/secrets`), and every test, smoke and build script that names the old paths (`internal/server/*_test.go`, `cmd/server/main_test.go`, `internal/cli/*_test.go`, `scripts/smoke.mjs`, `scripts/build.test.mjs`).
- Chart: `deploy/charts/clavis/` (Chart.yaml, values.yaml, values.schema.json, templates, README, test values), `deploy/README.md` if the top-level README stays concise.
- Documentation: README (prerequisites, Commands table, a short Deployment section), `.env.example` unchanged, PRD section 12 status paragraph.
- Dependencies: no Go module changes. New pinned development tools installed like the existing ones: Helm, kind and kubeconform through versioned `go install` into `.tools/` if that works for each (checked during planning; the design records the outcome), otherwise documented prerequisites. Docker with Compose is already required.

## Decisions recorded for owner review (2026-09-15)

Discussed with the owner and an independent read-only review on 2026-09-15; each is recorded so the implementer does not relitigate it.

- The chart contains no PostgreSQL resources and no subchart; the README points at CloudNativePG in one sentence.
- Upgrades keep Kubernetes' default RollingUpdate with `maxUnavailable: 0` and `maxSurge: 1`, exposed as a value. A new migration makes the old pod fail closed on every request the moment the migration commits, so the interruption is about one readiness period; `Recreate` would only lengthen it. Image rollback across a migration is unsupported and documented; that is the forward-only ledger, not the strategy.
- The readers change rather than an init container staging the files: two small functions and their tests instead of a second image and volume every operator must understand. Secrets stay files; environment variables for secret values are not added.
- Health endpoints follow the Kubernetes names (owner decision 2026-09-15): `/livez` and `/readyz` keep the existing minimal bodies so probes and `clavis doctor` stay cheap, and `/healthz` is the human and monitoring aggregate that also carries the version. Commit and date stay in the startup log; only the version is public.
- Bootstrap is an explicit chart block the operator enables for the first install and disables afterwards; the chart never inspects cluster state, deletes Secrets or reasons about Helm revisions.
- A file-based secret provider (Vault Agent, Secrets Store CSI) is supported through `extraVolumes`, `extraVolumeMounts` and overridable file paths, without chart logic for any particular provider.

## Non-goals

Publishing the image or chart, signing, CI, CLI release archives, key rotation, migration tooling separate from server startup, multi-replica availability during schema changes, Windows images, an in-cluster database.
