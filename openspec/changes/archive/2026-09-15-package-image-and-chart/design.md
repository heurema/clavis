## Context

The server is one static Go executable (`CGO_ENABLED=0`, `-trimpath`) that embeds the browser assets `scripts/build-web-assets.mjs` writes into the ignored `internal/web/assets/`, the Goose migrations, and nothing else it needs at runtime. It applies migrations itself at startup under a session-level advisory lock (`internal/database/migrate.go`, `migrationLocker`), creates the initial administrator once from `CLAVIS_BOOTSTRAP_USERNAME` and a mounted password file, and reports `/livez`, `/readyz` and `/healthz` while the initializer retries in the background (`internal/server/server.go`, `Serve`). Configuration is environment only (`internal/config`), with `CLAVIS_HTTP_ADDR` defaulting to loopback and a non-loopback bind requiring an HTTPS `CLAVIS_PUBLIC_URL` (`configuredPublicOrigin`). `internal/buildinfo` exists but only the CLI reads it. The image build must reproduce what `make build-server` does: `check-db-generated` and `check-web-generated` gates, the asset build with Node 26.8.2 and pnpm 12.3.4, then the Go compile; templ and sqlc are pinned by `go.mod` and `.sqlc-version` and installed by `go install`.

Two startup rules were written for a developer's owner-only files and block Kubernetes. `secrets.LoadKeyFile` (`internal/secrets/keyfile.go:48`) and `database.ReadBootstrapPassword` (`internal/database/initialize.go:118`) reject any group or world permission bit. A Secret volume mounted into a non-root container is root-owned `0400` without `fsGroup`, unreadable, and `0440` owned by `fsGroup` with it, rejected. The ledger check (`validateLedger`, `internal/database/migration_metadata.go:53`) fails closed on a row it does not know, and every store entry point re-runs it per request through `LocalAuth.ready`, so an old pod stops serving the moment a newer pod's migration commits.

The operator's clusters run Flux with OCI sources; the chart is consumed as an OCI artifact later, but that publishing and the CI around it are a following change. This change produces the artifacts and proves them locally.

## Goals / Non-Goals

**Goals:**
- One `Dockerfile` that is the documented server build in container form: same gates, same asset script, same compile recipe, and a runtime image with nothing but the executable, certificates and time zone data.
- A chart an operator can install with three existing Secrets and a public URL, that says exactly what it does on upgrade and never touches a database.
- The two reader changes that make mounted Secrets work without a wrapper, kept as strict as the platform allows.
- Verification a contributor can run on a laptop: image smoke against compose, chart lint in `make check`, and a kind run that exercises bootstrap, bootstrap removal, a migration upgrade and a CLI sign-in.

**Non-Goals:**
- Publishing, signing, CI, CLI archives (next change). Key rotation, a migrate-only mode, multi-replica availability across schema changes, an in-cluster database, Windows.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Self-hosted, single tenant, one server executable plus external PostgreSQL | PRD section 12 "Delivery model"; embedded-web "Self-contained server distribution" | Retained; the chart owns no database |
| Initial administrator from deployment configuration and a mounted password file; initialized installations ignore bootstrap inputs | PRD section 12; platform-initialization "Atomic unattended administrator bootstrap", "Bootstrap is not credential reconciliation" | Retained; the chart's bootstrap block maps onto it |
| Bootstrap file: bounded regular file, protected POSIX permissions, symlinks followed, target validated | platform-initialization "Safe bounded bootstrap secret handling" | Explicitly changed (delta): "protected" now admits group-read by a group the process belongs to |
| Encryption key file: same rules as the bootstrap file, group-readable refused | project-bootstrap "Required encryption key configuration"; connection-management "Encrypted credentials at rest" | Explicitly changed (delta) with the same rule; one implementation for both |
| Key read once at startup, held in memory, rotation deferred | project-bootstrap; PRD section 12 "Credential storage" | Retained; the chart never generates or rotates the key and the README says why a changed key is fatal |
| Health paths `/health/live` and `/health/ready`; liveness body exactly `{"status":"alive"}`; readiness codes | project-bootstrap "Independent liveness and readiness"; embedded-web "Distinct HTML and JSON representations" | Explicitly changed (delta, owner decision 2026-09-15): paths become `/livez` and `/readyz` with the same bodies and codes, `/healthz` is added as the aggregate carrying the version; old paths removed |
| Migrations embedded, applied by the server under the advisory lock, forward-only ledger, fail closed on unknown rows | platform-initialization "Embedded transactional schema initialization" | Retained; the chart documents the consequences instead of working around them |
| Non-loopback bind requires an HTTPS public origin; Host and forwarded headers never trusted | archived console design, `internal/config` | Retained; `publicURL` is required by the chart schema |
| Documented server build generates or verifies templates and assets before packaging; no unpinned fetches | embedded-web "Reproducible generated assets" | Retained; the builder stage runs the same gates and script |
| Tools pinned and installed by `make setup` through versioned `go install` into `.tools/` | project-bootstrap "Repeatable quality and smoke checks"; README Commands | Retained and extended to Helm, kind, kubeconform (verified installable on 2026-09-15) |
| Published development services bind loopback; smoke cleans up only what it creates | project-bootstrap "Local infrastructure isolation", "Repeatable quality and smoke checks" | Retained; the compose `app` profile publishes on loopback and the image smoke uses its own project name |
| README concise; technical detail in specs and design | project-bootstrap "Documented and reproducible project setup" | Retained; the README gains a short Deployment section, the chart README carries the operator contract |
| No backward-compatibility shims before production | owner memory | Retained; nothing here changes an API |

No unresolved departure requires owner approval beyond the decisions recorded in the proposal.

## Decisions

### 1. Builder stage runs the Make targets; runtime is distroless static

```dockerfile
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:… AS builder
# Node 26.8.2 and pnpm 12.3.4 installed from pinned archives/npm, no corepack.
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/
RUN pnpm --dir web install --frozen-lockfile
COPY . .
RUN make install-templ install-sqlc check-db-generated check-web-generated build-web-assets
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=unknown DATE=unknown
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH make compile-server VERSION=$VERSION COMMIT=$COMMIT DATE=$DATE

FROM gcr.io/distroless/static-debian12:nonroot@sha256:…
COPY --from=builder /src/bin/server /server
USER 65532:65532
EXPOSE 8080
ENV CLAVIS_HTTP_ADDR=0.0.0.0:8080
ENTRYPOINT ["/server"]
```

The builder runs on the build platform so `go install` of templ and sqlc produces native tools, and only the final compile takes `GOARCH`. `compile-server` is extracted from `build-server`: no gates, no asset rebuild, atomic output through the existing temp-dir-and-`mv` pattern, `-ldflags "-X github.com/heurema/clavis/internal/buildinfo.Version=… -X …Commit=… -X …Date=…"` from three Make variables defaulting to `dev`/`unknown`. `build-server` becomes gates, `build-web-assets`, `compile-server`. `.dockerignore` lists `.env*` (except the example), `.tools/`, `bin/`, `reports/`, `.local/`, `web/node_modules/`, `internal/web/assets/`, `internal/web/.assets-*/`, `.git/`, `openspec/`, `docs/`.

Alternatives: a bare Go stage copying prebuilt assets would skip the gates and violate embedded-web's build rule; ko and GoReleaser were discussed and set aside (ko cannot run the asset step; GoReleaser earns its place only with the CLI archives, next change). Alpine adds a shell and package manager the server never uses; scratch would need certificates and zoneinfo assembled by hand. Distroless static ships both and a `nonroot` user (65532).

### 2. One permission rule, in `internal/secrets`, used by both readers

```go
// ProtectedFile reports whether an opened regular file is safe to read as a
// secret: no permissions for others, at most read for the group, and when
// group-read is set the file's group is one the process belongs to.
func ProtectedFile(info os.FileInfo) bool {
    mode := info.Mode().Perm()
    if mode&0o037 != 0 { return false }
    if mode&0o040 == 0 { return true }
    gid := info.Sys().(*syscall.Stat_t).Gid
    return gid == uint32(os.Getegid()) || slices.Contains(groups(), int(gid))
}
```

`ReadBootstrapPassword` and `LoadKeyFile` replace their inline `Perm()&0077` checks with this call on the already opened descriptor's `Stat`, so the symlink and race properties are unchanged. `os.Getgroups` is read once per call; it is cheap and both readers run at most a few times per process. Error categories stay `UNSAFE_PERMISSIONS` and `BOOTSTRAP_FAILED`. Tests cover `0400`, `0600`, `0440` and `0640` with the process's primary group (accepted), `0440` with an unrelated group (refused, needs a second group the test user belongs to or a chown that requires privileges; use `os.Getgroups` to pick a foreign group and skip when the user has only one), `0460`, `0444`, `0404`, `0640` with `0004`, and a world-readable file (refused). The existing FIFO, directory and oversize tests stay.

Alternatives: an init container copying Secrets into an owner-only `emptyDir` needs a second image, a volume and an explanation in every operator's runbook; secret values through environment variables would put them into `kubectl describe`, crash dumps and child processes and abandon the file contract; a `CLAVIS_ALLOW_GROUP_READ` flag is a knob every Kubernetes user must flip and protects nothing.

### 3. Three health endpoints and build identity

The routes in `internal/server/server.go` become:

```go
router.Get("/livez",   func(w, r) { writeJSON(w, 200, live()) })            // {"status":"alive"}
router.Get("/readyz",  func(w, r) { result := check(ctx); writeJSON(w, readyStatus(result), result.Response()) })
router.Get("/healthz", func(w, r) {
    result := check(ctx)
    body := map[string]any{
        "status":  "ok",                      // "unhealthy" when !result.Ready()
        "version": buildinfo.Version,
        "checks":  map[string]any{"live": live(), "ready": result.Response()},
    }
    writeJSON(w, readyStatus(result), body)
})
```

`/livez` and `/readyz` are the old handlers under the Kubernetes names, bodies and codes unchanged, so probes and `clavis doctor` stay one small JSON document. `/healthz` is the aggregate for a person, an uptime monitor or an agent: it runs the same readiness check under the same `DBCheckTimeout`, returns 200 only when live and ready, and nests both bodies so a reader sees which half failed. It carries `version` only; `commit` and `date` go to the `server_started` log entry from `buildinfo.Current()`, alongside `version`. The old `/health/*` paths are removed; the router's not-found handling covers them. `internal/cli/doctor.go` requests `/readyz`; its result contract does not change. `internal/server/server_test.go`, `web_test.go`, `contracts_test.go`, `auth_test.go`, `database_test.go`, `cmd/server/main_test.go`, `internal/cli/cli_test.go`, `auth_test.go`, `scripts/smoke.mjs` and `scripts/build.test.mjs` are renamed accordingly, and `smoke.mjs` gains one `/healthz` assertion in the ready and the outage states. README, PRD section 7.8 and 12 and the chart follow.

Alternatives: keeping `/health/*` beside the new paths would be a compatibility shim the project does not carry before production; putting the version into `/livez` would change a body three suites and the CLI depend on for no gain over `/healthz`.

### 4. Chart shape

```
deploy/charts/clavis/
  Chart.yaml            # apiVersion v2, version 0.1.0, appVersion from the image tag
  values.yaml
  values.schema.json    # required: publicURL, secrets.database, secrets.encryptionKey
  templates/
    _helpers.tpl        # names, labels, selector, image reference, validation
    deployment.yaml serviceaccount.yaml service.yaml
    ingress.yaml httproute.yaml networkpolicy.yaml pdb.yaml
    NOTES.txt
  ci/                   # representative value sets for chart-lint
    default.yaml ingress.yaml httproute.yaml full.yaml bootstrap.yaml csi-key.yaml
    fail-no-public-url.yaml fail-both-routes.yaml
  README.md
```

Values, abbreviated:

```yaml
image: { repository: ghcr.io/heurema/clavis, tag: "", digest: "", pullPolicy: IfNotPresent }
replicaCount: 1
strategy: { type: RollingUpdate, rollingUpdate: { maxUnavailable: 0, maxSurge: 1 } }
publicURL: ""                       # required, https://…
server: { logLevel: info, sessionTTL: 8h, dbCheckTimeout: 2s, shutdownTimeout: 10s }
secrets:
  database:      { secretName: "", key: database-url }
  encryptionKey: { secretName: "", key: encryption-key, mountPath: /var/run/secrets/clavis/encryption-key, external: false }
bootstrap:
  enabled: false
  username: ""
  password:      { secretName: "", key: password, mountPath: /var/run/secrets/clavis/bootstrap-password, external: false }
service: { type: ClusterIP, port: 80 }
ingress:   { enabled: false, className: "", annotations: {}, host: "", tls: [] }
httpRoute: { enabled: false, parentRefs: [], hostnames: [] }
networkPolicy: { enabled: false, ingress: [], egress: [] }   # DNS and the database are the operator's rules
podDisruptionBudget: { enabled: false, minAvailable: 1 }
podSecurityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: { type: RuntimeDefault } }
securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
resources: {}
extraEnv: []  extraVolumes: []  extraVolumeMounts: []
nodeSelector: {}  tolerations: []  affinity: {}  podAnnotations: {}  podLabels: {}
```

Rules, enforced in `_helpers.tpl` with `fail` and mirrored in the schema: `publicURL` required and `https://`; `ingress` and `httpRoute` not both enabled; when `bootstrap.enabled`, `username` and the password reference required; `external: true` on a file reference skips the Secret volume and mount but still sets the `*_FILE` variable to `mountPath`. Secret volumes use `defaultMode: 0440`, the `nonroot` user with `fsGroup` 65532 then reads them under decision 2. `CLAVIS_HTTP_ADDR` is `0.0.0.0:8080` from the image and repeated by the chart so `helm template` shows it; the Service targets port `http`. Probes: liveness `/livez` period 10 s; readiness `/readyz` period 5 s, timeout `dbCheckTimeout + 1s` rounded up, failure threshold 3; no startup probe by default, the initializer retries on its own and liveness is independent. `terminationGracePeriodSeconds` is `shutdownTimeout + 5s`. `automountServiceAccountToken: false`. Chart `version` and `appVersion` are independent; the image `tag` defaults to `appVersion` and `digest` wins when set, which is what Flux image automation and Renovate expect.

Alternatives: bjw-s app-template or another library chart trades forty lines of templates for a second abstraction operators must learn; Kustomize is a second delivery format for one Deployment.

### 5. Chart verification: lint, template, kubeconform, offline

`make chart-lint` runs `helm lint --strict` and, for each file in `ci/`, `helm template` piped to `kubeconform -strict -summary` with `-schema-location` pointing at schema sets `make setup` downloads once into `.tools/kube-schemas/` (Kubernetes 1.34 from the kubernetes-json-schema repository and the Gateway API `HTTPRoute` schema from the CRDs catalog, both pinned by commit), so the check needs no network. The two `fail-*` sets must fail with the expected message. `chart-lint` joins `make check` after `build`. Helm 4.1.4, kind 0.31.0 and kubeconform 0.7.0 install through `go install` into `.tools/<tool>/bin/` with `HELM_VERSION`, `KIND_VERSION` and `KUBECONFORM_VERSION` in the Makefile, verified during planning.

### 6. Image smoke on compose, health only

`compose.yaml` gains an `app` service under `profiles: [app]`: `image: clavis:local`, `depends_on: db: condition: service_healthy`, `CLAVIS_DATABASE_URL` pointing at `db:5432`, `CLAVIS_PUBLIC_URL=https://clavis.local`, the key and a bootstrap password bind-mounted read-only from files the smoke script creates with mode `0440` and the container's group, port published on `127.0.0.1:${CLAVIS_APP_PORT:-8081}`. `scripts/smoke-image.mjs` uses its own compose project name like `smoke.mjs`, builds nothing (it requires `make image` first, or is invoked by `make smoke-image` which depends on `image`), waits for `/livez` then `/readyz` to report `ready`, checks `/login` and one embedded asset, reads `/proc/1/status` through `docker inspect`-free means (`docker top`) to confirm uid 65532, and tears the project down with its volume. Because the container binds a non-loopback address, the origin is HTTPS and browser sign-in is out of reach without a TLS proxy; the CLI does not send an `Origin` header, so the script may additionally run `clavis doctor` and `clavis login` against the published port. The development database volume is untouched by construction: a separate project name creates a separate volume.

### 7. Kind verification script

`scripts/verify-kind.mjs` (`make verify-kind`) creates a kind cluster with a pinned `kindest/node` digest, installs CloudNativePG? No: it runs a plain `postgres:18.6` Deployment and Service from an inline manifest, the same image compose pins, to keep the cluster free of operators. It builds two images: `clavis:kind-a` from the checkout and `clavis:kind-b` from a temporary copy of the checkout (the `mkdtemp` pattern from `scripts/mutation.mjs`) with an extra `900_verify.sql` migration creating one empty table, so the second image carries an additional migration without touching the tree; `kind load docker-image` loads both. Then: create the three Secrets; `helm install` with `bootstrap.enabled=true`; wait for `ready`; port-forward and run `clavis doctor`, `clavis login`, `clavis whoami`; `helm upgrade` with `bootstrap.enabled=false`; delete the bootstrap Secret; `kubectl rollout restart` and confirm `ready` and sign-in; `helm upgrade` to `clavis:kind-b`; watch the rollout, confirm the old pod's readiness turns false after the new pod is ready, confirm `ready` and sign-in; `helm template` output of the installed values validates. `kind delete cluster` runs in a `finally`. Each step writes to `reports/verify-kind.json` like the smoke summary. This script is the manual version of the CI job the next change automates.

### 8. Documentation split

README gains prerequisites (Docker already, Helm/kind/kubeconform via setup), Commands rows for `image`, `chart-lint`, `smoke-image`, `verify-kind`, and a Deployment section of about ten lines pointing at `deploy/charts/clavis/README.md`. The chart README carries the operator contract: prerequisites, the three Secrets and an External Secrets example, `publicURL` and TLS termination, bootstrap lifecycle, upgrade behaviour and rollback limit, PgBouncer pooling mode, key rotation not supported, backups of the database and key together, CloudNativePG in one sentence, file-based providers through `extraVolumes`. PRD section 12's status paragraph records the image and chart.

## Risks / Trade-offs

- [The group check refuses a `0440` file when the container runtime does not add `fsGroup` to supplementary groups] → Kubernetes always does for volume ownership; the kind run proves it on a real kubelet, and the README names `fsGroup` as required when operators override the security context.
- [A contributor's `make check` now needs schema files from setup] → `chart-lint` fails with a message naming `make setup` when `.tools/kube-schemas/` is missing, like the other tool pins.
- [Builder stage time: pnpm install, templ, sqlc, Go compile] → layer order caches module and package downloads; the gates run once per source change. Multi-arch builds compile twice, which buildx does in parallel.
- [The kind script depends on Docker resources and takes minutes] → it is not part of `make check`; it is the pre-archive evidence and the seed of the CI job.
- [`fail` in templates versus `values.schema.json` disagreeing] → both are exercised by the `ci/` sets, including the two failure sets.
- [Upgrade interruption surprises an operator] → the README states it plainly and the chart never claims zero downtime.
- [A future Node release drops the archive layout the builder downloads] → the Node and pnpm versions are pinned with checksums in the Dockerfile and updated with `.node-version`.

## Migration Plan

No data or API change. The reader change is backward compatible for owner-only files. Contributors run `make setup` once more to install the three tools and the schema sets. Operators do not exist yet; the first deployment follows the chart README.

## Open Questions

- Whether Node 26 archives for `linux/arm64` builders exist for every build host the team uses; if the builder image must be amd64-only, `--platform=$BUILDPLATFORM` still works under emulation. To be confirmed in slice 1.
- The Gateway API CRD schema source and version to pin for kubeconform; the implementer picks the current stable `HTTPRoute` (v1) schema and records the commit.
