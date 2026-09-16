# Clavis Helm chart

Installs the Clavis server: one Deployment, one Service and one ServiceAccount,
with an optional Ingress or Gateway API HTTPRoute, NetworkPolicy and
PodDisruptionBudget. The chart owns no database and no Secret. Values are
documented inline in `values.yaml` and constrained by `values.schema.json`.

## Prerequisites

- Kubernetes 1.25 or newer, and a Gateway API installation if you use
  `httpRoute`.
- PostgreSQL 17 or 18, reachable from the pod, as a **direct endpoint or
  a session-pooling proxy** (see [Upgrades](#upgrades)).
- Three values in existing Secrets in the release namespace: the database URL,
  the encryption key, and, for the first install only, the administrator's
  initial password.
- TLS terminated in front of the Service, at the Ingress controller or the
  Gateway listener. The server speaks plain HTTP on port 8080 inside the pod
  and never infers its public origin from forwarded headers.

## Installing

Released charts are published as OCI artifacts beside the server image, at the
release version without its leading `v`. The chart's `appVersion` is that same
version and supplies the default image tag, so a version pins both halves:

```sh
helm install clavis oci://ghcr.io/heurema/charts/clavis --version 0.1.0 \
  --set publicURL=https://clavis.example.com \
  --set secrets.database.secretName=clavis \
  --set secrets.encryptionKey.secretName=clavis
```

Use the checked-out `deploy/charts/clavis` path instead when you are testing an
unreleased change to the chart itself.

## Secrets

The chart takes the three secrets **by reference** and never accepts a secret
value, generates one, rotates one or deletes one. Each reference is a Secret
name and a key, and all three may name the same Secret:

| Value                              | Becomes                                     | Default key      |
| ---------------------------------- | ------------------------------------------- | ---------------- |
| `secrets.database.secretName`      | `CLAVIS_DATABASE_URL` in the environment    | `database-url`   |
| `secrets.encryptionKey.secretName` | a file at `secrets.encryptionKey.mountPath` | `encryption-key` |
| `bootstrap.password.secretName`    | a file at `bootstrap.password.mountPath`    | `password`       |

The two files are mounted read-only with mode `0440`, and the pod's `fsGroup`
65532 owns them. That is exactly what the server accepts: a secret file may
grant nothing to others and at most read to a group the process belongs to. If
you override `podSecurityContext`, **keep an `fsGroup` the container's user
belongs to** or the server refuses to start with `UNSAFE_PERMISSIONS`.

Each file is placed on its own absolute path with `subPath`, so the two
references may name different Secrets and still share a directory. A `subPath`
mount does not follow later Secret updates; that is immaterial here, because
the server reads both files once at startup.

### One Secret from External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: clavis
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: clavis
    creationPolicy: Owner
  data:
    - secretKey: database-url
      remoteRef:
        key: clavis/postgres
        property: url
    - secretKey: encryption-key
      remoteRef:
        key: clavis/encryption
        property: key
    # Only for the first install. Afterwards drop this entry so the operator
    # removes the key from the Secret. Do not delete the Secret itself: the
    # database URL and the encryption key live in it too.
    - secretKey: password
      remoteRef:
        key: clavis/bootstrap
        property: password
```

```yaml
secrets:
  database: { secretName: clavis }
  encryptionKey: { secretName: clavis }
bootstrap:
  enabled: true
  username: owner
  password: { secretName: clavis }
```

### A file-based provider instead

A Secrets Store CSI driver, or anything else that projects a file, supplies the
key without a Secret volume: set `external: true`, point `mountPath` at the file
the provider writes, and mount the provider's volume through the pass-through
values. `secrets.encryptionKey.secretName` stays required by the schema but
nothing in the rendered manifest references it. See `ci/csi-key.yaml`.

```yaml
secrets:
  encryptionKey:
    secretName: clavis
    mountPath: /mnt/secrets-store/encryption-key
    external: true
extraVolumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes: { secretProviderClass: clavis }
extraVolumeMounts:
  - name: secrets-store
    mountPath: /mnt/secrets-store
    readOnly: true
```

### The encryption key is not rotatable

Connection credentials are encrypted at rest under the key, which is read once
at startup and held in memory. Changing the value in the store does nothing to
a running pod; **restarting with a different key makes every stored connection
credential unrecoverable**. There is no rotation path yet. Back up the database
and the encryption key together, and restore them together: either alone is
useless.

## Public URL and TLS

`publicURL` is required and must be an `https://` origin — scheme and host, no
path. The container binds all interfaces, and the server refuses a non-loopback
bind without an HTTPS origin, so a rendered manifest without `publicURL` is a
pod that cannot start; the chart fails the render instead. Terminate TLS at the
Ingress (`ingress.tls`) or at the Gateway listener your `httpRoute.parentRefs`
names, and make sure the origin you terminate matches `publicURL` exactly.
`ingress` and `httpRoute` are mutually exclusive.

## Bootstrap lifecycle

The initial administrator is created once, against a fresh database, from
`bootstrap.username` and the mounted password file. Subsequent starts ignore
bootstrap inputs; they never reset credentials. The chart does not inspect
cluster state and does not vary by Helm revision, so the lifecycle is yours:

1. Install with `bootstrap.enabled=true`, a username and the password Secret.
2. Wait until readiness reports `ready`
   (`kubectl port-forward` and `curl /readyz`, or `clavis doctor`).
3. Sign in and confirm the account works.
4. Upgrade with `bootstrap.enabled=false`. The variables and the volume
   disappear from the pod template, so the pod is replaced without them.
5. Get rid of the initial password. **Which action depends on whether the
   bootstrap Secret is its own Secret.** When `bootstrap.password.secretName`
   differs from both `secrets.database.secretName` and
   `secrets.encryptionKey.secretName`, delete the Secret. When it names the
   same Secret as either of them — as the External Secrets example above does —
   remove only the `bootstrap.password.key` key, at the source your secret
   tooling writes it from. Deleting a shared Secret takes the database URL or
   the encryption key with it. `NOTES.txt` prints whichever applies to your
   values.

Doing step 5 before step 4 leaves the pod template referencing a file that no
longer exists, and the next pod never starts: the kubelet cannot mount the
volume and the pod sits in `ContainerCreating` with a `FailedMount` event.

## Upgrades

**This chart does not claim zero-downtime upgrades.**

- The server applies its embedded migrations at startup under a session-level
  advisory lock, and the migration ledger is forward-only and fails closed on a
  row it does not recognize. When a new image carries a new migration, the old
  pod stops serving the moment the migration commits, and it is removed once
  the new pod is ready, so the interruption is about one readiness period.
- **Rolling back an image across a migration is unsupported.** The older
  executable sees a ledger row it does not know and refuses to serve. Roll
  forward, or restore the database and the encryption key together from backup.
- PostgreSQL must be a direct endpoint or a **session-pooling** proxy.
  Transaction or statement pooling (PgBouncer's default modes) breaks the
  session-level advisory lock the migration holds.
- One replica is the supported topology, which is why `replicaCount` defaults
  to 1. Extra replicas do not survive a schema change: every replica older than
  the applied migration fails closed at once.
- Back up the database and the encryption key together, before every upgrade
  that carries a migration.

## Database

The chart renders no database resource and never will. Run PostgreSQL as a
managed service, or in the cluster with an operator such as
[CloudNativePG](https://cloudnative-pg.io/), and put the resulting connection
URL into the Secret `secrets.database.secretName` names.

## Optional resources

- `ingress` — Ingress with an optional class, annotations, host, path and TLS.
- `httpRoute` — Gateway API `HTTPRoute` (v1); `parentRefs` is required.
- `networkPolicy` — declares both directions, so **empty rule lists deny
  everything, DNS included**. Supply the egress rules your cluster needs to
  reach DNS and PostgreSQL. See `ci/full.yaml` for a worked example.
- `podDisruptionBudget` — with one replica, `minAvailable: 1` blocks voluntary
  evictions such as a node drain until an operator intervenes.

## Health and probes

Liveness is `GET /livez` and is independent of the database: the process serves
the public sign-in document while the initializer retries in the background.
Readiness is `GET /readyz`, 200 only when the database is reachable, the schema
is supported and the installation is initialized. `GET /healthz` aggregates
both and reports the build version. The chart derives the readiness probe
timeout from `server.dbCheckTimeout` (plus one second, rounded up) and
`terminationGracePeriodSeconds` from `server.shutdownTimeout` (plus five
seconds), so raising either value raises the probe bound with it. Durations use
Go syntax with the units `ms`, `s`, `m` and `h`, optionally combined: `2s`,
`500ms`, `1m30s`. Every duration must be greater than zero, and
`server.sessionTTL` must be between `5m` and `24h`; the chart refuses to render
values the server would reject at startup.

## Verifying a change to this chart

From the repository root, `make chart-lint` runs `helm lint --strict` and
renders every value set in `ci/` through `kubeconform` against pinned
Kubernetes and Gateway API schemas, including the two sets that must fail. It
is part of `make check` and needs no network after `make setup`.

`make verify-kind` goes further: it builds the image, installs this chart on a
throwaway kind cluster with a first-install bootstrap, disables bootstrap and
restarts, upgrades to an image that carries an extra migration, signs in through
the CLI at each stage and records the secret file modes and the rollout
handover in `reports/verify-kind.json`. It needs Docker and `kubectl` and takes
a few minutes; run it after changing the chart's templates or the image.
