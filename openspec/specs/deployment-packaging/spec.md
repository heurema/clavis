# deployment-packaging Specification

## Purpose

Ship the server as a container image and a Helm chart an operator can install with existing Secrets and a public URL, with the verification a contributor runs locally to prove both work.

## Requirements

### Requirement: Server container image

The project SHALL provide a documented container image build for the server executable. The image build SHALL run the documented asset generation and the generated-source consistency checks from pinned inputs before compiling, SHALL compile with `CGO_ENABLED=0` and `-trimpath` through the same Make recipe contributors use, and SHALL produce a runtime image that contains the server executable, CA certificates and time zone data on a pinned distroless base with no shell or package manager. The container SHALL run as a non-root user and group with a read-only root filesystem, SHALL listen on a non-loopback address and port fixed by the image, and SHALL be buildable for `linux/amd64` and `linux/arm64` from one definition. The build context SHALL exclude local secrets, ignored tools, built binaries, reports and previously generated assets. The image SHALL NOT include the CLI, the source checkout, development tools or a database.

#### Scenario: Build the image from a clean checkout
- **WHEN** a contributor runs the documented image build command with Docker available
- **THEN** the build generates browser assets, verifies checked-in generated templates and queries, compiles the server and produces a runnable image without reading `.env`, `.tools/`, `bin/` or an existing `internal/web/assets/` from the checkout

#### Scenario: Generated source is stale
- **WHEN** a maintained template or query changes without its checked-in generated source being updated
- **THEN** the image build exits unsuccessfully instead of producing an image from stale source

#### Scenario: Run the image against an initialized database
- **WHEN** the image runs with valid environment configuration, a mounted encryption key file and a reachable initialized PostgreSQL
- **THEN** the container serves liveness, readiness, the sign-in document and embedded assets on its fixed port as a non-root process with a read-only root filesystem
- **AND** outbound HTTPS to a provider succeeds using the image's certificate store

### Requirement: Build identity

Release builds SHALL stamp version, commit and date into `internal/buildinfo` through the documented linker flags, and the Make compile recipe SHALL accept them as variables so the Dockerfile and contributors stamp the same way. The server SHALL record `version`, `commit` and `date` in its structured startup log entry and SHALL report `version` in the `/healthz` aggregate defined by project-bootstrap. Local builds without the flags SHALL report `dev` and `unknown`. The `/livez` and `/readyz` bodies SHALL NOT carry build identity.

#### Scenario: Stamped image starts
- **WHEN** an image built with version `1.2.3`, a commit and a date starts
- **THEN** the startup log entry carries those three values, `/healthz` reports version `1.2.3`, and the `/livez` body is still exactly `{"status":"alive"}`

#### Scenario: Local build starts
- **WHEN** a contributor runs a server built without the flags
- **THEN** the startup log entry reports version `dev` and commit and date `unknown`, and `/healthz` reports version `dev`

### Requirement: Helm chart contract

The project SHALL provide a Helm chart for the server under `deploy/charts/clavis` with a `values.schema.json` and a README. The chart SHALL render a Deployment, a Service and a ServiceAccount without an automounted token, and SHALL render an Ingress, a Gateway API HTTPRoute, a NetworkPolicy and a PodDisruptionBudget only when each is enabled; Ingress and HTTPRoute SHALL be mutually exclusive. The Deployment SHALL run one replica by default with the RollingUpdate strategy at `maxUnavailable: 0` and `maxSurge: 1`, exposed as values; SHALL set the liveness HTTP probe on `/livez` and the readiness HTTP probe on `/readyz` with a readiness timeout above the configured database check timeout; SHALL set a termination grace period above the configured shutdown timeout; and SHALL apply a pod security context that runs as a fixed non-root user, sets `fsGroup` to the same group, forbids privilege escalation, drops all capabilities, uses the runtime default seccomp profile and mounts the root filesystem read-only. The chart SHALL set the listener address to all interfaces on the image port and SHALL require an explicit `publicURL` value that the server accepts as an HTTPS origin; rendering without it SHALL fail with a message naming the value. Every server setting the chart exposes SHALL map to its documented `CLAVIS_*` variable, and the chart SHALL accept additional environment variables, volumes and volume mounts as pass-through values. The chart SHALL NOT render, require or manage PostgreSQL or any other database resource.

#### Scenario: Render with defaults and a public URL
- **WHEN** the chart is templated with the required secret references and `publicURL` set to an HTTPS origin
- **THEN** it renders exactly a Deployment, a Service and a ServiceAccount, the Deployment carries the probes, security context, strategy and environment mapping above, and the rendered manifests validate against the pinned Kubernetes schemas

#### Scenario: Render without a public URL
- **WHEN** the chart is templated without `publicURL`
- **THEN** rendering fails and the message names `publicURL`

#### Scenario: Enable both route kinds
- **WHEN** both `ingress.enabled` and `httpRoute.enabled` are true
- **THEN** rendering fails and the message says they are mutually exclusive

#### Scenario: Enable optional resources
- **WHEN** Ingress or HTTPRoute, NetworkPolicy and PodDisruptionBudget are enabled with their required values
- **THEN** each renders with the chart's labels and selectors and validates against the pinned Kubernetes and Gateway API schemas

### Requirement: Secrets by reference

The chart SHALL take the database URL, the encryption key and the bootstrap password as references to existing Secrets, each with a configurable Secret name and key, and SHALL NOT accept any secret value as a chart value. The three references MAY name the same Secret. The database URL SHALL be injected as `CLAVIS_DATABASE_URL` from the referenced key. The encryption key and the bootstrap password SHALL be mounted as files at chart-owned absolute paths with mode `0440`, and their `CLAVIS_*_FILE` variables SHALL point at those paths; both paths SHALL be overridable so a file-based secret provider can supply the file through a pass-through volume instead, in which case the chart SHALL NOT render the Secret volume for it. The chart SHALL NOT generate, rotate or delete the encryption key.

#### Scenario: Secrets from an external secrets operator
- **WHEN** an operator supplies one Secret produced by an external secrets tool holding the three keys and points the three references at it
- **THEN** the pod starts with the database URL in its environment and the two files readable by the server process under `fsGroup`, and no secret value appears in the rendered manifests

#### Scenario: Key supplied by a file-based provider
- **WHEN** the encryption key path is overridden and a pass-through volume mount supplies that file
- **THEN** the chart renders no encryption key Secret volume and the server reads the key from the overridden path

#### Scenario: Key value changes in the store
- **WHEN** the referenced encryption key Secret changes while the release is deployed
- **THEN** the running pod keeps its loaded key, and the chart README states that a restart with a different key makes stored credentials unrecoverable

### Requirement: Bootstrap as an explicit installation input

The chart SHALL expose bootstrap as a block with `enabled`, `username` and a password Secret reference. When enabled, the chart SHALL set `CLAVIS_BOOTSTRAP_USERNAME` and mount the password file; when disabled, it SHALL render neither the variables nor the volume, so the referenced Secret can be deleted afterwards. The chart SHALL NOT inspect cluster state, delete Secrets, or vary behaviour by Helm revision. The README SHALL document the lifecycle: enable for the first install, wait for readiness, disable, upgrade, then delete the bootstrap Secret.

#### Scenario: First install
- **WHEN** the chart is installed with bootstrap enabled against a fresh database
- **THEN** readiness becomes `ready` and the configured administrator can sign in through the CLI

#### Scenario: Bootstrap disabled after setup
- **WHEN** the release is upgraded with bootstrap disabled and the bootstrap Secret is then deleted
- **THEN** replacement pods start without the Secret, readiness stays `ready` and the administrator account is unchanged

### Requirement: Documented upgrade behaviour

The chart README SHALL state that an upgrade whose image carries a new migration interrupts service for about one readiness period, that image rollback across a migration is unsupported because the ledger is forward-only, that PostgreSQL must be a direct endpoint or a session-pooling proxy because migrations hold a session-level advisory lock, and that the database and the encryption key must be backed up together. The README SHALL NOT claim zero-downtime upgrades.

#### Scenario: Upgrade across a migration
- **WHEN** a release is upgraded to an image that applies a new migration
- **THEN** the new pod migrates and becomes ready, the old pod fails closed until it is replaced, and readiness is `ready` afterwards with the administrator account intact

### Requirement: Image and chart verification commands

The project SHALL provide documented non-interactive commands that build the image, lint and schema-validate the chart against representative value sets including each optional resource and the failure cases, run the built image against the local compose database and verify its health endpoints and non-root execution, and verify the chart on a throwaway kind cluster with a fresh bootstrap, a restart with bootstrap disabled, an upgrade across a migration and a CLI sign-in over a port-forward. Helm, kind and kubeconform SHALL be pinned and installed by the setup command through versioned `go install` like the other Go tools. The chart lint SHALL be part of the documented quality check; the image smoke and kind verification SHALL be separate documented commands that clean up only what they create. Docker and `kubectl` SHALL remain the only prerequisites these commands add beyond the setup command; `kubectl` is needed by the kind verification alone and cannot be installed through `go install`, so the README documents it.

#### Scenario: Chart lint in the quality check
- **WHEN** a contributor runs the documented quality check
- **THEN** the chart is linted and each representative value set is rendered and validated, and a template error or schema violation fails the check and names the value set

#### Scenario: Image smoke
- **WHEN** a contributor runs the image smoke command with Docker and the compose database available
- **THEN** the built image starts under its own compose profile against that database, liveness and readiness are verified over the loopback-published port, the process is confirmed to run as the non-root user, and the container and its data are removed afterwards without touching the development database volume

#### Scenario: Kind verification
- **WHEN** a contributor runs the kind verification command
- **THEN** it creates a throwaway cluster, loads the local image, installs the chart with bootstrap enabled, waits for readiness, signs in with the CLI over a port-forward, upgrades with bootstrap disabled and the bootstrap Secret removed, upgrades to an image with an additional migration and confirms readiness and sign-in again, then deletes the cluster even when an assertion fails
