## MODIFIED Requirements

### Requirement: Build identity

Release builds SHALL stamp version, commit and date into `internal/buildinfo` through the documented linker flags, and the Make compile recipes for the server and the CLI SHALL accept them as variables so the Dockerfile, the release workflow and contributors stamp the same way. For each of the three values the linker flags left at its default, the executable SHALL fall back to the Go toolchain's embedded build information: the version to the main module version when it is neither empty nor `(devel)`, the commit to the VCS revision setting, and the date to the VCS commit time setting; a value with no source in either place SHALL be reported as `dev` or `unknown`. A linker-set value SHALL always take precedence over the build information. Every reader of the identity, including `clavis version`, the skill stamp, the server startup log and `/healthz`, SHALL use the resolved identity rather than the raw linker variables. The server SHALL record `version`, `commit` and `date` in its structured startup log entry and SHALL report `version` in the `/healthz` aggregate defined by project-bootstrap. The `/livez` and `/readyz` bodies SHALL NOT carry build identity.

#### Scenario: Stamped image starts
- **WHEN** an image built with version `v1.2.3`, a commit and a date starts
- **THEN** the startup log entry carries those three values, `/healthz` reports version `v1.2.3`, and the `/livez` body is still exactly `{"status":"alive"}`

#### Scenario: Stamped CLI
- **WHEN** the CLI is built through the documented recipe with version `v1.2.3`, a commit and a date, for any supported operating system and architecture
- **THEN** `clavis version` reports those three values

#### Scenario: CLI installed from a tag with the Go toolchain
- **WHEN** a user runs `go install github.com/heurema/clavis/cmd/clavis@v1.2.3` and then `clavis version`
- **THEN** the version is `v1.2.3` and the commit and date are `unknown`, because the toolchain records the module version but no VCS settings for a proxy install

#### Scenario: Contributor builds from a checkout without the flags
- **WHEN** a contributor runs the documented CLI or server build from a Git checkout without passing the variables
- **THEN** the version is the pseudo-version the toolchain derives from the checkout, the commit is the checkout's full revision and the date is that commit's time, and a modified working tree is visible in the version's dirty marker

#### Scenario: Build without a module version or VCS
- **WHEN** an executable is built from a source export, or a test binary reads the identity
- **THEN** the version is `dev` and the commit and date are `unknown`

#### Scenario: Flags and build information both present
- **WHEN** an executable is built from a checkout with only the version passed as a variable
- **THEN** the version is the passed value, and the commit and date come from the checkout's VCS settings

## ADDED Requirements

### Requirement: Tagged release

The project SHALL provide one GitHub Actions workflow that runs when a tag matching `v*` is pushed. It SHALL run the documented quality check, then publish from that tag: a `clavis` executable for `darwin` and `linux` on `amd64` and `arm64`, each stamped with the tag, with a `SHA256SUMS` file, attached to a GitHub Release on the tag; the server image for `linux/amd64` and `linux/arm64` at `ghcr.io/heurema/clavis` tagged with the version without its leading `v`, built through the documented image recipe; and the chart packaged with that same version as its version and `appVersion`, pushed to `oci://ghcr.io/heurema/charts/clavis`. A tag containing a hyphen SHALL be a pre-release. The workflow SHALL use the existing Make targets, SHALL pin every action by commit SHA, and SHALL need only `contents: write` and `packages: write`. The README SHALL document pushing a tag as the way to release, and both supported ways to install the CLI, `go install` at a tag and the binary from the Release; the chart README SHALL document installation from the OCI registry at a version.

#### Scenario: Release candidate tag
- **WHEN** a maintainer pushes `v0.1.0-rc.2`
- **THEN** the workflow publishes four executables and the checksums on a pre-release, the image at `ghcr.io/heurema/clavis:0.1.0-rc.2` for both architectures, and the chart version `0.1.0-rc.2`, and each executable and the image report version `v0.1.0-rc.2`

#### Scenario: Final tag
- **WHEN** a maintainer pushes `v0.1.0`
- **THEN** the same artifacts are published with version `0.1.0`, the Release is not a pre-release, and no `latest` tag is written

#### Scenario: Both install paths agree
- **WHEN** a user installs release `v1.2.3` with `go install` at that tag and another downloads the binary from the Release
- **THEN** both report version `v1.2.3`

#### Scenario: Quality check fails on the tag
- **WHEN** the documented quality check fails on the tagged commit
- **THEN** the workflow stops and publishes nothing
