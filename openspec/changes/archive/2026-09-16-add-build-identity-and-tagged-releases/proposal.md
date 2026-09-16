## Why

There is no release. One tag exists without a GitHub Release, no image or chart has been published, and `deploy/charts/clavis/values.yaml` points at `ghcr.io/heurema/clavis`, which is empty. The first beta users arrived on September 16, 2026, and one of them reported `clavis version` printing `dev` after `go install github.com/heurema/clavis/cmd/clavis@v0.1.0-rc.1`, which is how they obtained the CLI. The next two changes in `docs/plans/2026-09-16-cli-sign-in-profiles-release.md` each require a CLI upgrade, so a tag has to produce something people can install and every install path has to say which version it is.

## What Changes

- One GitHub Actions workflow on a `v*` tag push that runs `make check`, builds the CLI for darwin and linux on amd64 and arm64 with the tag as its version, builds and pushes the server image for both architectures to `ghcr.io/heurema/clavis`, packages and pushes the chart to `oci://ghcr.io/heurema/charts`, and creates a GitHub Release on the tag with the binaries and their checksums. A tag with a hyphen is a pre-release.
- `internal/buildinfo` falls back to the Go toolchain's embedded build information for each value the linker flags left at its default: the version to the main module version, the commit to the VCS revision, the date to the VCS commit time. Linker flags keep precedence. So a release binary reports the tag from its flags, `go install` at a tag reports that tag from the module metadata, a build from a checkout reports the pseudo-version with the revision and a dirty marker, and a source export or a test binary still reports `dev` and `unknown`.
- `make build-cli` stamps version, commit and date like `compile-server` and honours `GOOS`/`GOARCH`; `make image` accepts extra Docker flags for the platform list and the push.
- The README says how to release (push a tag) and the two supported ways to install the CLI, `go install` at a tag or the binary from the Release; the chart README shows the OCI install command.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `deployment-packaging`: "Build identity" gains the fallback to the toolchain's build information and its precedence rule, and the CLI joins the server in stamping; a requirement "Tagged release" is added for the workflow and its artifacts.

## Impact

- `internal/buildinfo/buildinfo.go` and a new test file; `internal/server/server.go` (`/healthz` reads the resolved identity); the four tests comparing against `buildinfo.Version`.
- `Makefile` (`build-cli`, `IMAGE_FLAGS`), `scripts/build.test.mjs` (one case for the stamped CLI), `.github/workflows/release.yml` (new), `README.md`, `deploy/charts/clavis/README.md`, `docs/PRD.md` section 12 status paragraph.
- Workflow permissions: `contents: write`, `packages: write`. The two GHCR packages are private after the first push until an owner makes them public.
- No new dependency or tool.

## Decisions (2026-09-16)

- Plain shell in one workflow calling the existing Make targets. No goreleaser, no signing, no pull-request workflow, no guard beyond the tag trigger; any of those is a later addition that changes nothing published here.
- The identity is resolved in the executable rather than derived from Git by the build, because `go install` is a supported install path and no build recipe runs on that path. This is where the design departs from kubectl, whose version package has no fallback and whose users are on package managers.
- The tag is the version. The binaries, `/healthz` and the image labels carry it as written, with the `v`; the image tag, the chart version and `appVersion` drop the `v`, because Helm requires a bare semantic version and the chart's default image tag is its `appVersion`. No `latest` tag.
