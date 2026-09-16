## Context

`internal/buildinfo` is three package variables, `Version = "dev"`, `Commit = "unknown"`, `Date = "unknown"`, and `Current()` copies them into an `Info`. `compile-server` sets them with `-ldflags -X` from `VERSION`, `COMMIT` and `DATE`; `build-cli` passes no flags; `make image` forwards the three as build arguments and derives them from Git when unset. Readers go through `Current()` except `/healthz`, which reads `buildinfo.Version` directly (`internal/server/server.go:113`), and four test files that compare against the raw variable.

The Go toolchain records its own identity in every executable, readable through `runtime/debug.ReadBuildInfo`. Verified on this checkout with Go 1.27.1 on September 16, 2026: `go install ...@v0.1.0-rc.1` sets the main module version to `v0.1.0-rc.1` and no VCS settings; `go build` from the checkout sets it to a pseudo-version such as `v0.1.0-rc.1.0.20260916143119-5121b0cd463e+dirty` with `vcs.revision`, `vcs.time` and `vcs.modified`; a test binary sets it to `(devel)` with no VCS settings. The Dockerfile excludes `.git/` from its context, so the image depends entirely on its build arguments.

The chart's default image tag is its `appVersion` (`deploy/charts/clavis/templates/_helpers.tpl:53`) and its image repository is already `ghcr.io/heurema/clavis`. `scripts/build.test.mjs` exercises the Make targets in a temporary copy. There is no CI and the repository is public.

## Goals / Non-Goals

**Goals:** a tag produces binaries, an image, a chart and a Release using the recipes contributors already run; every install path reports a truthful version.

**Non-Goals:** signing, guards beyond the tag trigger, a pull-request workflow, a rehearsal target, Windows, package managers.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Release builds stamp identity through linker flags; local builds report `dev` and `unknown` | deployment-packaging "Build identity" | Explicitly changed (delta): flags keep precedence, the toolchain's build information fills unset values, and only a build with neither reports `dev` and `unknown`; the CLI recipe joins the server |
| `/healthz` carries the version only; commit and date stay in the startup log | archived `package-image-and-chart` design decision 3 | Retained; it now reads the resolved version, same field, same shape |
| Image build runs the gates and compiles through `compile-server` from build arguments; multi-architecture from one definition | deployment-packaging "Server container image" | Retained; the workflow calls `make image` with extra flags |
| Chart version and `appVersion` independent | `Chart.yaml` comment | Narrowed (owner 2026-09-16): both equal the release version; independence not exercised |
| Tools pinned, no remote installer | project-bootstrap; README | Retained; the workflow uses the runner's Go, Node, Docker and `gh` plus `make setup` |
| The skill stamp carries the build version, never a hand-written number | agent-skill; `internal/skill/skill.go:77` | Retained; it now carries a truthful one |
| Publishing and CI deferred from the packaging change | archived `package-image-and-chart` proposal | Publishing delivered; signing and the pull-request workflow stay deferred |

## Decisions

### 1. Resolution in `buildinfo`: per-value fallback, flags first, computed once

```go
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func Current() Info { once.Do(func() { current = resolve(Version, Commit, Date, debug.ReadBuildInfo) }); return current }
```

`resolve` takes the three linker values and a reader, so the test injects a fabricated `*debug.BuildInfo` and never depends on how the test binary itself was built. The rules, each independent of the others:

- version: keep the flag value unless it is `dev`; else the main module version unless it is `""` or `(devel)`; else `dev`.
- commit: keep the flag value unless it is `unknown`; else the `vcs.revision` setting; else `unknown`.
- date: keep the flag value unless it is `unknown`; else the `vcs.time` setting; else `unknown`.

`vcs.modified` is not read: the toolchain already appends `+dirty` to the version it derives, and a release build has no VCS settings. `Info` keeps its three fields and JSON shape, so `clavis version` does not change shape and `schemaVersion` stays 1. `/healthz` switches to `buildinfo.Current().Version` and the four test comparisons follow, which also makes them independent of how the test binary was built; `internal/cli/cli_test.go` still sees `dev` because a test binary reports `(devel)`.

This is where the design departs from kubectl, which has no fallback and does not support `go install`. For a Go CLI whose users are developers and agents, `go install` at a tag is the one-line install path and the beta user already took it.

### 2. Version forms

| Place | Form | Example |
|---|---|---|
| Git tag, GitHub Release, `VERSION` linker value, `go install` argument, `clavis version`, `/healthz`, image labels | as written | `v0.1.0-rc.2` |
| Image tag, chart version, chart `appVersion`, binary names | without `v` | `0.1.0-rc.2` |

Binary names: `clavis_<version>_<os>_<arch>` with a `SHA256SUMS` beside them. Pre-release when the tag contains `-`.

### 3. Make targets

`build-cli` gains the `-ldflags` block from `compile-server` and honours `GOOS`/`GOARCH`; its name and its Go-only nature stay, which `build.test.mjs` asserts by running it with `NODE=false PNPM=false`. `IMAGE_FLAGS ?=` is appended to the `docker build` in `image`. Nothing else changes.

### 4. The workflow

`.github/workflows/release.yml`, `on: push: tags: ['v*']`, `permissions: {contents: write, packages: write}`, one job on `ubuntu-latest`:

1. Checkout (with tags), `actions/setup-go` from `go.mod`, `actions/setup-node` from `.node-version`, pnpm at the `packageManager` pin, `make setup`.
2. `make check`.
3. `VERSION=$GITHUB_REF_NAME`, `BARE=${VERSION#v}`, `COMMIT=$GITHUB_SHA`, `DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)`; then for each of `darwin/amd64 darwin/arm64 linux/amd64 linux/arm64`: `GOOS=$os GOARCH=$arch make build-cli VERSION=$VERSION COMMIT=$COMMIT DATE=$DATE && mv bin/clavis dist/clavis_${BARE}_${os}_${arch}`; then `(cd dist && sha256sum * > SHA256SUMS)`.
4. `docker/setup-buildx-action`, `docker login ghcr.io` with `GITHUB_TOKEN`, `make image IMAGE=ghcr.io/heurema/clavis:$BARE VERSION=$VERSION COMMIT=$COMMIT DATE=$DATE IMAGE_FLAGS="--platform linux/amd64,linux/arm64 --push"`.
5. `helm registry login ghcr.io` with the same token, `helm package deploy/charts/clavis --version $BARE --app-version $BARE`, `helm push clavis-$BARE.tgz oci://ghcr.io/heurema/charts`. Helm is the one `make setup` installed.
6. `gh release create "$VERSION" --generate-notes [--prerelease] dist/*`.

Every `uses:` pinned by commit SHA with a version comment. No emulation is needed for arm64: the builder cross-compiles and the distroless stage has no `RUN`.

### 5. Documentation

README Deployment section: a short "Releases" paragraph (push a `vX.Y.Z` or `vX.Y.Z-rc.N` tag on `main`, what appears where, and the two install paths, `go install github.com/heurema/clavis/cmd/clavis@<tag>` or the binary from the Release checked against `SHA256SUMS`, both reporting the same version; make the two GHCR packages public once after the first release). Chart README: `helm install clavis oci://ghcr.io/heurema/charts/clavis --version <version>`. PRD section 12 status paragraph: tagged releases exist.

## Risks / Trade-offs

- [No guard that the tag is on `main` or well-formed] → Owner decision; a bad tag produces a bad release that is deleted by hand. The trigger pattern and `${VERSION#v}` are the whole rule.
- [First run is the first real release] → A candidate tag is a pre-release, so `v0.1.0-rc.2` is the rehearsal. A failed run after the image push leaves partial artifacts; re-running the same tag overwrites them.
- [A contributor's `make build` now reports a pseudo-version instead of `dev`] → Intended and documented; the smoke scripts assert only the shape.
- [`go install` reports the tag but `unknown` for commit and date] → Inherent to a proxy install, which carries no VCS data; the version is what identifies the build and the release binaries carry all three.
- [`make check` skips the database suites on the runner] → Same as a contributor without the variable; a pull-request workflow with a database is a later change.
- [GHCR packages start private] → One-time owner action, documented.

## Migration Plan

Merge, push `v0.1.0-rc.2` from `main`, watch the run, make both packages public, then verify both install paths report `v0.1.0-rc.2` and `helm pull` the chart. Rollback is deleting the Release, the tag and the package versions.

## Open Questions

None.
