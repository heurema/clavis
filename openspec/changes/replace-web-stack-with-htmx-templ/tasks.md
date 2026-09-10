## 1. Pin the replacement toolchain and components

- [x] 1.1 Add pinned templ 0.3.1020 compiler/runtime, htmx 4.0.0 and Tailwind CLI 4.3.3 inputs using the existing setup tooling; verify exact versions, frozen installation and compiler compatibility with the repository's Go version, and record any baseline correction in the design.
- [x] 1.2 Import only the selected templUI 1.13.2 controls, required utilities/icons and matching scripts into `internal/web/ui`; verify a minimal composed component compiles and retain upstream revision, local modifications and required copyright/permission notices inline in source, without standalone license files, notice Markdown files or a web README.
- [x] 1.3 Establish checked-in `.templ`/`*_templ.go` ownership and ignored public asset staging; verify explicit generation succeeds, `templ generate -check` detects a stale generated file without rewriting it, and handwritten source remains unchanged by checks.

## 2. Build and serve the embedded application

- [x] 2.1 Add deterministic CSS/script/notice preparation for `internal/web/assets` with pinned local inputs; verify the staged set contains every referenced asset and a missing input or failed CSS build exits unsuccessfully instead of retaining a successful stale output.
- [x] 2.2 Add embedded public asset serving under `/assets/`; verify Go HTTP tests cover correct MIME/cache headers, successful file retrieval, and 404 responses for unknown paths, directories and private-file probes.
- [x] 2.3 Add buffered templ rendering for `GET /` and `GET /ui/readiness`, sharing the bounded readiness check with the JSON handler; verify ready/503 fragments, safe rendering failures, cache prevention, and initial document availability with the database unavailable.
- [x] 2.4 Protect the existing `/health/live`, `/health/ready` and CLI contracts while mounting the UI on the same router; verify existing Go/CLI tests plus requests with HTML/partial-request headers still receive the documented JSON responses.
- [x] 2.5 Add `make build-server`, `make build-cli`, asset/generation prerequisites and atomic binary output as described in the design; verify the server builds with `CGO_ENABLED=0`, missing generation stops the build, and CLI-only compilation invokes no web tools.

## 3. Replace the setup page and its browser behavior

- [x] 3.1 Recreate the Clavis shell/status page with templ and the selected templUI controls; restore pinned Playwright 1.63.0 and verify responsive layout, real labels and service states against bootstrap commit `4e27c5a0645858bb2ebdcc9c06e27a4cc75a12c3` without adding unimplemented product screens.
- [x] 3.2 Implement the initial htmx check, manual retry, a shared cancellation scope, checking state and five-second deadline including body reads; verify browser cases for ready, known 503, timeout, a stalled body, superseded responses, and absence of polling or automatic retries.
- [x] 3.3 Gate readiness swaps by expected status, content type and the application fragment marker, and render safe local failure messages; verify unexpected 200/500 bodies, absent markers and unrecognized redirect results containing sentinel secrets never enter the DOM.
- [x] 3.4 Preserve `clavis.appearance`, system appearance changes and blocked-storage fallback with embedded application scripts; verify persistence, reload behavior and in-memory interaction without introducing additional persisted state.
- [x] 3.5 Keep retry/theme controls and announcements usable across partial replacements, load component scripts once, and cover inserted controls in an isolated fixture where needed; verify keyboard focus, Space/Enter behavior, accessible names and a single action after repeated initialization.

## 4. Verify single-binary deployment and recovery

- [ ] 4.1 Change the smoke runner to start a copied server executable from an empty temporary directory and use that same origin for the browser and JSON requests; verify styles, scripts, icons, notices, theme and retry load with third-party requests blocked and without frontend tools in the server process's executable search path.
- [ ] 4.2 Preserve real PostgreSQL outage/recovery and CLI doctor coverage against the copied server; verify liveness remains available, readiness changes 200/503 correctly, and database recovery updates the loaded browser without reload.
- [ ] 4.3 Replace the fresh-navigation API-down smoke case with an already-loaded page losing its server, then restarting at the same address; verify a safe failed check followed by successful explicit retry without reload, and document the deliberate fresh-navigation limitation.
- [ ] 4.4 Track temporary directories and every restarted server process in smoke cleanup; verify normal completion and the existing injected-failure path remove only smoke-owned processes/resources and preserve developer database volumes.

## 5. Retire the React workflow and update documentation

- [x] 5.1 Remove React/Vite/TanStack/Ky/Zod/Tremor code, unused dependencies, generated routing, old app tests and obsolete configuration immediately, as approved by the user; verify a frozen install and repository search find no active imports or runtime references to the retired stack outside OpenSpec's migration/history records. A temporary lack of browser UI is accepted.
- [x] 5.2 Reduce the development package to the asset and validation tools still used; update `scripts/check.mjs`, tool checks, generated-code exclusions and mutation exclusions for `*_templ.go` and copied UI code; verify relevant lint/tests still run and generated/vendor code is excluded from mutation targets while handwritten behavior remains covered. Preserve API/CLI database outage/recovery smoke independently of the removed browser harness and explicitly report pending browser coverage.
- [ ] 5.3 Introduce the single-server `make dev` flow using existing environment-loading scripts, retain `dev-api` only as an alias, and remove `dev-web` and `CLAVIS_API_PROXY`; verify one command starts the UI and API at the configured address and termination cleans up the process.
- [ ] 5.4 Update the root README, environment examples, inline source attribution/permission notices and current PRD stack sentence; verify instructions distinguish development prerequisites from binary runtime requirements, retain external PostgreSQL and optional CLI, and describe the new outage behavior without rewriting the archived design or adding web README/notice Markdown/standalone license files.

## 6. Complete migration verification

- [ ] 6.1 Run setup, generated-source checks, formatting/static checks, relevant Go/browser tests and full builds from a clean checkout or equivalent isolated copy; verify successful commands do not modify tracked files and failures return nonzero.
- [ ] 6.2 Run the full real-database smoke suite and existing mutation compatibility/reporting command with the revised exclusions; verify standalone artifact behavior, unchanged CLI outcomes, bounded recovery/cleanup and meaningful handwritten mutation scope, recording execution results only in ignored local reports.
