## Context

See `proposal.md` for motivation and the delta specs for acceptance behavior. At proposal time, the `web/` application had one React setup page, Tremor Raw controls, a TanStack route tree and readiness query, and a Ky/Zod client. Vite served the page independently and proxied `/api` to Go; the smoke suite launched both processes and expected the page to remain available when Go stopped. That reference implementation is preserved in bootstrap commit `4e27c5a0645858bb2ebdcc9c06e27a4cc75a12c3`.

The user has selected htmx, templ and templUI and wants a simple binary deployment. The existing CLI-first PRD still applies. Its earlier React preference and the archived bootstrap design's separate frontend-serving decisions are superseded by this change; update the current PRD stack sentence and README during implementation, while leaving the archived design historical.

The user subsequently approved removing the old web application immediately rather than keeping it operational during migration. Until the embedded UI is implemented, the server exposes only JSON health endpoints, development runs only Go, and smoke verification covers API/CLI and real PostgreSQL outage/recovery. Reports must state that browser verification is pending; this intermediate state does not satisfy the final embedded-web acceptance criteria.

## Goals / Non-Goals

**Goals:**

- One server process, listener and deployable executable for the API and UI, with compiled templates and embedded public assets.
- A small component-based Go UI that preserves the existing operational behavior and gives later administration screens a consistent foundation.
- A reproducible development/build process with explicit generated-file ownership and artifact-level verification.

**Non-Goals:**

- No embedded PostgreSQL, database schema change, authentication, administrative CRUD, provider integration, audit persistence or new dashboard.
- No combination of the server and CLI into one command. Preserve `bin/server` and the optional independently built `bin/clavis` client.
- No requirement to eliminate Node.js from development or tests. The deployed server must run without it.
- No deployment platform, container publishing, release automation, TLS termination design, offline application cache or separate status service.
- No permanent React islands or second UI library. Do not build speculative form/dialog screens merely to demonstrate components.

## Decisions

### 1. Use templ, htmx 4 and templUI's stable line

Planning baseline, verified September 10, 2026:

| Component | Selection | Evidence and purpose |
| --- | --- | --- |
| Go / chi | Retain Go 1.27.1 and chi 5.3.2 | Existing repository baseline and standard HTTP handlers. |
| templ compiler and runtime | 0.3.1020, pinned together | [Release](https://github.com/a-h/templ/releases/tag/v0.3.1020); [components](https://templ.guide/core-concepts/components/). Typed Go component arguments and composition. Its module requires Go 1.25. |
| htmx | 4.0.0 | [Release](https://four.htmx.org/announcements/2026-08-28-htmx-4.0.0-is-released). Stable, even though npm intentionally labels the release `next`. Pin the exact package version. |
| templUI | 1.13.2 | [Release](https://github.com/axadrn/shadcn-templ/releases/tag/v1.13.2), [v1 usage](https://templui.io/docs/how-to-use). The v1 module path is `github.com/templui/templui`. Use copied source. |
| Tailwind CSS and CLI | 4.3.3 | Retain the existing CSS version and replace the Vite integration with the matching [npm CLI package](https://registry.npmjs.org/@tailwindcss%2Fcli/4.3.3); its published dependency is Tailwind 4.3.3. |
| Node / pnpm / Playwright | 26.8.2 / 12.3.4 / 1.63.0 | Development, asset preparation and browser verification only. Remove the obsolete browser harness now; restore pinned Playwright 1.63.0 with the embedded UI tests. |

The newer shadcn-templ 2.0.0-beta.9 is a separate beta baseline and is not selected here. Source repository redirects must not silently change the v1 module path or copied API. Recheck availability and compatibility when implementing; record corrections in this design before changing the selected major line. No verified assembled build is claimed by this planning baseline.

Implementation recheck: the selected versions are available without baseline corrections. The templ compiler builds with Go 1.27.1 and takes its pin from the runtime requirement in `go.mod`; `scripts/templ.mjs` installs and verifies it under `.tools`. The frozen frontend install includes htmx 4.0.0 and Tailwind CLI/CSS 4.3.3. Tailwind CLI brings `@parcel/watcher`; use its prebuilt platform packages and explicitly disallow its native source-build fallback in pnpm's build-script policy.

Copy only the templUI components used by the reference page: the button, card, badge, alert/callout equivalent, switch and required icons/utilities. Record the upstream tag, resolved source revision and local modifications in source comments. Keep the required copyright and permission notices in the delimited comment blocks in `internal/web/ui/utils/templui.go` and `internal/web/ui/icon/icon.templ`; the asset build must extract these notices for the embedded distribution. Do not maintain standalone license files, separate notice Markdown files or a web README. Include matching scripts and their actual transitive component dependencies. Keep the Clavis layout, identity, responsive behavior and light/dark presentation; exact Tremor pixels and its React API are not compatibility requirements.

templ is preferred to `html/template` because component parameters, imports and composition participate in Go compilation. Copied templUI source follows the ownership model already used for Tremor Raw and avoids depending on an evolving component module at runtime. Browser interactions still use JavaScript; htmx does not replace component behavior. Tailwind/Playwright are retained instead of introducing another build runner or browser-testing framework.

### 2. Compile templates and embed a dedicated public asset directory

Add a Go package with this responsibility split:

```text
internal/web/
  *.templ, *_templ.go     application layout, status page and fragments
  ui/                    copied templUI components and their source scripts
  assets.go              embedded filesystem and public-asset serving
  assets/                generated, ignored distribution assets only
web/
  package.json, lockfile  minimal development dependencies
  styles/                Tailwind entry and application theme
  scripts/               small application browser scripts and asset build
  tests/                 Playwright verification
```

The exact source filenames can follow existing repository conventions; the public asset boundary and generated-file policy are fixed. Keep `.templ` and generated `*_templ.go` checked in. Treat generated Go as generated source in formatting, linting and mutation configuration; handwritten handlers and rendering decisions remain tested. Verify generated source with the pinned compiler's `templ generate -check`; only an explicit generation/format command updates checked-in files.

Produce CSS, the pinned local htmx script, required templUI scripts, application scripts and attribution notices in a freshly staged `internal/web/assets/` directory before compiling the server. Use system fonts and local SVG icons. Read htmx from the exact lockfile-resolved package during the build; copy templUI scripts from the committed source snapshot. Routine builds do not download components from a mutable remote branch or use a CDN.

Use [`go:embed`](https://pkg.go.dev/embed) for only that distribution directory. Never embed the repository root, configuration, development sources or `node_modules`. Missing required files or failed staging must fail the build. Build `bin/server` with `CGO_ENABLED=0` for the target macOS or Linux architecture, so it has no application-specific shared-library dependency. A binary is specific to its operating system and architecture; this is not a promise of one executable for every platform.

At runtime, read templates from compiled Go and assets from the embedded filesystem, with no working-directory override. Serve public files with explicit content types, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-cache` so stable asset URLs revalidate after replacing the binary. Refuse directories and unknown paths; do not add an SPA catch-all. The system's normal OS facilities and externally configured database remain runtime prerequisites.

### 3. Keep HTML rendering separate from JSON contracts

The existing chi router remains the only server router:

| Route | Representation / behavior |
| --- | --- |
| `GET /` | Full setup document, HTTP 200; rendered without a database check. |
| `GET /ui/readiness` | Complete readiness fragment, HTTP 200 or documented 503. |
| `GET /assets/*` | Embedded public assets, or 404 for absent/non-file resources. |
| `GET /health/live` | Existing JSON liveness contract. |
| `GET /health/ready` | Existing JSON readiness contract, unchanged. |

HTML and JSON endpoints share the existing bounded database check through a small helper in the server package. The web package renders safe view data and does not access the database or call the JSON API over HTTP. Do not create an empty domain-service framework. Later administration work must place authorization and audit decisions below both presentation adapters, but this migration does not build those services.

Use buffered rendering, either the normal buffered `templ.Handler` path or an explicit buffer, before writing headers/body. A rendering failure gets a fixed safe HTML error with the correct status; never emit a partially successful document followed by a raw error. Escape dynamic data using templ's normal expressions; do not introduce raw HTML for dependency diagnostics. Documents, readiness fragments and JSON health responses use `Cache-Control: no-store`.

The `/health/*` routes ignore presentation-selection headers and remain JSON. Separate paths avoid HTML/JSON cache negotiation and preserve the CLI's response parser. Remove the Vite-only `/api` proxy prefix from browser requests and remove `CLAVIS_API_PROXY`; retain `CLAVIS_HTTP_ADDR`, database settings and the CLI's server URL behavior.

### 4. Preserve readiness semantics with a small explicit browser layer

Render the shell immediately with a checking region and an htmx load trigger targeting `/ui/readiness`. Put the retry control, appearance control and an accessible status container outside the replaced fragment so focus and application controls survive readiness updates. The button and entry request share one request synchronization scope. A new explicit retry replaces/cancels the earlier check; do not queue extra checks or disable recovery indefinitely.

Set the readiness request deadline to five seconds and verify that it covers response-body completion. Use htmx's supported request lifecycle and cancellation facilities plus a small application timer if needed to meet that bound. Retain the latest-request identity until completion so a late result cannot update or announce stale state. On each fresh check, present checking instead of treating a previous ready response as current evidence. Do not poll or automatically retry on reconnect/focus.

htmx 4 swaps error responses by default and has a 60-second default timeout; neither default matches this screen. Configure the readiness response handling explicitly. Accept only the expected 200/503 HTML response with an application-owned fragment identifier header (for example `X-Clavis-Fragment: readiness`). Check status, content type and that marker before a swap. Unexpected status/body combinations, missing markers, redirects to an unrecognized document, timeout and transport failure display fixed local messages. Never insert their raw response text. A known 503 fragment is deliberately allowed through this gate. Reference: [htmx 4 changes](https://four.htmx.org/docs/whats-new-in-htmx-4).

Keep application handlers in an embedded script, use htmx 4 event names, and make any inherited attributes explicit. Do not blindly port htmx 2 examples. Preserve the `clavis.appearance` preference and system-theme behavior, including an in-memory fallback when local storage is unavailable. Use a small early same-origin appearance script to apply the chosen theme before rendering the page; keep it separate from readiness state. Load needed templUI scripts once in the layout. Verify replaced-component initialization with an isolated test fixture when the production page has no appropriate replacement target; do not add a fake product screen.

If Go stops after the page loads, the embedded scripts already in the browser can report a failed check. Restarting Go at the same address permits retry without reload. Fresh navigation while it is stopped cannot load Clavis. The user-selected single-binary architecture replaces the old independent-shell test; do not retain Vite, a service worker or a fallback service to simulate it.

### 5. Keep development tooling explicit and deployment independent

Retain a reduced `web/package.json` and frozen pnpm lockfile for htmx asset acquisition, Tailwind's CLI, and formatting/linting of maintained JavaScript tooling. Remove React/DOM, Radix React packages, Remix React icons, TanStack Router/Query and router plugin, Ky, Zod, React styling helpers, Vite/plugins, React Testing Library, JSX route generation and their configuration now. Remove the obsolete app's browser harness and unused Playwright/Vitest/jsdom/TypeScript dependencies; restore Playwright at the selected version when implementing browser verification. Move the old browser suite's API/CLI database outage/recovery assertions into the Node smoke runner so backend coverage remains active. Preserve formatting and correctness lint for every retained script instead of dropping validation indiscriminately.

Use the existing Make/Node script arrangement; do not add Task just because upstream examples use it. Install the pinned templ compiler locally under `.tools`. The templUI CLI is used only for an explicit component import/update, with a pinned component revision; regular setup consumes committed component source.

| Command | Result |
| --- | --- |
| `make setup` | Verify/install pinned development dependencies and prepare ignored assets needed by Go package compilation. |
| `make generate-web` | Explicitly regenerate checked-in templ Go output and prepare browser assets. |
| `make build-web-assets` | Rebuild only ignored distribution assets from pinned/committed inputs. |
| `make build-server` | Check generated template consistency, rebuild assets, then compile the complete server binary. |
| `make build-cli` | Build only `cmd/clavis` using Go; no web preparation. |
| `make build` | Produce the embedded server and separate CLI. |
| `make dev` | Build and run one configured Go application. Existing `dev-api` can remain an alias; remove `dev-web`. |
| `make check` | Non-mutating formatting/generated-source checks, ignored asset preparation, relevant lint/tests, and builds. |
| `make smoke` | Exercise the copied binary, same-origin browser and separate CLI with isolated PostgreSQL. |

Build failure must exit nonzero without describing a previously existing executable as newly built. Use a temporary output and publish the new executable only after successful compilation. Document the build/runtime distinction: development can use Node, pnpm, the templ compiler and browser tooling; an operator runs `./server` with environment configuration and PostgreSQL, from any working directory.

### 6. Verify the artifact and preserve useful tests

Go tests cover render output, content types, cache headers, public-asset boundaries, safe failures and unchanged JSON/CLI behavior. Port component-level readiness races into browser tests against controlled responses where necessary, including a delayed stale response, body stall, unrecognized HTML containing a sentinel secret, and multiple updates. Keep browser checks for theme persistence/system changes, disabled storage, accessible names, keyboard focus and status announcements. Visual checks confirm the Clavis shell remains usable; no claim of automatic accessibility follows from selecting templUI.

Change `scripts/smoke.mjs` to copy the built server into its own empty temporary directory and start it there with an absolute executable path and a sanitized executable search path that lacks development tools. PostgreSQL remains the runner's isolated Compose project. Run browser tests directly on the server's origin, reject third-party asset requests, and assert CSS/scripts actually load and controls work. The Node-based harness remains outside the deployed application process.

Keep the existing real database stop/restart path and CLI doctor assertions. Replace the old fresh-navigation API-down test with load-page, stop-server, retry-fails, restart-same-address, retry-recovers. Track each restarted process in the runner's cleanup set. Preserve bounded execution, injected-failure cleanup checks, and existing developer-resource protection. The normal browser suite can test newly inserted templUI controls through a local fixture without expanding product scope.

## Risks / Trade-offs

- templUI's active v2 transition → pin the selected v1 source and compiler versions; test the selected controls with htmx 4 before claiming the replacement UI is complete.
- Smaller client architecture still has browser lifecycle code → keep one readiness controller, explicit script loading and behavioral tests; avoid adding a global client-state library.
- Generated assets can become stale or leak development files → stage a dedicated public directory before builds, verify template consistency, and test the copied executable from an empty directory.
- The server and UI share availability → document the fresh-navigation outage behavior; keep CLI diagnostics and already-loaded-page recovery.
- Copying components transfers maintenance responsibility → record provenance and retain notices; component upgrades are explicit changes rather than part of routine builds.
- Embedding assets increases binary size and couples UI/API releases → accept the coupling for the selected deployment model; no unsupported size or speed target is introduced.

## Migration Plan

1. Pin tooling and import the minimal templUI controls; establish generation and public asset staging.
2. Remove React/Vite, obsolete commands/proxy configuration and the old browser harness immediately, as approved by the user. Keep API/CLI development, checks and database smoke functional; document the temporary lack of a browser UI. Keep provenance and required copyright/permission notices inline in source, not additional Markdown or license files.
3. Add buffered templ rendering, embedded assets and HTML routes alongside the unchanged JSON endpoints. Rebuild the setup page against the bootstrap reference and verify the selected controls against htmx 4.
4. Restore pinned Playwright and implement readiness/theme behavior and browser tests, then run the copied-binary, database-outage and loaded-page recovery checks. The early removal of React does not waive any of these checks.
5. Finalize runtime documentation and run the full relevant checks and smoke suite from a clean setup. This is an application-stack migration, not completion of the PRD's authentication or administration features.

Rollback restores the previous source/dependency/build changes and the previous server plus web serving arrangement. No database migration is involved. Keep the existing CLI protocol compatible throughout, and do not delete developer database volumes or change credentials during migration.
