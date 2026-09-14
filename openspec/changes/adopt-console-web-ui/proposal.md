## Why

The browser interface is a landing page with a readiness widget, a sign-in card and one 672-pixel administration card into which three tables are squeezed: connection names break mid-word, timestamps are cut off, and four badge styles compete in every row. The PRD asks for "minimal sign-in and administration screens" (PRD 4, 7.8); the owner reviewed three directions on 2026-09-14 and chose the Console direction (sidebar shell, one page per list, quiet tables) and decided that the status page is not needed. This change replaces the pages with that design.

## What Changes

- Replace the single `/admin` page with an administration shell: a sidebar with the Clavis mark, the three list pages (`Users`, `Connections`, `Grants`) with their bounded counts, an appearance toggle at the top of the sidebar, and the signed-in username, role and sign-out at the bottom. Each list gets its own route (`/admin/users`, `/admin/connections`, `/admin/grants`) and a full-width table; `/admin` redirects to `/admin/users`, and browser sign-in lands on `/admin/users`. **BREAKING** for the `/admin` document (allowed, not in production).
- Quiet the tables: role and provider as plain text, status and check outcome as a coloured dot plus a word (colour never alone), labels as small outline chips, absolute UTC times in tabular numerals, one accent colour and red only for problems (blocked user, unreachable or rejected check). Empty lists and truncation keep an explicit notice.
- Simplify sign-in: a 384-pixel column under a slim top bar, heading "Sign in", no intro copy, no username-format helper text, the error alert reduced to the message and the retry hint. The auth-error document uses the same top bar.
- **BREAKING** Remove the public setup/status page at `GET /`, the HTML readiness fragment at `GET /ui/readiness`, the readiness script and the htmx asset (owner decision 2026-09-14: "System status not needed", remove all of it). `GET /` becomes a redirect into the administration shell, which sends signed-out visitors to `/login` without touching the database. JSON `/health/live` and `/health/ready` and the CLI `doctor` command remain the readiness diagnostics.
- Keep the stack otherwise: templ, templUI components, Tailwind CSS, the embedded asset build, light and dark appearance with the persisted `clavis.appearance` preference, system font stack, no third-party network access. Drop `htmx.org` from the web package and its attribution from the notices file.
- Update README (quick start, web section), PRD 7.8 and 12, and the maintained specs that describe the setup page and readiness fragment.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `embedded-web`: "One origin for the interface and API" loses `GET /` as a document and `GET /ui/readiness`; `/` becomes a redirect. "Distinct HTML and JSON representations" loses the HTML readiness fragment scenarios. "Interactive controls survive partial updates" is removed (no partial updates remain). The asset scenarios name the remaining assets.
- `project-bootstrap`: "Web foundation displays actual readiness" is removed. "Consistent shell and accessibility" is restated for the administration shell, the appearance toggle and the dot-plus-word status convention.
- `local-authentication`: "Protected browser authentication" describes the sign-in document, the `/admin` redirect and the per-list administration pages; the "database unavailable" scenario covers `GET /` as a redirect and `/login` as a document.
- `user-administration`, `connection-management`, `connection-grants`: the three "read-only … in the browser" requirements move from "the administration page" to their own pages inside the shell, with the sidebar count, the status convention and the fail-closed rule per page.
- `platform-initialization`: the "public documents remain available" scenario names the login document rather than setup/login documents.

## Impact

- Backend: `internal/server/server.go` (root redirect, readiness fragment route removed), `internal/server/auth.go` (three admin routes, redirect from `/admin`, timeout fallbacks per route), `internal/auth/browser_contract.go` (post-login location), `internal/web` (`page.templ` removed, `auth.templ` rewritten as shell, sign-in and three list pages, `readiness.go` removed, models for counts and status), `internal/web/ui/icon` (users, link, shield-check, sun, moon, log-out; unused icons removed for the dead-code check), `internal/web/ui/switch` removed in favour of an icon button, `internal/web/assets.go` (embed list without `htmx.min.js` and `readiness.js`).
- Browser assets: `web/scripts/appearance.js` (button instead of checkbox), `web/scripts/readiness.js` removed, `web/styles/app.css` (status tokens), `web/package.json` and lockfile (htmx removed), `scripts/build-web-assets.mjs` and its test.
- Tests: `internal/server/web_test.go`, `admin_page_test.go`, `connections_page_test.go`, `grants_page_test.go`, `auth_test.go`, `contracts_test.go`, `internal/web/*_test.go`, `internal/web/testdata/composition.templ`, `scripts/build.test.mjs`, `scripts/smoke.mjs`.
- Docs: `README.md`, `docs/PRD.md`, the six maintained specs above.
- Dependencies: `htmx.org` removed; none added. Templates and assets regenerate through the existing `make generate-web` and `make build-web-assets`.
- Size: this is a whole-interface replacement and will exceed the 400-line guideline; the tasks split it into three independently reviewable slices with a safe intermediate state after each.

## Owner decisions (2026-09-14)

- Console direction chosen over the "Quiet" single-column and "Terminal" dark-first sketches (design canvas "Clavis UI").
- No status page; remove the fragment route, its script and htmx rather than keep an unused route.
- No CLI command hints on the pages; no explanatory copy under page titles; no "Showing all…" footers.
- Appearance toggle at the top of the sidebar, as an icon button.

## Non-goals

Browser management forms, groups, an overview or dashboard page, relative timestamps, a mobile navigation drawer (the shell stacks at narrow widths but is not optimised for phones), replacing templUI or Tailwind, a design-token overhaul beyond the status colours.
