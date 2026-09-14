## Context

The browser interface is three templ documents in `internal/web`: `Page()` (the public setup/status page at `/`, whose readiness widget swaps `GET /ui/readiness` fragments with htmx and `readiness.js`), `Login` and `AuthError` (wrapped by `authDocument`), and `Admin`, a single `/admin` document that renders the users, connections and grants tables inside one 672-pixel card. `authHTTP.adminBrowser` loads all three bounded lists in one request and fails closed when any of them fails; `auth.AdminOutcome` and `LoginOutcome` fix the redirect targets. Assets are built by `scripts/build-web-assets.mjs` into `internal/web/assets` and embedded by an explicit list; templUI components (`button`, `card`, `alert`, `badge`, `switch`, `icon`) are vendored under `internal/web/ui` with a pinned upstream revision, and `make check` runs a whole-program dead-code check, so unused Go functions, including templ-generated ones, fail the build.

The owner chose the Console direction on 2026-09-14 from the "Clavis UI" design canvas: a 232-pixel sidebar with the mark, three navigation entries with counts, an appearance icon button at the top and the signed-in user with sign-out at the bottom; one page per list with a full-width table in a card; 13-pixel table text with uppercase 11-pixel headers; status as a dot plus a word; labels as monospace outline chips; a slim top bar for the public documents; a 384-pixel sign-in column. The owner also decided the status page goes, with its fragment route, script and htmx.

Constraints that shape the design: no third-party network access from the browser (embedded-web), so the canvas's Geist font is not adopted and the system font stack stays; public documents must not touch the database (local-authentication, platform-initialization); every page fails closed without current data; the dead-code check; templ formatting and generated-source consistency checks; the smoke script and the copied-executable build test enumerate public routes and assets.

## Goals / Non-Goals

**Goals:** the Console shell and pages as approved, with the same security and fail-closed properties as today; the status page and its machinery removed cleanly; tests, docs and the maintained specs consistent with the new interface.

**Non-Goals:** browser management forms, an overview page, relative timestamps, a mobile drawer, htmx-based partial updates, web fonts, replacing templUI or Tailwind, design tokens beyond the three status colours.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Sign-in plus read-only administration; every mutation through the CLI | PRD 4, 7.8, 12 | Retained |
| Public setup/status page with in-page readiness checks, retry, five-second bound | project-bootstrap "Web foundation displays actual readiness", embedded-web fragment scenarios, README | Explicitly changed (owner 2026-09-14): removed; `/health/ready` and `clavis doctor` are the readiness diagnostics |
| htmx in the stack | PRD 12, archived replace-web-stack-with-htmx-templ | Explicitly changed: dropped with the only partial update; templ, templUI and Tailwind stay |
| One origin, same-origin URLs, public documents and assets available with the database down, no CDN or font service | embedded-web | Retained; `/` becomes a redirect that never touches the database |
| Public GETs excluded from authentication and readiness middleware | local-authentication | Retained for `/`, `/login`, `/assets/*`; the three admin routes stay inside `a.operation` |
| Browser sign-in lands on the protected shell; unauthenticated navigation redirects to `/login`; members get 403 | local-authentication | Retained; the landing route becomes `/admin/users` |
| Each browser table: escaped text, bounded, truncation notice, no forms, fail closed | user-administration, connection-management, connection-grants | Retained per page; the requirement text moves from "the administration page" to "its page" |
| Times rendered in UTC, never locale-dependent | connection-grants, `createdLayout` | Retained; the canvas's "2 h ago" is not adopted |
| Light and dark appearance, persisted as `clavis.appearance`, colour never the only status signal | project-bootstrap "Usable visual foundation" | Retained; the switch becomes an icon button |
| Explicit embed list, reproducible assets, attribution notices travel with the binary | embedded-web "Reproducible generated assets" | Retained; the list shrinks to `app.css`, `appearance.js`, `notices.txt` |
| No connection target, role, URL or secret reaches display data | connection-management | Retained; the models are unchanged |

No unresolved departure: both departures are owner decisions recorded in the proposal.

## Decisions

### 1. Routes

`GET /` answers `303 See Other` to `/admin/users` with `Cache-Control: no-store` and no database access; the admin route then sends a visitor without a valid session to `/login` through the existing `AdminOutcome`. Alternative considered: `/` redirects straight to `/login`, which would show the form to a signed-in administrator on every visit to the origin; rejected. `GET /admin` answers `303` to `/admin/users` so old bookmarks keep working. `GET /ui/readiness` is removed and answers the router's 404 like any unknown path. `auth.LoginOutcome` returns `Location: /admin/users`; `AdminOutcome` is unchanged.

The three pages are `GET /admin/users`, `GET /admin/connections` and `GET /admin/grants`, all mounted with `a.operation` like `/admin` today. The timeout fallback in `operation` matches `strings.HasPrefix(path, "/admin/")` and renders the same 503 error document as before.

### 2. Loading and the shell model

One loader (`adminBrowser` renamed `adminPage`, taking a `web.AdminPage` value) keeps today's sequence: token, service, authenticate, role, users, connections, grants, fail closed on the first error. Every page loads all three lists because the sidebar shows the three counts, and a count is current data like the table itself; rendering a page with a missing count would present partial data as current. The cost equals today's single page. Alternative considered: count queries or cached counts; rejected as new query surface for no user value at MVP scale.

`web.AdminModel` gains `Page AdminPage` (`PageUsers`, `PageConnections`, `PageGrants`). `AuthViews.Admin` keeps its signature, so the server test fixtures change only where they assert paths. Counts are rendered as `len(list)` and, when the list is truncated, as the bound followed by `+` (for example `1000+`), so a truncated list is never presented as a complete count; the truncation notice stays above the table.

### 3. Documents and components

`auth.templ` is reorganised into: `publicDocument(title)` (head, slim 56-pixel top bar with the mark, the word Clavis and the appearance button; used by `Login` and `AuthError`), `adminShell(model)` (head, sidebar, main column) and three page bodies. The sidebar lists the three pages with an icon, the label and the count, marks the current page with `aria-current="page"` and the highlighted style, and carries at the bottom the username, the role and the sign-out form. At widths below the `lg` breakpoint the sidebar becomes a top row and the navigation wraps; the body never scrolls horizontally, and tables keep their `overflow-x-auto` wrapper.

Tables reuse the existing markup with the approved styling: 13-pixel text, uppercase 11-pixel muted headers on a tinted header row, 42-pixel rows, `white-space: nowrap` on cells with the names allowed to break only between words (`break-words`, no `break-all`), tabular numerals on times. A `status(kind, text)` templ helper renders `<span class="inline-flex items-center gap-2"><span aria-hidden="true" class="size-1.75 rounded-full bg-status-…"></span>text</span>`; kinds are `ok`, `bad` and `off`, mapped in `auth_models.go` (user active or blocked; connection enabled or disabled; check reachable, else bad). Three CSS tokens (`--status-ok`, `--status-bad`, `--status-off`) are defined for light and dark in `app.css` and exposed as Tailwind colours; the `.status-success` and `.status-warning` classes go with the readiness widget. Labels use `badge.VariantOutline` with a monospace 11-pixel class; role and provider are plain muted text. The `badge` variants `default`, `secondary` and `destructive` become unused in product templates and are kept only if the composition fixture uses them; otherwise the dead-code check requires removing them, and the vendored file's header records the local change.

The `switch` component is removed. The appearance control is a `<button type="button" data-appearance aria-pressed="…" aria-label="Dark appearance">` rendering both sun and moon icons, with CSS showing one per appearance. `appearance.js` keeps its head-time apply, storage handling and system-change listener; the `change` delegation becomes a `click` delegation on `button[data-appearance]`, and `apply` sets `aria-pressed` on every such button. The `htmx:after:process` listener is dropped with htmx.

Icons: add `Users`, `Link`, `ShieldCheck`, `Sun`, `Moon` and `LogOut` from the pinned lucide revision named in `icon.templ`; remove `ArrowRight`, `Server`, `Database`, `RefreshCw` and `SquareTerminal` unless the composition fixture keeps one, since unused templ functions fail the dead-code check. `KeyRound` stays for the mark. The composition fixture in `testdata` drops the htmx attribute and the switch and exercises the remaining components, including the new status helper.

Sign-in: a 384-pixel column, heading "Sign in", the alert (message plus the rate-limit hint, and the cleared-password sentence kept so the behaviour stays announced), the card with the two fields and the full-width button. No helper text; the username input keeps its `pattern`, `minlength`, `maxlength`, `autocomplete` and `autocapitalize` attributes. The auth-error document keeps its buttons and the conditional sign-out form.

### 4. Assets and build

`assets.go` embeds `app.css`, `appearance.js` and `notices.txt`. `build-web-assets.mjs` stops copying htmx and its licence; the notices keep lucide (icons) and templUI. `web/package.json` drops `htmx.org`; the lockfile is regenerated with `pnpm install` and the frozen-lockfile check keeps passing. `readiness.js` and `page.templ` are deleted; `readiness.go` and `Readiness()` go with them. The Tailwind source globs already cover `internal/web/*.templ` and `internal/web/ui/**/*.templ`.

### 5. Tests

Server: `web_test.go` asserts the root redirect without a database ping, the unknown-path 404, the asset list without htmx, and that `/ui/readiness` is 404; `contracts_test.go` and `auth_test.go` update the public path lists and the `/admin/users` locations; the three page tests request their own route and additionally assert the sidebar counts, `aria-current` and that the other two lists are still loaded and fail the page when unavailable. Web: `auth_view_test.go` covers the shell (three navigation entries, counts with `+`, sign-out form is the only form, no `hx-` attributes, appearance button with `aria-pressed`), the status helper per kind (text present for every kind), the sign-in document (no helper text, alert text) and the existing escaping and sentinel-target assertions; `assets_test.go` lists the three assets; `components_test.go` follows the fixture. Scripts: `build.test.mjs` expects `/` to answer 303 to `/admin/users` and lists the three assets; `build-web-assets.test.mjs` lists them; `smoke.mjs` replaces `/` and the htmx asset in its public-route list with `/login` and checks the redirect chain from `/` to `/login` when signed out.

### 6. Documentation

README: quick start opens `http://127.0.0.1:8080` for sign-in; the web paragraph describes the shell and the three pages and drops the readiness widget text; the stack line drops htmx. PRD: 7.8 states sign-in plus the three read-only pages and no status page; 12 records the decision and the stack. The maintained specs are updated by the delta specs of this change.

### 7. Slices

Three, sequential, each leaving a working interface: remove the status page and htmx (root redirect, routes, assets, tests, docs); the public documents (sign-in, auth error, top bar, appearance button, icons, fixture); the administration shell and the three pages (routes, loader, views, models, page tests, docs). The whole-change checks follow.

## Risks / Trade-offs

- [The dead-code check fails on unused templ-generated functions after removing pages] → each slice runs `make check-dead-code`; unused icons, badge variants and helpers are removed in the slice that orphans them.
- [Tailwind purges classes used only in Go string helpers] → status kinds map to full class names listed in the templ file, never concatenated at runtime.
- [Every admin page loads three lists] → same cost as today's single page; the bounds are 1,000 rows each; counts are current data.
- [Appearance flashes on load] → unchanged head-time script; the button only adds `aria-pressed` handling.
- [Narrow screens] → the sidebar becomes a top row below `lg`; not a phone design, and the proposal says so.
- [Bookmarks and CLI docs pointing at `/admin` or `/`] → both redirect; `/ui/readiness` is gone deliberately and documented.

## Migration Plan

1. Deploy; no data migration. `/` and `/admin` redirect; `/ui/readiness` answers 404.
2. Rollback: redeploy the previous executable; the database is untouched.

## Open Questions

None.
