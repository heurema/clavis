## MODIFIED Requirements

### Requirement: Protected browser authentication


The same server SHALL provide a public sign-in document at `/login`, same-origin login/logout form actions and an administrator-only shell with one page per list at `/admin/users`, `/admin/groups`, `/admin/connections` and `/admin/grants`; `GET /admin` SHALL redirect to `/admin/users`. Successful browser sign-in SHALL redirect to `/admin/users`, except when the sign-in request carries a return target that is a valid CLI authorization link as defined in "CLI authorization through the browser"; the server SHALL then redirect to that link rebuilt from its parsed parameters, never to the submitted text, and SHALL ignore any other return target. The return target SHALL travel in the sign-in form's action URL, and every response to a refused sign-in SHALL render the sign-in document carrying the target the refused request carried. Browser sessions SHALL use host-only HttpOnly cookies, SameSite protection and Secure cookies on HTTPS, and a cookie's expiry SHALL be the session's absolute expiry. Authentication tokens SHALL NOT appear in URLs, rendered HTML, JavaScript storage or application logs. Browser mutations SHALL reject absent, null, multiple or nonmatching configured Origin headers and cross-site Fetch Metadata. A failed sign-in SHALL state its reason in one short application-owned sentence, without restating what the rendered form already shows. GET requests SHALL only validate existing credentials, which MAY renew a valid session's idle expiry, and SHALL never issue, rotate or revoke credentials or mutate accounts. Authentication documents SHALL reject framing. A document whose form a browser submits SHALL use a referrer policy that keeps the browser's `Origin` header on a same-origin submission while withholding the document's URL from other origins; a policy that makes a browser send an opaque origin SHALL NOT be used on such a document. Every administration page SHALL render inside the shell, which SHALL show the signed-in username and role, the sign-out form, the appearance control and the four navigation entries with their bounded counts; each page SHALL load all four bounded lists for those counts and SHALL fail closed when any of them cannot be loaded.

#### Scenario: Browser sign-in and protected navigation
- **WHEN** a user signs in through the same-origin form
- **THEN** the server sets a fresh browser session cookie and redirects to `/admin/users`
- **AND** an unauthenticated navigation to any administration page instead redirects to login

#### Scenario: Sign-in returns to a CLI authorization
- **WHEN** a member signs in through a login form carrying a valid CLI authorization link as its return target
- **THEN** the server sets a fresh browser session cookie and redirects to that authorization link instead of `/admin/users`

#### Scenario: Sign-in ignores any other return target
- **WHEN** a login form carries a return target that is an absolute URL, another path, or an authorization link with an invalid port, challenge or state
- **THEN** a successful sign-in redirects to `/admin/users`

#### Scenario: An authenticated member opens administration
- **WHEN** a valid non-admin session requests any administration page
- **THEN** the server returns safe 403 rather than granting administration merely because sign-in succeeded

#### Scenario: Cross-origin or missing-origin form submission
- **WHEN** a login or logout POST has an absent, null, multiple or incorrect Origin, or is marked cross-site
- **THEN** it fails before creating or revoking a session, even if cookies were included

#### Scenario: Safe browser rendering
- **WHEN** a form fails or a protected page renders user-supplied text
- **THEN** errors use application-owned messages, text is escaped and password fields are never echoed
- **AND** username/password labels, keyboard focus, submission and sign-out remain usable

#### Scenario: Public documents receive stale cookies during an outage
- **WHEN** the database is unavailable and GET `/` or `/login` includes an absent, malformed, expired or revoked session cookie
- **THEN** `/` redirects and `/login` renders without attempting database session validation

#### Scenario: Browser logout cannot confirm revocation
- **WHEN** a same-origin logout cannot confirm server-side revocation because storage is unavailable
- **THEN** the browser cookie is cleared and a safe 503 document distinguishes local sign-out from unconfirmed remote revocation

#### Scenario: Administration page cannot load a list
- **WHEN** an administrator's valid session requests an administration page but the user, group, connection or grant listing fails or times out
- **THEN** the server returns safe 503 rather than rendering the page or its counts without current data

#### Scenario: Old administration bookmark
- **WHEN** a browser requests `GET /admin`
- **THEN** the server redirects to `/admin/users` without reading the database

#### Scenario: A refused sign-in keeps the return target
- **WHEN** a sign-in request carrying a valid CLI authorization link is refused for a bad origin, an unsupported media type, duplicate session credentials, invalid input, wrong credentials, throttling, unavailable storage or an operation timeout
- **THEN** the rendered sign-in document carries that return target, rebuilt from its parsed parameters
- **AND** a successful sign-in submitted from that document redirects to the authorization link rather than `/admin/users`

#### Scenario: A browser posts the sign-in form from an authorization document
- **WHEN** a browser that withholds the referrer under a `no-referrer` policy submits the sign-in or approval form rendered by the authorization page
- **THEN** the request carries the document's own origin rather than an opaque one, and the submission is not refused for its origin
- **AND** the document's URL, with its challenge and state, is still not sent to another origin

#### Scenario: A refused sign-in states one short reason
- **WHEN** a sign-in fails for wrong credentials, a refused origin, throttling or unavailable storage
- **THEN** the document shows one short sentence for that failure and no further line describing the form's own state
