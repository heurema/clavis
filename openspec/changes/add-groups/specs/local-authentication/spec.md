## MODIFIED Requirements

### Requirement: Protected browser authentication

The same server SHALL provide a public sign-in document at `/login`, same-origin login/logout form actions and an administrator-only shell with one page per list at `/admin/users`, `/admin/groups`, `/admin/connections` and `/admin/grants`; `GET /admin` SHALL redirect to `/admin/users`. Successful browser sign-in SHALL redirect to `/admin/users`. Browser sessions SHALL use host-only HttpOnly cookies, SameSite protection and Secure cookies on HTTPS. Authentication tokens SHALL NOT appear in URLs, rendered HTML, JavaScript storage or application logs. Browser mutations SHALL reject absent, null, multiple or nonmatching configured Origin headers and cross-site Fetch Metadata. GET requests SHALL only validate existing credentials, never issue/rotate/revoke credentials or mutate accounts/sessions. Authentication documents SHALL reject framing. Every administration page SHALL render inside the shell, which SHALL show the signed-in username and role, the sign-out form, the appearance control and the four navigation entries with their bounded counts; each page SHALL load all four bounded lists for those counts and SHALL fail closed when any of them cannot be loaded.

#### Scenario: Browser sign-in and protected navigation
- **WHEN** a user signs in through the same-origin form
- **THEN** the server sets a fresh browser session cookie and redirects to `/admin/users`
- **AND** an unauthenticated navigation to any administration page instead redirects to login

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
