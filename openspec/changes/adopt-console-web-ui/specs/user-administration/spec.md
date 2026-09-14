## MODIFIED Requirements

### Requirement: Read-only administrator user list in the browser

The administration shell SHALL provide a Users page at `/admin/users` that renders the bounded user list with username, role, status and creation time in UTC using escaped text, and SHALL show a truncation notice when applicable. Role SHALL be plain text; status SHALL be rendered as text with a colour indicator, `Active` for an enabled account and `Blocked` for a disabled one, with only the blocked state coloured as a problem. The sidebar entry SHALL show the number of listed users, suffixed with `+` when the list is truncated. The page SHALL NOT offer browser forms that create, block, reset or change roles. If the list cannot be loaded, the page SHALL fail closed with safe unavailability rather than rendering stale or partial data as current.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests `/admin/users`
- **THEN** the page lists all users with their role and active or blocked state, the Users entry is marked current, and no management form is present

#### Scenario: Username contains markup-like characters
- **WHEN** a listed username is rendered
- **THEN** it appears as escaped text within the documented username character set

#### Scenario: Truncated user list
- **WHEN** more users exist than the listing bound
- **THEN** the table shows the bounded list with the truncation notice and the sidebar count carries the `+` suffix
