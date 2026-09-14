## MODIFIED Requirements

### Requirement: Read-only grants table in the browser

The administration shell SHALL provide a Grants page at `/admin/grants` that lists grants with username, connection name, granted time in UTC and the granting administrator's username, escaped and bounded like the other tables, with a truncation notice and no forms. The sidebar entry SHALL show the number of listed grants, suffixed with `+` when truncated. The page SHALL fail closed when the list cannot be loaded.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests `/admin/grants`
- **THEN** the grants table renders with the documented columns and the Grants entry is marked current

#### Scenario: Grant list unavailable
- **WHEN** the grant listing fails
- **THEN** the page returns safe 503 rather than rendering without current data
