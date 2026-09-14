## MODIFIED Requirements

### Requirement: Read-only connections table in the browser

The administration shell SHALL provide a Connections page at `/admin/connections` that lists connections with name, title, provider, labels, status and last check outcome and time in UTC, escaped, bounded like the user list, with a truncation notice and no management forms. Provider SHALL be plain text; labels SHALL be rendered as `key=value` chips in a stable order; status SHALL be text with a colour indicator, `Enabled` or `Disabled`, with the disabled state muted rather than coloured as a problem; the check outcome SHALL be text with a colour indicator, only `reachable` coloured as healthy and every other outcome coloured as a problem, and an unchecked connection SHALL say so. The sidebar entry SHALL show the number of listed connections, suffixed with `+` when truncated. The page SHALL fail closed when the list cannot be loaded and SHALL never show target hosts, roles or secrets.

#### Scenario: Administrator opens the page
- **WHEN** a signed-in administrator requests `/admin/connections`
- **THEN** the connections table renders with the documented columns and nothing more, and the Connections entry is marked current

#### Scenario: List unavailable
- **WHEN** the connection listing fails
- **THEN** the page returns safe 503 rather than rendering without current data

#### Scenario: Failed check is visible without colour
- **WHEN** a connection's last check outcome is not `reachable`
- **THEN** the outcome text names the outcome and the indicator marks it as a problem
