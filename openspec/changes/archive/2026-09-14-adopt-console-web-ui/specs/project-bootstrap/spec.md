## MODIFIED Requirements

### Requirement: Usable visual foundation

The web interface SHALL use a consistent set of shared controls across the public documents and the administration shell, support light and dark appearance, and expose keyboard focus and accessible names for its interactive controls. The administration shell SHALL present the three list pages as navigation entries with the current page marked for assistive technology. Status information SHALL be rendered as text accompanied by a colour indicator and SHALL remain understandable without relying on colour alone. The appearance control SHALL be a button that reports its state to assistive technology, and the appearance preference SHALL persist across page reloads in the same browser.

#### Scenario: Operate the shell with a keyboard
- **WHEN** a user navigates the appearance control, the sidebar entries and the sign-out control using the keyboard
- **THEN** focus is visible, the controls have accessible names, the current page is announced, and their actions can be completed without a pointer

#### Scenario: Retain the selected appearance
- **WHEN** a user selects light or dark appearance and reloads the page
- **THEN** the application restores that preference and status labels remain readable

#### Scenario: Read a status without colour
- **WHEN** a blocked user, a disabled connection or a failed connectivity check is listed
- **THEN** the state is conveyed by its text, with the colour indicator as reinforcement only

## REMOVED Requirements

### Requirement: Web foundation displays actual readiness
**Reason**: The owner decided on 2026-09-14 that the browser does not need a status page. Readiness diagnostics remain available as JSON at `/health/ready` and through `clavis doctor`, which already distinguish every state the page represented.
**Migration**: Operators check readiness with `clavis doctor` or `GET /health/ready`. `GET /` now redirects into the administration shell.
