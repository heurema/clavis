# PRD: Clavis — Unified Access to External Systems Through AI Agents

Status: Draft product requirements for review and design.\
Version: 0.2 (MVP scope decisions of September 11, 2026 applied; see section 12).\
Date: September 11, 2026.\
Product name: Clavis (`clavis`).

## 1. Product Concept

The platform gives users and their AI agents unified, controlled access to external company systems through a CLI. It includes a skill with instructions for discovering available connections, using the CLI, retrieving data, and explaining results.

Each user signs in with a personal account. An administrator grants access to connections configured in advance. The agent accesses external systems through the platform with the user's permissions. The platform checks access to the connection, executes a supported operation, returns the result, and records an audit event.

Restrictions on data and operations are configured in the external systems beforehand. For example, a PostgreSQL role is created with the required permissions, and the platform receives its credentials. For VictoriaMetrics, the administrator provides an endpoint and an authentication method with a predefined access scope.

The primary MVP interfaces are **CLI + skill**. MCP is outside the product model and the expansion plan defined in this PRD.

### Core Promise

> Ask your agent a question: it will retrieve the company data you are allowed to access and help you complete the task. Access is centrally managed, and requests are audited.

### Short Description

A centralized access platform for AI agents. Managers retrieve business data independently, developers investigate problems, and administrators manage access through their own agents. The first integrations are PostgreSQL and VictoriaMetrics. The MVP uses local authentication only; optional Google sign-in and corporate OpenID Connect follow in a later stage.

## 2. Problem and Value

Data is spread across databases, monitoring tools, and other systems. To get an answer, users must find the right source, request separate access, and ask developers or DevOps engineers to export data. Configuring these sources in every agent environment repeats the same work and makes centralized access revocation and auditing difficult.

The platform addresses the following needs:

- Managers retrieve permitted information through their usual agent without involving a developer in data collection.
- Developers use their assigned connections for diagnosis and analysis.
- Administrators configure a connection once, grant access to users or groups, and can revoke it.
- The company gains a history of connection usage attributable to individual people.
- New integrations extend the shared CLI while retaining the same user, connection, and audit model.

The quality of an agent's answer depends on the available data and its analysis. The platform is responsible for exposing permitted capabilities and accurately returning source results, limitations, and errors.

## 3. Users

| User | Main Task | Value |
|---|---|---|
| Manager | Get an answer about business data or service status | Independent access to information |
| Developer | Explore data and investigate problems | Unified access to permitted sources |
| Administrator | Manage users, connections, and permissions | Centralized control and auditing |
| User's AI agent | Discover capabilities, execute queries, and explain results | A predictable CLI and accompanying skill |

Manager and developer are user personas. In the MVP, their differences are represented by groups and assigned connections. Separate fixed roles with these names are not required.

## 4. Key Product Decisions

| Decision | Agreed Scope |
|---|---|
| Primary interface | A CLI usable by both people and their agents |
| Agent support | A skill shipped with the product; no MCP |
| Identity | A personal user account and authenticated CLI sessions |
| Sign-in methods | Local authentication only in the MVP; optional Google and external OpenID Connect in a later stage |
| Passwords | Administrators set and reset local passwords; no self-service password change or account recovery in the MVP |
| Unit of access assignment | A specific connection configured in advance |
| Management permission | Connection and user management is the administrator role; a grant to a member means only "may use" |
| Data restrictions | Enforced solely by the external system through the credentials presented to it; the platform is a pass-through and applies no access rules of its own |
| Resource bounds | Every connection has a statement/request timeout and a result cap; truncation is always explicit |
| Initial providers | PostgreSQL and VictoriaMetrics |
| Initial operations | Any operation the external credentials allow, plus discovery and diagnostics helpers |
| Credential storage | External credentials are encrypted at rest with a deployment-supplied key |
| Data storage | Platform management data and audit records; no persistent storage of external query results or query text |
| Audit retention | No automatic purge in the MVP; an administrator-configurable retention window is a later stage |
| Agent autonomy | The user's agent independently chooses the sequence of permitted operations |
| Built-in agent | Not required for the MVP |
| User interface | Minimal sign-in and administration screens; the CLI is the primary interface |

The requirements below describe product behavior. Implementation details, API schemas, the database model, and provider architecture are defined separately.

## 5. Core Concepts

### User and Group

A user is a personal platform account. A group brings users together to grant access to connections. Users can receive access directly and through group membership.

### Provider

A provider defines an external system type, its connection parameters, and its supported operations. For example, the PostgreSQL provider supports discovering accessible database structures and executing queries, while the VictoriaMetrics provider supports retrieving metric information and querying values.

### Connection

A connection is a specific configured means of accessing an external system:

- A stable identifier and a readable name.
- The provider and target system configuration.
- Credentials for the external system.
- A description of its purpose and preconfigured access scope.
- Environment, service, and additional tags.
- Status: enabled or disabled, plus the result of the latest connectivity check.

Multiple connections may point to the same system using different credentials.

| Example Connection | External Permissions | Access Recipients |
|---|---|---|
| `payments-prod-reporting` | A preconfigured PostgreSQL role for reporting data | Payments managers |
| `payments-prod-diagnostics` | A preconfigured PostgreSQL role for diagnostics | Payments developers |
| `payments-stage` | A preconfigured role for the staging database | Payments team |
| `payments-prod-metrics` | Preconfigured access to Payments metrics | Payments team |

Environments, services, and tags help users find and organize connections. They describe access but do not filter external data themselves. In the MVP, permissions are granted to specific connections; changing a tag must not silently change access assignments.

### Permission

A permission determines who may use a connection or perform an administrative operation. Permission to manage the platform and permission to use external data are treated separately. In the MVP, management permission is the administrator role; a connection grant to a user or group confers only the right to use that connection.

### Operation and Audit Event

An operation is a supported action through a provider or an administrative action in the platform. An audit event records an execution attempt and its outcome, attributed to the user.

## 6. Access Responsibilities

| Layer | Responsibility |
|---|---|
| Local sign-in (Google or OIDC in a later stage) | Verify the user's identity |
| Our platform | Check permission to use connections and perform administrative operations; apply resource bounds; proxy the operation unchanged |
| External system | Enforce the data and operations allowed by the credentials presented to it |

The administrator configures restricted access in the external system before granting a connection to users. The platform provides a unified way to use and audit that access.

The MVP does not implement its own access rules for rows, columns, time series, statement types, or operations. The platform forwards the agent's request to the external system as submitted, under the connection's credentials; it does not rewrite queries, wrap them in read-only transactions, or filter by allowlist. If two audiences need different external permissions, separate connections are created with the corresponding permissions configured externally. The only limits the platform imposes are per-connection resource bounds: a timeout and a result cap.

A user selects an available connection and the parameters of a supported operation. Replacing its target system or credentials is a connection management action and requires administrative permissions.

All users of a connection share its preconfigured external access scope. The external source may see a shared role or token; individual attribution is retained in the platform's audit records.

## 7. MVP Functional Requirements

All requirements in this section are included in the first version. Implementation order will be determined after PRD approval.

### 7.1. Authentication and Users

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| AUTH-01 | Local account with a username and password | A user can sign in with a local account; no external identity provider is involved in the MVP |
| AUTH-05 | Local user management | Account creation, blocking and unblocking, administrator-initiated local password reset, and explicit administrator role assignment are available; there is no self-service password change and no account recovery in the MVP |
| AUTH-06 | Separation of authentication and resource access | Successful sign-in alone does not grant connection access or an administrator role |
| AUTH-07 | CLI session management | A user can end their own session; an administrator can revoke a user's sessions |

Deferred to a later stage (identifiers retained for continuity):

| ID | Requirement | Status |
|---|---|---|
| AUTH-02 | Optional Google sign-in | Later stage |
| AUTH-03 | External OIDC provider integration (authentik verified) | Later stage |
| AUTH-04 | Management of available sign-in methods | Later stage; the MVP has one method |
| AUTH-08 | Controlled linking of sign-in methods to users | Later stage; no linking exists with a single method |

MVP permissions and groups are managed within the platform. Automatic group synchronization from an external identity provider is not required.

### 7.2. Roles, Groups, and Permissions

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| ACCESS-01 | Basic administrator and member roles | Administrative operations require the appropriate role assignment |
| ACCESS-02 | Group creation and membership management | Adding or removing a member changes the access inherited through that group |
| ACCESS-03 | Connection access grants to users or groups | A recipient can discover and use the assigned connection |
| ACCESS-04 | Verification of current permissions on each request | Subsequent requests are rejected after access is revoked, even if the CLI is already authenticated |
| ACCESS-05 | Restricted resource discovery | A member can see only permitted connections and their descriptions |
| ACCESS-06 | Separation of management and usage permissions | Managing a connection requires the administrator role; a usage grant never confers management. Per-connection manager permissions are not part of the MVP |
| ACCESS-07 | Explicit management of the administrator role | The role can be assigned and revoked through the CLI by a user with the necessary permissions |

Effective access is the union of active direct grants and group-based grants. Revoking one grant does not remove other active grants; the CLI must let users inspect the source of access.

### 7.3. Providers and Connections

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| CONN-01 | Connection creation and updates | An administrator specifies the provider, target, credentials, and description |
| CONN-02 | Organization by environment, service, and tags | Connections can be discovered using these attributes |
| CONN-03 | Connectivity checks | The result shows whether the connection and the defined check succeeded; it does not claim that all external permissions have been verified |
| CONN-04 | Enabling and disabling connections | A disabled connection rejects subsequent operations |
| CONN-05 | Credential updates | An administrator can replace credentials; the change is audited without exposing secrets |
| CONN-06 | Protected credential handling | Secrets are encrypted at rest with a deployment-supplied key, are not returned to members or agents when viewing connections, and are excluded from audit records and error messages |
| CONN-07 | Extensible provider support | A new system type uses the shared user, connection, permission, and audit model |
| CONN-08 | Capability discovery | Operation descriptions, purposes, and required parameters are available for each connection |
| CONN-09 | Resource bounds | Each connection has a timeout and a result cap; exceeding them yields an explicit timeout or truncation outcome rather than a silent partial result |

A connectivity check confirms only what it actually tested. The administrator supplies the access scope description; the external system determines whether a specific query is permitted.

### 7.4. Initial Integrations

**PostgreSQL** (pilot targets PostgreSQL 17 and 18)

- Connectivity checks.
- Discovery of accessible database structures within the external role's permissions.
- Pass-through execution of any SQL the agent submits, under the connection's credentials. The platform does not restrict statement types or wrap statements in read-only transactions; the external role decides what succeeds.
- Per-connection statement timeout and row cap with explicit truncation.
- Structured results and clear source errors.
- Access through preconfigured roles with restricted permissions.

**VictoriaMetrics** (pilot targets single-node deployments)

- Connectivity checks using the configured authentication method.
- Retrieval of available metric names and metadata, where permitted by the configured connection.
- Instant and range queries.
- Per-connection request timeout and result cap with explicit truncation.
- Structured results and clear source errors.
- Authentication methods in the MVP: none, HTTP basic, bearer token, and a custom header. The credential model leaves room for mutual TLS and OAuth2 client credentials in a later stage.

Business data modification is not a first-release use case, but the platform does not prevent it: whether a submitted statement can modify data is decided entirely by the external credentials. Administrators must configure restricted roles in the external systems before granting a connection. Naming a connection does not make broadly privileged external credentials safe.

### 7.5. CLI

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| CLI-01 | Sign-in, sign-out, and current identity | A user can see which account is used to perform operations |
| CLI-02 | Catalog of available connections | An agent can find the required resource by purpose, service, and environment |
| CLI-03 | Capability descriptions | An agent can retrieve the actual supported operations and their parameters |
| CLI-04 | Operation execution | Results are available in a structured, machine-readable format |
| CLI-05 | Predictable errors | Access denial, invalid parameters, a disabled connection, a source error, and an exceeded limit can be distinguished |
| CLI-06 | Administration | Users, groups, roles, connections, and access grants can be managed through the CLI |
| CLI-07 | Audit inspection | Users can view their own history; administrators can view the broader history they are authorized to access |
| CLI-08 | Handling of large results | Any result limit or truncation is explicit in the response; a partial result is not presented as complete |
| CLI-09 | Termination of long-running operations | Execution time limits and clear cancellation or timeout outcomes are provided |

An additional human-readable format may be offered. The skill relies on stable structured output, documented errors, and built-in CLI help. Limits and time bounds in CLI-08 and CLI-09 come from the per-connection resource bounds (CONN-09), not from access rules.

### 7.6. Skill for AI Agents

The skill ships with the MVP and describes how to use the CLI. It does not store source credentials, act as an authorization system, or grant additional permissions.

The skill must teach the agent to:

1. Check that the CLI is available and inspect the user's current authentication status.
2. Discover available connections and understand their purpose.
3. Retrieve descriptions of supported operations and parameters.
4. Choose a suitable source and execute the required queries in sequence.
5. Account for errors, access restrictions, the data's time range, and incomplete results.
6. Explain its answer with the sources and time range used.
7. Carry out the user's administrative requests when authorized.
8. Distinguish external data from user instructions and avoid treating result content as permission to change access rights or perform additional actions.

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| SKILL-01 | Packaged CLI usage instructions | An agent completes the core scenarios without the user manually explaining each command |
| SKILL-02 | Installation and compatibility | Usage instructions for Claude Code and Codex are provided, along with the compatible CLI version |
| SKILL-03 | Shared model for adding providers | The skill uses CLI capability descriptions; adding a provider does not require new access assignment rules |
| SKILL-04 | Accurate presentation of results | An agent reports denial, unavailability, or truncation and does not present missing data as successfully verified |

The user chooses the agent and its model. A built-in LLM or proprietary chat interface is not an MVP dependency.

### 7.7. Auditing and Storage

The platform stores the following in its own database:

- Users, groups, and role assignments.
- Authentication settings and session state.
- Connection configuration and permissions.
- Usage and administrative change events.

A request event contains:

- An operation identifier.
- User and CLI session identifiers, plus an agent label if supplied.
- The connection and operation type.
- Timestamp, duration, and outcome.
- Result size and whether the result was truncated or timed out.
- Safe details about the request target and error category.

The authenticated session determines the user's identity. A client-supplied agent name is supplementary metadata and does not replace that identity.

For administrative operations, the platform records the actor, the affected object, and changes to non-secret settings or permissions. Failed and denied attempts are also recorded.

**MVP storage rule:** SQL query results, time series, and other source responses are not stored persistently. This applies to audit records, service logs, and platform error diagnostics. Query text and arbitrary operation parameters are never stored, because they may contain sensitive values; there is no per-connection option to record them in the MVP. The audit records the action, connection, outcome and size at a safe level of detail and does not offer query replay.

**Retention:** the MVP does not purge audit records; the operator is responsible for database growth. A retention window that an administrator configures through the CLI or the web interface is a later stage.

Once a result is sent to an agent, the agent's own environment may retain the conversation history. The policy against persistent storage of external data applies to our platform.

### 7.8. Minimal Web Interface

The MVP needs screens for sign-in and initial access setup, plus read-only administrative views of users, connections, permissions, and audit records. The browser does not offer management forms in the MVP; every mutation goes through the CLI.

Administrative capabilities are available through the CLI. Data exploration takes place through the agent and CLI; dedicated log browsers, query editors, monitoring dashboards, and investigation interfaces are not required for the MVP.

## 8. Core User Scenarios

### Scenario A. A Manager Gets an Answer Independently

1. An administrator prepares a PostgreSQL reporting role and a connection.
2. The administrator grants the connection to the manager or their group.
3. The manager signs in with the local account an administrator created and authenticates the CLI.
4. They ask their agent for information, such as the number of orders in a particular status yesterday.
5. The agent uses the skill, explores the accessible structure, and executes queries.
6. The manager receives an answer with its source and time range; the platform records the operations in the audit log.

Success: the manager gets an answer without asking a developer to export data.

### Scenario B. A Developer Investigates a Problem

1. The developer has access to a PostgreSQL diagnostic connection and service metrics.
2. They ask the agent to investigate an observed symptom over a specific period.
3. The agent independently selects and executes permitted queries.
4. It returns results and conclusions, explicitly identifying missing data.

Success: the agent retrieves data from multiple configured connections under one user session.

### Scenario C. An Administrator Manages Access

1. The administrator asks the agent to add a user to a group, grant a connection, or change a role.
2. The agent performs the administrative operation through the CLI.
3. The platform checks permissions and records the change in the audit log.
4. The user's effective access is updated; after full revocation, subsequent requests are rejected.

Success: platform administration uses the same agent interaction model.

### Scenario D. An External System Rejects a Query

1. The user has access to a connection.
2. The agent requests an object that the preconfigured external role is not allowed to access.
3. The platform forwards the query unchanged; the source rejects it.
4. The platform returns the source's denial clearly and records an audit event without the query text.

Success: permission to use a connection does not expand its actual external permissions.

## 9. MVP Scope

### Included

- Local authentication with administrator-managed passwords.
- Users, basic roles, groups, and manageable CLI sessions.
- A catalog of providers and preconfigured connections with encrypted credentials.
- Connection access assignments; management is the administrator role.
- PostgreSQL (pass-through SQL) and VictoriaMetrics (none, basic, bearer, custom-header authentication).
- Per-connection timeouts and result caps.
- A CLI with structured output and administrative operations.
- A skill and instructions for using it with Claude Code and Codex.
- Request proxying and auditing without stored query text or purge.
- A sign-in page and read-only administration views.

### Later Stages

- Optional Google sign-in, external OIDC (authentik), management of enabled sign-in methods, and controlled linking of sign-in methods to users.
- Self-service password change, account recovery, and credential-key rotation.
- Per-connection manager permissions.
- Mutual TLS and OAuth2 client-credential authentication for VictoriaMetrics and other HTTP sources.
- Administrator-configurable audit retention.
- Other databases, Prometheus, and log and trace sources.
- GitHub/GitLab, issue trackers, Slack, and other external systems.
- Additional permitted operations, including data modification subject to a separate product decision.
- Saved investigations, built-in agents, alerts, and workflows.
- Security checks, vulnerability monitoring, and component update tracking.
- Expanded corporate user and group synchronization.

### Explicit Exclusions

- MCP is not required: agents use CLI + skill.
- Background security checks are outside the MVP.
- A proprietary persistent store of external data is outside the MVP.
- An independent fine-grained permission engine for rows, columns, and metrics is outside the MVP.
- A complex analytical user interface and automatic incident remediation are outside the MVP.

## 10. First Release Readiness Criteria

The MVP is ready for a pilot when the following end-to-end scenarios have been verified:

1. **Local sign-in:** an administrator creates a local account, the user signs in through the browser and CLI, and an administrator can block the user, reset the password and revoke sessions.
2. **Administrator role:** the role can be granted and revoked, and the last enabled administrator cannot be removed.
3. **Two providers:** PostgreSQL and VictoriaMetrics are configured and used with preconfigured restricted permissions, and each of the MVP VictoriaMetrics authentication methods is verified.
4. **Connection isolation:** a user can discover and use only assigned connections; a denied operation is not sent to the external source.
5. **External restrictions:** connection access cannot exceed the permissions of the external role or configured endpoint.
6. **Access revocation:** subsequent requests are rejected after all applicable grants are removed or the session is revoked.
7. **Skill-based usage:** an agent completes data retrieval and administration scenarios without the user manually explaining commands.
8. **Auditing:** successful, denied, and failed operations are attributed to the user; role and connection changes are traceable.
9. **Data handling:** credentials are encrypted at rest and absent from logs and audit; external system responses and query text are never persisted.
10. **Accurate results:** source unavailability, errors, per-connection timeouts, and truncated responses are visible to both the person and the agent.

## 11. Pilot Success Metrics

| Metric | What It Validates |
|---|---|
| Share of tasks completed without another employee manually exporting data | The core value of independent access |
| Time from an access request to the first successful operation | Ease of user onboarding |
| Successful operation rate for each provider | Integration reliability |
| Request execution time through the platform | Practicality of proxying |
| Completeness of operation auditing | The ability to establish who did what |
| Pass rate for scenarios using restricted permissions | Compliance with the access model |

Numerical targets for performance and user metrics will be defined around the pilot team's circumstances. Permission enforcement, the absence of secrets in logs, and audit completeness are mandatory acceptance criteria.

## 12. Decisions Made and Remaining

Decided on September 11, 2026 (applied throughout this document):

| Topic | Decision |
|---|---|
| Delivery model | Self-hosted, single tenant: one Go server executable plus an external PostgreSQL platform database |
| Sign-in methods | Local only in the MVP; Google and OIDC deferred |
| Passwords | Administrators set and reset passwords; no self-service change or recovery in the MVP |
| Initial administrator | Created once at startup from deployment configuration and a mounted password file |
| Management permission | The administrator role; grants mean "may use" only |
| Administrator model | Administrators are peers (GitLab group-owner style): any administrator manages any other, nobody can block or demote themself, and the installation always keeps at least one enabled administrator; there is no root tier |
| Credential storage | Encrypted at rest with a mounted deployment key; rotation deferred |
| PostgreSQL operations | Pass-through of any submitted SQL; the external role is the only access boundary |
| Resource bounds | Per-connection timeout and result cap with explicit truncation |
| Audit content | Query text is never stored |
| Audit retention | No purge in the MVP; administrator-configurable window deferred |
| Web interface | Sign-in plus read-only administration tables; no browser management forms |
| VictoriaMetrics authentication | None, basic, bearer, custom header; mutual TLS and OAuth2 deferred |
| Pilot targets | Small teams; PostgreSQL 17 and 18; single-node VictoriaMetrics; Claude Code and Codex agents |
| Session lifetime | Fixed, eight hours by default, configurable between five minutes and 24 hours |

Still open, to be settled with the pilot team:

- Default values for per-connection timeouts and result caps.
- The first real questions from managers and developers used to evaluate the pilot.

The technical stack is Go for the backend and CLI, with templ, htmx, templUI and Tailwind CSS for the minimal web interface, sqlc-generated pgx application queries and Goose SQL migrations. The API, migrations and web assets are delivered in one Go server executable; PostgreSQL remains external and the CLI remains separate. Implemented so far: automated initial administrator setup, local browser/CLI sign-in, revocable sessions, administrator-managed local users with the peer administrator model and self-protection, and a protected admin page with a read-only user list. Planned next: groups and connection grants, providers and connections with encrypted credentials, PostgreSQL and VictoriaMetrics pass-through with resource bounds, request auditing and inspection, and the agent skill.

## 13. Sources and Context

This PRD consolidates the decisions from the discussion. Keep served as a source of ideas for providers, connections, context organization, and auditing; this document defines the MVP scope.

- [Keep: provider methods](https://docs.keephq.dev/providers/provider-methods)
- [PostgreSQL: roles and privileges](https://www.postgresql.org/docs/current/user-manag.html)
- [VictoriaMetrics: vmauth](https://docs.victoriametrics.com/victoriametrics/vmauth/)
- [Prometheus: security model](https://prometheus.io/docs/operating/security/)
- [Google: OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [authentik: OAuth 2.0 and OpenID Connect](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)

Supporting an integration does not imply that all sources share the same restriction model. Each connection requires access that is actually restricted in the external system.
