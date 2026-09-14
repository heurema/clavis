## MODIFIED Requirements

### Requirement: Authoritative identity and explicit sign-out

The CLI SHALL provide `whoami`, `logout` and administrator `sessions revoke --user <uuid-or-username>`. Current identity SHALL be verified with the server, not inferred from cache, and `whoami` SHALL report the names of the connections the caller can effectively use through direct grants and group memberships, each once, with a truncation flag, and the names of the groups the caller belongs to with their own truncation flag; administrators see an empty connection list because they need no grants. Logout SHALL attempt remote revocation and remove the matching local credential even when the server is unreachable, while reporting unconfirmed remote revocation as failure. Missing local credentials and confirmed invalid/expired server sessions SHALL make logout an idempotent success.

#### Scenario: Verify an active identity
- **WHEN** whoami runs with a valid cached session
- **THEN** the server-confirmed user, expiry, effective connection names and group names are returned without the token

#### Scenario: Remote session is revoked
- **WHEN** whoami uses a session revoked through another client
- **THEN** it reports an authentication failure instead of presenting cached identity as active

#### Scenario: Sign out during an outage
- **WHEN** logout cannot reach the server
- **THEN** the local credential is removed and exit code 1 clearly reports that remote revocation was not confirmed
- **AND** the output does not claim `revoked:true`

#### Scenario: Sign out repeatedly
- **WHEN** logout has no local credential or the server confirms that the cached session is no longer valid
- **THEN** it succeeds after ensuring the matching local credential is absent

#### Scenario: Revoke another user's sessions
- **WHEN** a current administrator invokes sessions revoke with a valid user UUID or username
- **THEN** the CLI calls the protected revocation endpoint and reports only its safe result
- **AND** a non-admin receives a forbidden result without a mutation

### Requirement: Grant commands

The CLI SHALL provide `grants list [--user <ref> | --group <ref>] [--connection <ref>] [--limit N] [--effective]`, `grants create (--user <ref> | --group <ref>) --connection <ref> [--dry-run]` and `grants revoke (--user <ref> | --group <ref>) --connection <ref> [--dry-run]`, where a user reference is a UUID or username, a group reference is a UUID or name and a connection reference is a UUID or name, validated locally for syntax and flag exclusivity before any request. `create` and `revoke` SHALL require exactly one of `--user` and `--group`; `list` SHALL accept at most one of them, and `--effective` SHALL refuse `--group` locally and send `--user` as given or omitted, leaving the role-dependent default and refusal to the server. The commands SHALL use the stored session, the shared flags, transport, envelope, dry-run and hint conventions of the other groups; listings SHALL be read under the listing response limit. Results SHALL render the grant with the recipient kind, both identifiers and names; `revoke` SHALL render whether a grant was removed; the effective listing SHALL render the subject's username, role and status, then one line per connection and path naming the source and, for a group path, the group, and SHALL validate that a `group` entry carries a group and a `direct` entry does not. `USER_NOT_FOUND`, `GROUP_NOT_FOUND`, `CONNECTION_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`. Members MAY run `grants list` and see only their own direct grants, and `grants list --effective` for their own grant paths.

#### Scenario: Grant by names
- **WHEN** an administrator runs `grants create --user alice --connection payments-prod-reporting`
- **THEN** the CLI sends one request and prints the grant with a `user` recipient carrying alice's UUID and username and the connection's UUID and name

#### Scenario: Grant to a group
- **WHEN** an administrator runs `grants create --group finance-managers --connection payments-prod-reporting`
- **THEN** the CLI sends one request and prints the grant with a `group` recipient carrying the group's UUID and name

#### Scenario: Repeated revoke
- **WHEN** `grants revoke` runs twice for the same pair
- **THEN** the first prints `Revoked: true` and the second `Revoked: false`, both exit 0

#### Scenario: Invalid references
- **WHEN** `--user`, `--group` or `--connection` is neither a UUID nor a valid name, both `--user` and `--group` are given, neither is given to a mutation, `--effective` is combined with `--group`, or a positional argument is present
- **THEN** the command exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Grant paths as text
- **WHEN** an administrator runs `grants list --user alice --effective --output text`
- **THEN** alice's username, role and status print first, then each path on one line with the connection name, `direct` or the group name, and the grant time, followed by a truncation notice only when the server reports truncation

#### Scenario: Member inspects own paths
- **WHEN** a member runs `grants list --effective` without `--user`, or with their own username
- **THEN** the CLI sends the request as given and prints their own paths; with another user's reference the server answers `FORBIDDEN` and the CLI exits 1 with that code

#### Scenario: Administrator omits the subject
- **WHEN** an administrator runs `grants list --effective` without `--user`
- **THEN** the server answers `INVALID_ARGUMENT` with a hint naming `--user`, which the CLI renders and exits 2, as it does for every invalid-argument answer

#### Scenario: Member lists own grants as text
- **WHEN** a member runs `grants list --output text`
- **THEN** each of their direct grants prints on one line with the recipient, connection name and the grant time, followed by a truncation notice only when the server reports truncation

## ADDED Requirements

### Requirement: Group management commands

The CLI SHALL provide `groups list [--limit N]`, `groups get --group <ref>`, `groups create --name <slug> [--description <text>]`, `groups update --group <ref> [--name <slug>] [--description <text>]`, `groups delete --group <ref>`, `groups members --group <ref> [--limit N]`, `groups add-member --group <ref> --user <ref>` and `groups remove-member --group <ref> --user <ref>`, where a group reference is a UUID or a name and a user reference is a UUID or a username, validated locally before any request. These commands SHALL use the stored session, the `--server`/`--timeout` flags, origin policy, bounded transport and result envelope of the other authenticated commands, SHALL read the group and member listings under the listing response limit, SHALL call only the documented group routes, and SHALL use the verb vocabulary shared with `users`, `connections` and `grants`. Every mutating command SHALL accept `--dry-run`. Results SHALL expose only group records, membership results and safe user records; errors SHALL render the server's `hint` when present. `GROUP_EXISTS`, `GROUP_NOT_FOUND`, `GROUP_IN_USE`, `USER_NOT_FOUND`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`.

#### Scenario: Create and populate a group
- **WHEN** an administrator runs `groups create --name finance-managers --description "Finance managers"` and then `groups add-member --group finance-managers --user alice`
- **THEN** the first command prints the record with `id`, `name`, zero members and zero grants, and the second prints the membership with both identifiers and names and `added: true`

#### Scenario: Guarded delete as a dry run
- **WHEN** `groups delete --group finance-managers --dry-run` targets a group that still holds grants
- **THEN** the CLI exits 1 with `GROUP_IN_USE`, renders the hint with the remaining count, and the server has changed nothing

#### Scenario: Members as text
- **WHEN** `groups members --group finance-managers --output text` runs
- **THEN** each member prints on one line with ID, username, status and the time they were added, followed by a truncation notice only when the server reports truncation

#### Scenario: Invalid group arguments
- **WHEN** a `groups` command receives a reference that is neither a UUID nor a valid name, a name outside the grammar, a positional argument, or `update` without any field
- **THEN** it exits 2 with `INVALID_ARGUMENT` and a hint, without contacting the server

#### Scenario: Member runs a group command
- **WHEN** a member's stored session runs any `groups` command
- **THEN** the CLI exits 1 with `FORBIDDEN` and no mutation occurs
