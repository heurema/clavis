## Why

Access is granted one user at a time: onboarding a manager means repeating every grant their team holds, and offboarding means finding them all again. Groups are the last item in the MVP scope (PRD section 9, ACCESS-02, ACCESS-03, the "effective access is the union" rule in 7.2), the PRD status paragraph names them as the planned next step, and the later-stage identity-provider synchronization needs a group model to land on.

## What Changes

- Add groups: an administrator creates, renames, describes and deletes a group and adds or removes members. Groups are addressed by UUID or name like connections; names follow the username grammar and are never UUID-shaped. Membership is idempotent for retrying agents, survives blocking, and records who added the member.
- Let a grant name a group as its recipient. **BREAKING**: a grant record carries one `recipient` (`kind` `user` or `group`, `id`, `name`) instead of the `user` field; the create and revoke bodies take exactly one of `user` or `group` beside `connection`. Nothing is in production, so no compatibility shim is added.
- Make effective access the union of direct grants and grants held through membership. The per-request authorization operation, the member projection of `connections list` and `connections get`, and the `whoami` connection names all use that union, so a member inherits a connection the moment they join a group and loses it the moment they leave or the group's grant is revoked, without any derived row being stored.
- Let administrators inspect where a user's access comes from: `grants list --user <ref> --effective` returns the subject's record and one entry per connection and configured path, `direct` or the group it came through, so revoking one path visibly leaves the others. Entries describe grant paths, not usability: an administrator's bypass and a blocked state are visible on the record, and only the authorization operation says whether a connection can be used now. Members may inspect their own paths.
- Extend `whoami` with the caller's group names, bounded with a truncation flag, so an agent's first call already says which groups it belongs to.
- Guard group deletion: a group that still holds grants is refused with `GROUP_IN_USE` and the count in the hint; memberships are dropped with the group because membership alone confers nothing.
- Add the `groups` CLI group (`list`, `get`, `create`, `update`, `delete`, `members`, `add-member`, `remove-member`) with the shared conventions, `--group` on the grant commands, JSON routes under `/api/admin/groups` and `/api/admin/grants/effective`, a forward migration `007`, a read-only Groups page in the console with a recipient column on the Grants page, skill wording for the new vocabulary, and smoke coverage of inheritance, provenance and revocation through a group.

## Capabilities

### New Capabilities

- `group-management`: group records and lifecycle, membership management, the delete guard, group routes, and the read-only Groups page.

### Modified Capabilities

- `connection-grants`: a grant has one recipient, user or group; member visibility and per-request authorization use effective access; the grant routes gain the group filter and the effective-access listing; the Grants page shows the recipient; `whoami` connection names are the effective set.
- `cli-authentication`: `whoami` reports group names; the grant commands accept `--group` and `--effective`; the new `groups` command group.
- `local-authentication`: the administration shell has four pages and loads four bounded lists, with `/admin/groups` among them.
- `query-execution`: the authorization sentence names effective access through a direct grant or a group, not a grant alone.

## Impact

- Backend: `internal/auth` (group and membership DTOs, the `Groups` interface, grant recipient, effective-access types, `Identity` extension, codes `GROUP_NOT_FOUND`, `GROUP_EXISTS`, `GROUP_IN_USE`, route paths), `internal/database` (migration `007`, group, membership, recipient and effective-access queries, `groups.go`, the grants service and the member read paths rewritten on the union, readiness column checks), `internal/server` (group routes, grant recipient decoding, effective listing, `whoami` extension, the Groups page).
- UI: `internal/web` Groups table, Grants recipient column, sidebar entry, regenerated templ.
- Client: `internal/cli` groups commands, `--group` and `--effective` on grants, `whoami` rendering, per-route error allowlists, the skill drift test.
- Tooling and docs: `internal/skill/clavis/SKILL.md` administration vocabulary, `scripts/smoke.mjs`, README (Groups section, Grants section, the planned-work sentence), PRD sections 7.2 status, 9 and 12.
- Dependencies: none.

## Decisions recorded for owner review (2026-09-14)

Made while planning, not yet confirmed by the owner; each is cheap to reverse before implementation starts. An independent read-only planning review on 2026-09-14 accepted all five, with two conditions folded into the design and specs: members must keep a way to see their own grant paths, and `whoami` must reserve room for group names so connections cannot crowd them out.

- One `grants` table with exactly one recipient per row, rather than a separate group-grants table: one listing, one page, one delete-guard count, one `ON CONFLICT` insert.
- The `groups` commands and routes are administrator-only, like `users`; a member learns their groups from `whoami` and never sees another member's username through a group.
- Deleting a group requires zero grants and drops its memberships; there is no enabled flag on groups.
- Administrators may be group members and groups may hold grants to administrators, both without effect on access, matching how grants to administrators are allowed today.
- Group names share the username grammar but not the username namespace: `--user` and `--group` make every reference unambiguous.

## Non-goals

Identity-provider group synchronization, nested groups, per-connection manager permissions, group-scoped administration, grant expiry, bulk operations, an audit journal.
