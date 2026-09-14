## Context

`add-connection-grants` left a `grants` table keyed on user and connection, a `Grants` service on `LocalAuth` behind `administer` (advisory key, ordered row locks, recheck, savepoint dry run), the member read paths joined on `grants`, one `AuthorizeConnection` every provider calls, bearer-only routes under `/api/admin/grants`, the `grants` CLI group and a read-only Grants table. Users, connections and grants are addressed by UUID or name. `whoami` lists a member's granted connection names inside a byte budget. The audit journal is gone (`005`), so no event allowlists need widening.

This change adds groups as a second grant recipient and turns every "does this user hold a grant" question into "does this user hold effective access", the union of direct and group grants. It reuses every pattern from the grants change and adds two tables, one query family and one CLI group.

## Goals / Non-Goals

**Goals:**
- Access described per team: join a group, inherit its connections; leave it, lose them on the next request.
- One effective-access predicate shared by authorization, member reads and `whoami`, cheap enough to run on every request and never materialized.
- Provenance an administrator can read: which path gives a user a connection.
- The same agent-first conventions: names or UUIDs, idempotent mutations, dry runs, hints, bounded listings.

**Non-Goals:**
- Identity-provider synchronization, nested groups, group-scoped administration, per-connection managers, expiry, bulk operations, an audit journal, member-visible group rosters.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| `administer` transaction shape, advisory key per domain, ordered row locks, savepoint dry run, hints re-attached | archived `add-connections` design decision 3 | Retained; groups use a sixth advisory key `groupMutationLock` (`0x434c415649530006`); membership mutations share it; grant mutations keep the fifth |
| Bearer-only JSON routes, strict decoding, `no-store`, adapter rejections once, service outcomes once | archived `add-connections` design decision 4 | Retained for `/api/admin/groups` and the effective listing |
| Agent-first CLI rules: one vocabulary, names or ids, `--dry-run`, hints, listing bounds | archived `add-connections` design | Retained; `groups` joins the vocabulary; `--group` follows `--user` and `--connection` |
| Grant references UUIDs; renames never move access | connection-grants "Grant records" | Retained and extended to groups |
| A grant links one user to one connection; results carry `user` | connection-grants "Grant records" | Explicitly changed (proposal, BREAKING): one recipient, user or group, carried as `recipient {kind, id, name}` |
| Members see granted connections only, in the summary projection; ungranted is `CONNECTION_NOT_FOUND` | connection-grants "Member visibility" | Retained; "granted" now means effective access |
| Authorization: enabled and (administrator or grant) | connection-grants "Per-request connection authorization" | Retained; "grant" now means effective access |
| Administrators use any connection without a grant; grants to administrators allowed | owner decisions 2026-09-12 | Retained; administrators may also be group members without effect |
| Delete guard: connection needs zero grants, count in the hint | connection-management "Administrator-only connection operations" | Retained; the count includes group grants, since they live in the same table |
| Users are never deleted; foreign keys without cascade | archived `add-connection-grants` design decision 2 | Retained for users; explicitly extended: `group_members.group_id` cascades on group delete, because membership alone confers nothing and the delete guard already requires zero grants |
| `whoami` carries granted connection names inside a byte budget | connection-grants "Grant routes and listing", archived review follow-up | Retained; the names become the effective set and `groups` names join under the same budget after the connections |
| Username grammar shared with connection names; never UUID-shaped | user-administration, connection-management | Retained; group names use the same grammar, in their own namespace |
| Read-only admin tables, sidebar counts, fail closed | user-administration, connection-management, connection-grants | Retained; Groups page added, Grants page gains the recipient |
| `groups` deferred | PRD section 12 "Grants" row | Completed here |

No unresolved departure requires owner approval beyond the five decisions listed in the proposal.

## Decisions

### 1. One grants table, one recipient per row

Migration `007` keeps `grants` and widens it rather than adding a `group_grants` table:

```sql
CREATE TABLE groups (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9._-]{2,63}$'
        AND name !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE group_members (
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL REFERENCES users(id),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id, group_id);
ALTER TABLE grants DROP CONSTRAINT grants_pkey;
ALTER TABLE grants ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE grants ADD COLUMN group_id uuid REFERENCES groups(id);
ALTER TABLE grants ADD CONSTRAINT grants_one_recipient CHECK ((user_id IS NULL) <> (group_id IS NULL));
CREATE UNIQUE INDEX grants_user_connection ON grants(user_id, connection_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX grants_group_connection ON grants(group_id, connection_id) WHERE group_id IS NOT NULL;
```

Existing rows satisfy the check (they all have a user). The description bound is 2,000 characters, matching the connection description's constraint and Go validator, not bytes. `ON CONFLICT DO NOTHING` without a conflict target still covers both partial indexes, so `InsertGrant` keeps its shape with a nullable `user_id` and `group_id`, and the existing-row lookup on conflict stays. The alternative, a separate `group_grants` table, would leave the existing queries untouched but double the listing (a `UNION` for the page and the CLI), the delete-guard count and the insert and delete paths; the single table keeps one listing query with two `LEFT JOIN`s, one count and one guard. No `ON DELETE` on `grants.group_id`: group delete is guarded to zero grants, the honest choice as for connections.

Readiness gains `CheckGroupsColumns` and `CheckGroupMembersColumns`; `CheckGrantsColumns` adds `group_id`.

### 2. Effective access is one predicate

One SQL fragment, repeated in the four member-facing queries (`ListGrantedConnections`, `FindGrantedConnectionByID`, `FindGrantedConnectionByName`, `ListGrantedConnectionNames`):

```sql
EXISTS (
    SELECT 1 FROM grants g
    WHERE g.connection_id = c.id
      AND (g.user_id = $user
           OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = $user))
)
```

`EXISTS` returns each connection once whatever the number of paths, so the listing, the name list and the byte budget need no deduplication in Go. The exact formulation (one predicate, or two `EXISTS` branches for the direct and the membership path using the partial recipient indexes) is left to the implementer; the slice 2 review records `EXPLAIN (ANALYZE, BUFFERS)` for the point lookup, the member listing and the name list on a selective member and on a heavily granted connection, and the design claims no bound before that evidence exists. Nothing derived is stored: a membership change or a group grant revocation is visible on the next request, which is what the revocation scenarios require. `AuthorizeConnection` changes only in the query it calls.

### 3. Contracts

`internal/auth` gains:

```go
type RecipientKind string // "user" | "group"
type Recipient struct { Kind RecipientKind `json:"kind"`; ID string `json:"id"`; Name string `json:"name"` }
type Grant struct {
    Recipient  Recipient  `json:"recipient"`
    Connection GrantParty `json:"connection"`
    CreatedAt  time.Time  `json:"createdAt"`
    CreatedBy  GrantParty `json:"createdBy"`
}
type GrantRequest struct { User, Group, Connection string } // exactly one of User, Group
type GrantFilter struct { User, Group, Connection string; Limit int }
type AccessEntry struct {
    Connection GrantParty  `json:"connection"`
    Source     string      `json:"source"` // "direct" | "group"
    Group      *GrantParty `json:"group,omitempty"`
    CreatedAt  time.Time   `json:"createdAt"`
}
type AccessList struct {
    User      UserRecord    `json:"user"`      // the subject: role and disabled state explain the bypass and blocking
    Entries   []AccessEntry `json:"entries"`   // configured grant paths, never a usability claim
    Truncated bool          `json:"truncated"`
}

type Group struct { ID, Name, Description string; CreatedAt, UpdatedAt time.Time; Members, Grants int }
type GroupList struct { Groups []Group; Truncated bool }
type GroupRequest struct { Name, Description string }            // create
type GroupUpdate struct { Name, Description *string }             // update, at least one
type GroupMutation struct { Group Group; DryRun bool }
type GroupDeletion struct { Group GrantParty; DryRun bool }
type Membership struct { Group, User GrantParty; CreatedAt time.Time; CreatedBy GrantParty }
type MembershipMutation struct { Membership Membership; Added bool; DryRun bool }
type MembershipRemoval struct { Group, User GrantParty; Removed bool; DryRun bool }
type Member struct { UserRecord; AddedAt time.Time; AddedBy GrantParty }
type MemberList struct { Members []Member; Truncated bool }

type Groups interface {
    ListGroups(ctx, Session, limit int) (GroupList, error)
    GetGroup(ctx, Session, ref string) (Group, error)
    CreateGroup(ctx, Session, GroupRequest, dryRun bool) (GroupMutation, error)
    UpdateGroup(ctx, Session, ref string, GroupUpdate, dryRun bool) (GroupMutation, error)
    DeleteGroup(ctx, Session, ref string, dryRun bool) (GroupDeletion, error)
    ListMembers(ctx, Session, ref string, limit int) (MemberList, error)
    AddMember(ctx, Session, groupRef, userRef string, dryRun bool) (MembershipMutation, error)
    RemoveMember(ctx, Session, groupRef, userRef string, dryRun bool) (MembershipRemoval, error)
}
```

`Grants` gains `ListEffectiveAccess(ctx, Session, userRef, connectionRef string, limit int) (AccessList, error)`, where an empty `userRef` means the caller and the role rule of decision 4 is the server's, never the CLI's. `Identity` gains `Groups []string` and `GroupsTruncated bool`. The `Groups` interface and `ListEffectiveAccess` are declared in slice 1; nothing is wired to them until slices 2 and 3 implement and mount them, and no placeholder implementation returning `SERVICE_UNAVAILABLE` is added. `GrantRevocation` carries `Recipient` instead of `User`. Validators: `ValidGroupName = ValidUsername` (same grammar, refuses the UUID shape), `ValidGroupRef = ValidUserID || ValidGroupName`. Codes: `GROUP_NOT_FOUND` (404), `GROUP_EXISTS` (409), `GROUP_IN_USE` (409), each with a hint. Paths: `GroupsPath`, `GroupPath`, `GroupUpdatePath`, `GroupDeletePath`, `GroupMembersPath`, `GroupMemberAddPath`, `GroupMemberRemovePath`, `GrantsEffectivePath`. `MaxGroupListing` and `MaxMemberListing` are 1,000.

A `Recipient` with an explicit `kind` rather than two optional fields keeps the CLI's strict decoding simple (one required object) and the text rendering unambiguous (`alice → conn`, `group finance-managers → conn`).

### 4. Service

`groups.go` on `LocalAuth` implements `auth.Groups`. Mutations run through `administer` with `groupMutationLock`; the group row is locked with `LockGroup` (a `FOR UPDATE` resolver by UUID or name, the group counterpart of `lockConnection`), and membership mutations pass the user reference as `targetRef` so `lockMutationUsers` orders the user lock as it does for user administration. Create: insert, `GROUP_EXISTS` on the unique violation. Update: at least one field, `GROUP_EXISTS` on a rename collision with nothing written, `updated_at` bumped only on a change; the description is validated with the connection description's character-count validator. Delete: count grants; nonzero → `GROUP_IN_USE` with the count in the hint; zero → delete, cascade removes memberships. Add member: `ON CONFLICT DO NOTHING`, existing → `Added: false`; a blocked user may be added, matching how grants survive blocking. Remove: `:execrows`, zero → `Removed: false`. Reads (`ListGroups`, `GetGroup`, `ListMembers`) run in the administrator read transaction with `recheck`; member and grant counts come from correlated subqueries in the listing query. Every group operation is administrator-only, so `FORBIDDEN` for members follows from `authorize`.

The `denial` allowlist in `admin.go` gains `GROUP_NOT_FOUND`, `GROUP_EXISTS` and `GROUP_IN_USE`; without that, `administer` would turn them into `SERVICE_UNAVAILABLE`. Hints are re-attached by the caller as `DeleteConnection` does, the counted delete hint through a captured variable, so a dry run reports the count too.

Lock order, recorded so no path inverts it: the domain advisory key (`groupMutationLock` or `grantMutationLock`, never both in one transaction), then the actor and target user rows in UUID order through `lockMutationUsers`, then the session recheck, then the group row, then the connection row where the operation names one. Group deletion takes no grant advisory key and no membership user locks; the two advisory keys do not serialize each other, and the group row is what serializes a group delete against a group grant: grant first yields `GROUP_IN_USE` for the delete, delete first yields `GROUP_NOT_FOUND` for the grant, both tested with different actors. Membership add against a block of the same user serializes on the user row.

`grants.go` changes: `grantParties` resolves the recipient by kind (user via the existing resolver, group via `findGroup`) and locks the group row inside the grant transaction after the user rows. `ListGrants` gains the group filter; members are still forced to their own user id, answer `FORBIDDEN` to a group filter before any lookup, and never see group grants in the record listing; an unknown filter reference yields an empty list as today. `ListEffectiveAccess`: the server resolves the subject after `recheck`: members get themselves when the reference is empty or names them, `FORBIDDEN` otherwise; administrators must name a user, `INVALID_ARGUMENT` with a hint when they do not. The result carries the subject's safe record and one query that unions direct rows (`source = 'direct'`) and membership rows (`source = 'group'` with the group party), ordered by connection name, source, group name, limit plus one. Entries are configured paths: an administrator subject lists whatever grants name them or their groups, and `role: admin` on the record explains that their access does not depend on them.

Member reads and `AuthorizeConnection` switch to the queries of decision 2 without other change. The connection delete guard's `CountConnectionGrants` counts both kinds unchanged.

`whoami`: `ListGrantedConnectionNames` becomes the effective names; a new `ListGroupNames(user, limit)` fills `Groups`. The names budget (the general response limit minus the identity headroom) is split so groups can never be starved by connections: `boundedNames` runs on the groups first against an 8 KiB reservation, then on the connections against the total budget minus the bytes the groups actually consumed, so an unused reservation goes back to connections. `connectionsTruncated` and `groupsTruncated` are independent.

### 5. HTTP

| Method/path | Body | Success |
|---|---|---|
| `GET /api/admin/groups?limit=` | none | 200 `GroupList` |
| `POST /api/admin/groups[?dryRun=true]` | `{name, description?}` | 201 `GroupMutation` |
| `GET /api/admin/groups/{groupID}` | none | 200 `Group` |
| `POST /api/admin/groups/{groupID}/update[?dryRun=true]` | `{name?, description?}` | 200 `GroupMutation` |
| `POST /api/admin/groups/{groupID}/delete[?dryRun=true]` | none | 200 `GroupDeletion` |
| `GET /api/admin/groups/{groupID}/members?limit=` | none | 200 `MemberList` |
| `POST /api/admin/groups/{groupID}/members/add[?dryRun=true]` | `{user}` | 201 `MembershipMutation` (`added: true`), 200 when it existed or on dry run |
| `POST /api/admin/groups/{groupID}/members/remove[?dryRun=true]` | `{user}` | 200 `MembershipRemoval` |
| `GET /api/admin/grants?user=&group=&connection=&limit=` | none | 200 `GrantList` |
| `POST /api/admin/grants[?dryRun=true]` | `{user?, group?, connection}` | 201 / 200 as today |
| `POST /api/admin/grants/revoke[?dryRun=true]` | `{user?, group?, connection}` | 200 `GrantRevocation` |
| `GET /api/admin/grants/effective?user=&connection=&limit=` | none | 200 `AccessList` (`user` empty means the caller; the server applies the role rule) |

The adapter rejects a grant body with both or neither recipient as `INVALID_ARGUMENT` with the hint before the service sees it; the group reference on the path is validated like the connection reference. The four new listings (groups, members, effective entries, and the grant listing as today) go through `boundedListing` under `MaxListingBody`, and the CLI's `responseLimit` reads them under the same limit; without that a legitimate listing above 64 KiB would be refused by the CLI. `HandlerWithAuth` gains the `Groups` dependency in slice 3; the `LocalAuth` value satisfies it. `identityJSON` fills `Groups` for every caller and `Connections` for members, as described in decision 4.

### 6. CLI

`groups` group: `list [--limit]`, `get --group`, `create --name [--description]`, `update --group [--name] [--description]`, `delete --group`, `members --group [--limit]`, `add-member --group --user`, `remove-member --group --user`; mutations take `--dry-run`. `grants`: `--group` beside `--user` on all three, `--effective` on `list`. Local validation before any request: exactly one recipient on mutations, at most one on `list`, `--effective` refuses `--group`. Text renderings: group `Group: finance-managers (<id>)`, `Description:`, `Members: 3`, `Grants: 2`; members one line `id username status addedAt`; membership `Member: alice → finance-managers`, `Added: true|false`; grant `Grant: alice → conn` or `Grant: group finance-managers → conn`; effective one line `conn direct <time>` or `conn via finance-managers <time>`; `whoami` gains `Groups: a, b`. Per-route allowlists gain the three group codes; the skill drift test picks up the new commands automatically because it reads the CLI definitions.

### 7. Web

Groups page: name, description, members, grants, created (UTC); `PageGroups` between Users and Connections in the sidebar, since groups are about people. Grants page: the first column becomes the recipient, rendered as the name with a muted `group` badge for group grants. `adminPage` loads groups after users and fails closed like the other lists.

### 8. Skill, smoke and documentation

`SKILL.md` adds `groups` to the administration vocabulary, one sentence that `whoami` names the caller's groups and that access can come through a group, and that `grants list --effective` explains which path supplies a connection; still under 200 lines and no instruction to change access. Smoke, after the grant section: create a group, add the member, grant the group the metrics connection, member `whoami` lists the connection and the group, member `connections list` shows it once beside the direct one, `grants list --user --effective` shows both paths, revoke the direct grant and the connection stays, remove the member and it disappears on the next call, `groups delete` dry run refused with the count, revoke, delete succeeds, member `groups list` is `FORBIDDEN`. README gains a Groups section and the grants section describes recipients and `--effective`; PRD sections 7.2, 9 and 12 record groups as delivered.

## Risks / Trade-offs

- [The grants table rewrite changes the primary key under existing rows] → the migration is transactional, existing rows satisfy the check, and the migration test proves rows survive and both partial indexes enforce uniqueness.
- [Effective-access predicate repeated in four queries] → one fragment, reviewed once, with a test per query proving group inheritance; sqlc keeps them typed.
- [Grant JSON shape changes] → BREAKING by proposal; nothing is in production; CLI and server change together.
- [Sidebar gains a fifth entry and a fourth list load per admin page] → each list is bounded and indexed; the page already fails closed on any of them.
- [`whoami` grows by group names] → groups take an 8 KiB reservation first and connections the rest, so a member with many long connection names still learns their groups; both truncation flags are independent and tested at the boundary.
- [Members never see who else is in their group] → deliberate least-disclosure; `whoami` tells them their groups and `grants list --effective` which path supplies a connection, which is what an agent needs to explain access.
- [Slice 1 rewrites the grant contract under every consumer] → the mechanical migration lands in the same slice with the existing suites green and nothing wired to the new interfaces, so no intermediate state ships a broken tree or a placeholder implementation.

## Migration Plan

1. Deploy; migration `007` applies once inside the migration lock. No data is rewritten beyond the constraints.
2. Every CLI must be updated with the server: the grant shape and `whoami` change. Nothing is in production, so no compatibility window.
3. Rollback as before: previous binary and backup; `007` is forward-only.

## Open Questions

None beyond the proposal's recorded decisions.
