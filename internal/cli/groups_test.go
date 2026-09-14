package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

// The hints below are the fixture's application-owned guidance for the group
// and effective routes. None of them echoes a submitted value.
const (
	groupNotFoundHint    = "List groups to find the name or UUID"
	groupInUseHint       = "Revoke the group's remaining grants first"
	effectiveSubjectHint = "Name the user whose access to report with --user"
)

func (f *cliAuthFixture) groupRefIndex(reference string) int {
	for i, group := range f.groups {
		if group.ID == strings.ToLower(reference) || group.Name == reference {
			return i
		}
	}
	return -1
}

func (f *cliAuthFixture) isMember(groupID, userID string) bool {
	for _, membership := range f.memberships {
		if membership.Group.ID == groupID && membership.User.ID == userID {
			return true
		}
	}
	return false
}

// groupCounts fills the two counts a group record carries, which the store
// computes on read rather than storing.
func (f *cliAuthFixture) groupCounts(group auth.Group) auth.Group {
	for _, membership := range f.memberships {
		if membership.Group.ID == group.ID {
			group.Members++
		}
	}
	for _, grant := range f.grants {
		if grant.Recipient.Kind == auth.RecipientGroup && grant.Recipient.ID == group.ID {
			group.Grants++
		}
	}
	return group
}

// serveGroups implements the design's group route table over the fixture's
// group and membership stores: documented statuses, the dryRun query
// parameter, idempotent add and remove, the guarded delete with its count, and
// the administrator-only rule every route shares.
func (f *cliAuthFixture) serveGroups(w http.ResponseWriter, r *http.Request, actor auth.Identity, body []byte, fail func(string)) {
	f.groupCalls++
	f.groupQuery = r.URL.RawQuery
	encode := func(status int, value any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	failHint := func(code, hint string) {
		status, safe, _ := auth.LookupFailure(code)
		safe.Hint = hint
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
	}
	suffix := strings.TrimPrefix(r.URL.Path, auth.GroupsPath)
	reference := strings.TrimPrefix(suffix, "/")
	verb := ""
	if index := strings.Index(reference, "/"); index >= 0 {
		reference, verb = reference[:index], reference[index+1:]
	}
	list := r.Method == http.MethodGet && suffix == ""
	create := r.Method == http.MethodPost && suffix == ""
	get := r.Method == http.MethodGet && reference != "" && verb == ""
	members := r.Method == http.MethodGet && verb == "members"
	post := r.Method == http.MethodPost && reference != ""
	if !list && !create && !get && !members && !post {
		fail(auth.InvalidArgument)
		return
	}
	if post && verb != "update" && verb != "delete" && verb != "members/add" && verb != "members/remove" {
		fail(auth.InvalidArgument)
		return
	}
	needsBody := create || verb == "update" || verb == "members/add" || verb == "members/remove"
	if needsBody != (len(body) != 0) || (len(body) != 0 && r.Header.Get("Content-Type") != "application/json") {
		fail(auth.InvalidArgument)
		return
	}
	dryRun := false
	for key, values := range r.URL.Query() {
		valid := len(values) == 1
		switch key {
		case auth.DryRunQuery:
			valid = valid && values[0] == "true" && r.Method == http.MethodPost
			dryRun = true
		case "limit":
			valid = valid && (list || members)
		default:
			valid = false
		}
		if !valid {
			fail(auth.InvalidArgument)
			return
		}
	}
	role := actor.User.Role
	if i := f.userIndex(actor.User.ID); i >= 0 {
		role = f.users[i].Role
	}
	// Every group operation, reads included, is administrator-only.
	if role != auth.Admin {
		fail(auth.Forbidden)
		return
	}
	if reference != "" && !auth.ValidGroupRef(reference) {
		fail(auth.InvalidArgument)
		return
	}
	f.groupBody = body
	switch {
	case list:
		f.listGroups(r, encode, failHint)
	case create:
		f.createGroup(body, dryRun, encode, fail, failHint)
	case get, members:
		index := f.groupRefIndex(reference)
		if index < 0 {
			failHint(auth.GroupNotFound, groupNotFoundHint)
			return
		}
		if get {
			encode(http.StatusOK, f.groupCounts(f.groups[index]))
			return
		}
		f.listMembers(r, f.groups[index], encode, failHint)
	default:
		f.mutateGroup(reference, verb, body, dryRun, actor, encode, fail, failHint)
	}
}

func (f *cliAuthFixture) listGroups(r *http.Request, encode func(int, any), failHint func(code, hint string)) {
	limit := auth.MaxGroupListing
	if raw := r.URL.Query()["limit"]; len(raw) == 1 {
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > auth.MaxGroupListing {
			failHint(auth.InvalidArgument, "--limit accepts 1 to "+strconv.Itoa(auth.MaxGroupListing))
			return
		}
		limit = value
	}
	listed := []auth.Group{}
	for _, group := range f.groups {
		listed = append(listed, f.groupCounts(group))
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Name < listed[j].Name })
	truncated := f.groupTruncated
	if len(listed) > limit {
		listed, truncated = listed[:limit], true
	}
	encode(http.StatusOK, auth.GroupList{Groups: listed, Truncated: truncated})
}

func (f *cliAuthFixture) listMembers(r *http.Request, group auth.Group, encode func(int, any), failHint func(code, hint string)) {
	limit := auth.MaxMemberListing
	if raw := r.URL.Query()["limit"]; len(raw) == 1 {
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > auth.MaxMemberListing {
			failHint(auth.InvalidArgument, "--limit accepts 1 to "+strconv.Itoa(auth.MaxMemberListing))
			return
		}
		limit = value
	}
	listed := []auth.GroupMember{}
	for _, membership := range f.memberships {
		if membership.Group.ID != group.ID {
			continue
		}
		index := f.userIndex(membership.User.ID)
		if index < 0 {
			continue
		}
		listed = append(listed, auth.GroupMember{UserRecord: f.users[index],
			AddedAt: membership.CreatedAt, AddedBy: membership.CreatedBy})
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Username < listed[j].Username })
	truncated := f.memberTruncated
	if len(listed) > limit {
		listed, truncated = listed[:limit], true
	}
	encode(http.StatusOK, auth.MemberList{Members: listed, Truncated: truncated})
}

func (f *cliAuthFixture) createGroup(body []byte, dryRun bool, encode func(int, any),
	fail func(string), failHint func(code, hint string)) {
	var input auth.GroupRequest
	if !strictJSON(body, &input) || !auth.ValidGroupName(input.Name) ||
		utf8.RuneCountInString(input.Description) > auth.MaxDescriptionLength {
		fail(auth.InvalidArgument)
		return
	}
	if f.groupRefIndex(input.Name) >= 0 {
		failHint(auth.GroupExists, "Choose a name no group holds")
		return
	}
	record := auth.Group{ID: testUserID(), Name: input.Name, Description: input.Description,
		CreatedAt: time.Now().UTC().Truncate(time.Second), UpdatedAt: time.Now().UTC().Truncate(time.Second)}
	if dryRun {
		encode(http.StatusOK, auth.GroupMutation{Group: record, DryRun: true})
		return
	}
	f.groups = append(f.groups, record)
	f.groupMutations++
	encode(http.StatusCreated, auth.GroupMutation{Group: record})
}

func (f *cliAuthFixture) mutateGroup(reference, verb string, body []byte, dryRun bool, actor auth.Identity,
	encode func(int, any), fail func(string), failHint func(code, hint string)) {
	index := f.groupRefIndex(reference)
	if index < 0 {
		failHint(auth.GroupNotFound, groupNotFoundHint)
		return
	}
	group := f.groups[index]
	party := auth.GrantParty{ID: group.ID, Name: group.Name}
	switch verb {
	case "update":
		var update auth.GroupUpdate
		if !strictJSON(body, &update) || (update.Name == nil && update.Description == nil) {
			fail(auth.InvalidArgument)
			return
		}
		if update.Name != nil && !auth.ValidGroupName(*update.Name) {
			fail(auth.InvalidArgument)
			return
		}
		if update.Name != nil && *update.Name != group.Name && f.groupRefIndex(*update.Name) >= 0 {
			failHint(auth.GroupExists, "Choose a name no group holds")
			return
		}
		if update.Name != nil {
			group.Name = *update.Name
		}
		if update.Description != nil {
			group.Description = *update.Description
		}
		group.UpdatedAt = time.Now().UTC().Truncate(time.Second)
		if !dryRun {
			f.groups[index] = group
			f.groupMutations++
		}
		encode(http.StatusOK, auth.GroupMutation{Group: f.groupCounts(group), DryRun: dryRun})
	case "delete":
		counted := f.groupCounts(group)
		if counted.Grants > 0 {
			failHint(auth.GroupInUse, groupInUseHint+"; "+strconv.Itoa(counted.Grants)+" remain")
			return
		}
		if !dryRun {
			f.groups = append(f.groups[:index], f.groups[index+1:]...)
			kept := f.memberships[:0]
			for _, membership := range f.memberships {
				if membership.Group.ID != group.ID {
					kept = append(kept, membership)
				}
			}
			f.memberships = kept
			f.groupMutations++
		}
		encode(http.StatusOK, auth.GroupDeletion{Group: party, DryRun: dryRun})
	default:
		f.mutateMembership(group, party, verb, body, dryRun, actor, encode, fail, failHint)
	}
}

func (f *cliAuthFixture) mutateMembership(group auth.Group, party auth.GrantParty, verb string, body []byte,
	dryRun bool, actor auth.Identity, encode func(int, any), fail func(string), failHint func(code, hint string)) {
	var input membershipRequest
	if !strictJSON(body, &input) || !auth.ValidUserRef(input.User) {
		fail(auth.InvalidArgument)
		return
	}
	user := f.userRefIndex(input.User)
	if user < 0 {
		failHint(auth.UserNotFound, userNotFoundHint)
		return
	}
	member := auth.GrantParty{ID: f.users[user].ID, Name: f.users[user].Username}
	existing := -1
	for i, membership := range f.memberships {
		if membership.Group.ID == group.ID && membership.User.ID == member.ID {
			existing = i
		}
	}
	if verb == "members/remove" {
		if existing >= 0 && !dryRun {
			f.memberships = append(f.memberships[:existing], f.memberships[existing+1:]...)
			f.groupMutations++
		}
		encode(http.StatusOK, auth.MembershipRemoval{Group: party, User: member, Removed: existing >= 0, DryRun: dryRun})
		return
	}
	if existing >= 0 {
		// An existing membership is returned unchanged with 200: adding is
		// idempotent, so a retrying agent needs no special case.
		encode(http.StatusOK, auth.MembershipMutation{Membership: f.memberships[existing], DryRun: dryRun})
		return
	}
	membership := auth.Membership{Group: party, User: member, CreatedAt: time.Now().UTC().Truncate(time.Second),
		CreatedBy: auth.GrantParty{ID: actor.User.ID, Name: actor.User.Username}}
	if dryRun {
		encode(http.StatusOK, auth.MembershipMutation{Membership: membership, Added: true, DryRun: true})
		return
	}
	f.memberships = append(f.memberships, membership)
	f.groupMutations++
	encode(http.StatusCreated, auth.MembershipMutation{Membership: membership, Added: true})
}

func groupsRun(t *testing.T, server *httptest.Server, args ...string) (int, Result, string) {
	t.Helper()
	return cliInvoke(t, "", append(args, "--server", server.URL)...)
}

func groupsText(t *testing.T, server *httptest.Server, args ...string) (int, string) {
	t.Helper()
	return grantsText(t, server, args...)
}

// groupFixture signs an administrator in against the shared fixture and seeds
// one group with one member and one grant, which is the shape the guard, the
// member listing and the effective paths all need.
func groupFixture(t *testing.T) (*cliAuthFixture, *httptest.Server) {
	t.Helper()
	fixture, server, memberID, _ := memberFixture(t)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	group := auth.Group{ID: testUserID(), Name: "finance-managers", Description: "Finance managers",
		CreatedAt: time.Now().UTC().Truncate(time.Second), UpdatedAt: time.Now().UTC().Truncate(time.Second)}
	fixture.groups = append(fixture.groups, group)
	party := auth.GrantParty{ID: group.ID, Name: group.Name}
	fixture.memberships = append(fixture.memberships, auth.Membership{
		Group: party, User: auth.GrantParty{ID: memberID, Name: "alice"},
		CreatedAt: time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC),
		CreatedBy: auth.GrantParty{ID: testIdentity().User.ID, Name: testIdentity().User.Username},
	})
	fixture.grants = append(fixture.grants, auth.Grant{
		Recipient:  auth.Recipient{Kind: auth.RecipientGroup, ID: group.ID, Name: group.Name},
		Connection: auth.GrantParty{ID: fixture.connections[1].ID, Name: fixture.connections[1].Name},
		CreatedAt:  time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC),
		CreatedBy:  auth.GrantParty{ID: testIdentity().User.ID, Name: testIdentity().User.Username},
	})
	return fixture, server
}

// TestGroupsWorkflow walks the documented lifecycle over the fixture: create,
// populate, read back, rename, the guarded delete and the delete that follows
// a revocation.
func TestGroupsWorkflow(t *testing.T) {
	cliHome(t)
	fixture, server, memberID, _ := memberFixture(t)

	exit, result, output := groupsRun(t, server, "groups", "create", "--name", "finance-managers",
		"--description", "Finance managers")
	require.Equal(t, 0, exit, "%+v", result.Error)
	record := result.Data.(map[string]any)["group"].(map[string]any)
	require.Equal(t, "finance-managers", record["name"])
	require.True(t, auth.ValidUserID(record["id"].(string)))
	require.Equal(t, float64(0), record["members"])
	require.Equal(t, float64(0), record["grants"])
	require.NotContains(t, output, "token")

	exit, result, _ = groupsRun(t, server, "groups", "add-member", "--group", "finance-managers", "--user", "alice")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.Equal(t, true, result.Data.(map[string]any)["added"])
	membership := result.Data.(map[string]any)["membership"].(map[string]any)
	require.Equal(t, map[string]any{"id": memberID, "name": "alice"}, membership["user"])
	require.Equal(t, "finance-managers", membership["group"].(map[string]any)["name"])
	require.True(t, auth.ValidUserID(membership["group"].(map[string]any)["id"].(string)))

	// The body is exactly the one reference the route documents.
	fixture.mu.Lock()
	require.JSONEq(t, `{"user":"alice"}`, string(fixture.groupBody))
	fixture.mu.Unlock()

	// A second add is idempotent: one request, added false.
	exit, result, _ = groupsRun(t, server, "groups", "add-member", "--group", "finance-managers", "--user", memberID)
	require.Equal(t, 0, exit)
	require.Equal(t, false, result.Data.(map[string]any)["added"])

	// get by name and by UUID return the same record, now with one member.
	exit, result, _ = groupsRun(t, server, "groups", "get", "--group", "finance-managers")
	require.Equal(t, 0, exit)
	require.Equal(t, float64(1), result.Data.(map[string]any)["members"])
	byUUID := result.Data.(map[string]any)["id"].(string)
	exit, other, _ := groupsRun(t, server, "groups", "get", "--group", byUUID)
	require.Equal(t, 0, exit)
	require.Equal(t, result.Data, other.Data)

	// A rename keeps the membership, because both reference the UUID.
	exit, result, _ = groupsRun(t, server, "groups", "update", "--group", "finance-managers", "--name", "finance-leads")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.Equal(t, "finance-leads", result.Data.(map[string]any)["group"].(map[string]any)["name"])
	exit, result, _ = groupsRun(t, server, "groups", "members", "--group", "finance-leads")
	require.Equal(t, 0, exit)
	require.Len(t, result.Data.(map[string]any)["members"], 1)

	// A grant to the group makes the delete guard bite, and revoking it lets
	// the delete through.
	exit, result, _ = groupsRun(t, server, "grants", "create", "--group", "finance-leads",
		"--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.Equal(t, map[string]any{"kind": "group", "id": byUUID, "name": "finance-leads"},
		result.Data.(map[string]any)["grant"].(map[string]any)["recipient"])

	exit, result, _ = groupsRun(t, server, "groups", "delete", "--group", "finance-leads")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.GroupInUse, result.Error.Code)

	exit, _, _ = groupsRun(t, server, "grants", "revoke", "--group", "finance-leads",
		"--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	exit, output = groupsText(t, server, "groups", "delete", "--group", "finance-leads")
	require.Equal(t, 0, exit)
	require.Equal(t, "Deleted: finance-leads ("+byUUID+")\n", output)

	// The delete removed the memberships with the group.
	fixture.mu.Lock()
	require.Empty(t, fixture.memberships)
	require.Empty(t, fixture.groups)
	fixture.mu.Unlock()
}

// The guarded delete as a dry run is the documented refusal: exit 1 with the
// server's hint and its count, and nothing changed.
func TestGroupsGuardedDeleteDryRunIsRefusedWithItsCount(t *testing.T) {
	cliHome(t)
	fixture, server := groupFixture(t)
	fixture.mu.Lock()
	before := fixture.groupMutations
	fixture.mu.Unlock()
	exit, output := groupsText(t, server, "groups", "delete", "--group", "finance-managers", "--dry-run")
	require.Equal(t, 1, exit)
	require.Contains(t, output, auth.GroupInUse)
	require.Contains(t, output, "Hint: "+groupInUseHint+"; 1 remain\n")
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.groupMutations, "a refused dry run changes nothing")
	require.Len(t, fixture.groups, 1)
}

// A dry run of a mutation that would succeed reports the outcome and commits
// nothing.
func TestGroupsDryRunsCommitNothing(t *testing.T) {
	cliHome(t)
	fixture, server := groupFixture(t)
	fixture.mu.Lock()
	before := fixture.groupMutations
	fixture.mu.Unlock()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"groups", "create", "--name", "warehouse-readers", "--dry-run"},
			"Group: warehouse-readers ("},
		{[]string{"groups", "update", "--group", "finance-managers", "--description", "", "--dry-run"},
			"Description: \n"},
		{[]string{"groups", "add-member", "--group", "finance-managers", "--user", "cli-test", "--dry-run"},
			"Member: cli-test → finance-managers\nAdded: true\nDry run: true\n"},
		{[]string{"groups", "remove-member", "--group", "finance-managers", "--user", "alice", "--dry-run"},
			"Member: alice → finance-managers\nRemoved: true\nDry run: true\n"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			exit, output := groupsText(t, server, tc.args...)
			require.Equal(t, 0, exit)
			require.Contains(t, output, tc.want)
			require.Contains(t, output, "Dry run: true\n")
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			require.Equal(t, before, fixture.groupMutations)
			require.Equal(t, auth.DryRunQuery+"=true", fixture.groupQuery)
		})
	}
}

// The group text block is the agent-facing rendering: the name and UUID an
// agent addresses the group by, what it is for and the two counts that decide
// whether it can be deleted.
func TestGroupsTextRendering(t *testing.T) {
	moment := time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC)
	id := "0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11"
	record := auth.Group{ID: id, Name: "finance-managers", Description: "Finance managers",
		CreatedAt: moment, UpdatedAt: moment, Members: 3, Grants: 2}
	other := auth.Group{ID: id, Name: "warehouse-readers", CreatedAt: moment, UpdatedAt: moment}
	block := "Group: finance-managers (" + id + ")\nDescription: Finance managers\nMembers: 3\nGrants: 2\n"
	member := auth.GroupMember{
		UserRecord: auth.UserRecord{ID: id, Username: "alice", Role: auth.Member, CreatedAt: moment},
		AddedAt:    moment, AddedBy: auth.GrantParty{ID: id, Name: "personal-admin"},
	}
	blocked := member
	blocked.Username, blocked.Disabled = "bob", true
	membership := auth.Membership{Group: auth.GrantParty{ID: id, Name: "finance-managers"},
		User: auth.GrantParty{ID: id, Name: "alice"}, CreatedAt: moment,
		CreatedBy: auth.GrantParty{ID: id, Name: "personal-admin"}}
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"record": {success(record), block},
		"list":   {success(auth.GroupList{Groups: []auth.Group{record, other}}), id + " finance-managers 3 2\n" + id + " warehouse-readers 0 0\n"},
		"list-truncated": {success(auth.GroupList{Groups: []auth.Group{record}, Truncated: true}),
			id + " finance-managers 3 2\nTruncated: list is limited to 1000 groups\n"},
		"list-empty": {success(auth.GroupList{Groups: []auth.Group{}}), ""},
		"created":    {success(auth.GroupMutation{Group: record}), block},
		"created-dry": {success(auth.GroupMutation{Group: record, DryRun: true}),
			block + "Dry run: true\n"},
		"deleted": {success(auth.GroupDeletion{Group: auth.GrantParty{ID: id, Name: "finance-managers"}}),
			"Deleted: finance-managers (" + id + ")\n"},
		"deleted-dry": {success(auth.GroupDeletion{Group: auth.GrantParty{ID: id, Name: "finance-managers"}, DryRun: true}),
			"Deleted: finance-managers (" + id + ")\nDry run: true\n"},
		"members": {success(auth.MemberList{Members: []auth.GroupMember{member, blocked}}),
			id + " alice enabled 2026-09-11T08:30:00Z\n" + id + " bob blocked 2026-09-11T08:30:00Z\n"},
		"members-truncated": {success(auth.MemberList{Members: []auth.GroupMember{member}, Truncated: true}),
			id + " alice enabled 2026-09-11T08:30:00Z\nTruncated: list is limited to 1000 members\n"},
		"members-empty": {success(auth.MemberList{Members: []auth.GroupMember{}}), ""},
		"added":         {success(auth.MembershipMutation{Membership: membership, Added: true}), "Member: alice → finance-managers\nAdded: true\n"},
		"existing":      {success(auth.MembershipMutation{Membership: membership}), "Member: alice → finance-managers\nAdded: false\n"},
		"removed": {success(auth.MembershipRemoval{Group: membership.Group, User: membership.User, Removed: true}),
			"Member: alice → finance-managers\nRemoved: true\n"},
		"removed-none": {success(auth.MembershipRemoval{Group: membership.Group, User: membership.User}),
			"Member: alice → finance-managers\nRemoved: false\n"},
		"failure-hint": {failureWithHint(auth.GroupInUse, "The group must have no grants before deletion", groupInUseHint),
			"GROUP_IN_USE: The group must have no grants before deletion\nHint: " + groupInUseHint + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, render(&out, tc.result, "text"))
			require.Equal(t, tc.want, out.String())
			var encoded bytes.Buffer
			require.NoError(t, render(&encoded, tc.result, "json"))
			require.Equal(t, 1, decode(t, encoded.String()).SchemaVersion)
		})
	}
}

// Every refused argument exits 2 with a hint and reaches no request at all.
func TestGroupsArgumentsRejectedBeforeIO(t *testing.T) {
	cliHome(t)
	fixture, server := groupFixture(t)
	fixture.mu.Lock()
	before := fixture.groupCalls
	fixture.mu.Unlock()
	for _, args := range [][]string{
		{"groups", "get"},
		{"groups", "get", "--group", "FINANCE"},
		{"groups", "get", "--group", "ab"},
		{"groups", "get", "--group", "fin!ance"},
		{"groups", "create"},
		{"groups", "create", "--name", "Finance"},
		{"groups", "create", "--name", "abcdef12-3456-4890-abcd-ef1234567890"},
		{"groups", "create", "--name", "finance-managers", "--description", strings.Repeat("d", auth.MaxDescriptionLength+1)},
		{"groups", "update", "--group", "finance-managers"},
		{"groups", "update", "--group", "finance-managers", "--name", "FINANCE"},
		{"groups", "delete"},
		{"groups", "members", "--group", "finance-managers", "--limit", "0"},
		{"groups", "members", "--group", "finance-managers", "--limit", "1001"},
		{"groups", "list", "--limit", "0"},
		{"groups", "list", "--limit", "1001"},
		{"groups", "list", "extra"},
		{"groups", "add-member", "--group", "finance-managers"},
		{"groups", "add-member", "--group", "finance-managers", "--user", "ALICE"},
		{"groups", "remove-member", "--user", "alice"},
		{"groups", "remove-member", "--group", "finance-managers", "--user", "1alice"},
		{"groups", "get", "--group", "finance-managers", "extra"},
		{"groups", "unknown"},
		{"groups", "list", "--timeout=0"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			exit, result, output := groupsRun(t, server, args...)
			require.Equal(t, 2, exit)
			require.Equal(t, auth.InvalidArgument, result.Error.Code)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
		})
	}
	// An update with no field names the fields it accepts rather than
	// refusing without guidance.
	_, result, _ := groupsRun(t, server, "groups", "update", "--group", "finance-managers")
	require.Equal(t, "Pass --name, --description or both", result.Error.Hint)
	_, result, _ = groupsRun(t, server, "groups", "create", "--name", "Finance")
	require.Equal(t, groupNameHint, result.Error.Hint)
	_, result, _ = groupsRun(t, server, "groups", "get", "--group", "FINANCE")
	require.Equal(t, groupRefHint, result.Error.Hint)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.groupCalls, "no request may be made")
}

// A multibyte description at the bound is accepted locally, because the bound
// is a character count and not a byte count.
func TestGroupsDescriptionBoundCountsCharacters(t *testing.T) {
	cliHome(t)
	_, server := groupFixture(t)
	exit, result, _ := groupsRun(t, server, "groups", "create", "--name", "warehouse-readers",
		"--description", strings.Repeat("é", auth.MaxDescriptionLength))
	require.Equal(t, 0, exit, "%+v", result.Error)
	exit, result, _ = groupsRun(t, server, "groups", "create", "--name", "warehouse-writers",
		"--description", strings.Repeat("é", auth.MaxDescriptionLength+1))
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
}

func TestGroupsDocumentedFailures(t *testing.T) {
	cliHome(t)
	_, server := groupFixture(t)
	for _, tc := range []struct {
		args []string
		code string
		hint string
	}{
		{[]string{"groups", "get", "--group", "no-such-group"}, auth.GroupNotFound, groupNotFoundHint},
		{[]string{"groups", "members", "--group", "no-such-group"}, auth.GroupNotFound, groupNotFoundHint},
		{[]string{"groups", "create", "--name", "finance-managers"}, auth.GroupExists, "Choose a name no group holds"},
		{[]string{"groups", "add-member", "--group", "finance-managers", "--user", "nobody-here"}, auth.UserNotFound, userNotFoundHint},
		{[]string{"groups", "remove-member", "--group", "no-such-group", "--user", "alice"}, auth.GroupNotFound, groupNotFoundHint},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			exit, result, _ := groupsRun(t, server, tc.args...)
			require.Equal(t, 1, exit)
			require.Equal(t, tc.code, result.Error.Code)
			require.Equal(t, tc.hint, result.Error.Hint)
		})
	}

	// An undocumented code on a group route is not a result the CLI renders.
	for _, tc := range []struct {
		route apiCall
		code  string
	}{
		{apiCall{http.MethodGet, auth.GroupsPath, "", http.StatusOK}, auth.GroupNotFound},
		{apiCall{http.MethodGet, auth.GroupsPath, "", http.StatusOK}, auth.GroupInUse},
		{apiCall{http.MethodPost, auth.GroupsPath, "", http.StatusCreated}, auth.GroupInUse},
		{apiCall{http.MethodPost, groupPath(auth.GroupDeletePath, "finance-managers"), "", http.StatusOK}, auth.GroupExists},
		{apiCall{http.MethodPost, groupPath(auth.GroupMemberAddPath, "finance-managers"), "", http.StatusCreated}, auth.GroupInUse},
		{apiCall{http.MethodGet, groupPath(auth.GroupPath, "finance-managers"), "", http.StatusOK}, auth.ConnectionNotFound},
	} {
		hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			status, safe, _ := auth.LookupFailure(tc.code)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
		}))
		var list auth.GroupList
		failed := (authTransport{hostile.URL, time.Second}).send(t.Context(), tc.route, testToken(), nil, &list)
		hostile.Close()
		require.NotNil(t, failed)
		require.Equal(t, "INVALID_RESPONSE", failed.Error.Code, tc.code)
	}
}

// A group body that is not the documented shape is refused rather than
// rendered: a bad name, a negative count, a bad timestamp or an unknown member.
func TestGroupsTransportStrictResponses(t *testing.T) {
	valid := `{"group":{"id":"0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11","name":"finance-managers",` +
		`"description":"Finance managers","createdAt":"2026-09-11T08:30:00Z","updatedAt":"2026-09-11T08:30:00Z",` +
		`"members":3,"grants":2},"dryRun":false}`
	for name, body := range map[string]string{
		"valid":            valid,
		"unknown member":   strings.Replace(valid, `"dryRun":false`, `"dryRun":false,"extra":1`, 1),
		"uppercase name":   strings.Replace(valid, `"finance-managers"`, `"FINANCE"`, 1),
		"uuid-shaped name": strings.Replace(valid, `"finance-managers"`, `"0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11"`, 1),
		"bad id":           strings.Replace(valid, `"id":"0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11"`, `"id":"nope"`, 1),
		"negative count":   strings.Replace(valid, `"members":3`, `"members":-1`, 1),
		"offset time":      strings.Replace(valid, `"createdAt":"2026-09-11T08:30:00Z"`, `"createdAt":"2026-09-11T08:30:00+02:00"`, 1),
		"zero time":        strings.Replace(valid, `"updatedAt":"2026-09-11T08:30:00Z"`, `"updatedAt":"0001-01-01T00:00:00Z"`, 1),
		"control text":     strings.Replace(valid, `"Finance managers"`, "\"Finance\\u0007managers\"", 1),
		"case alias":       strings.Replace(valid, `"members"`, `"Members"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			var mutation auth.GroupMutation
			route := apiCall{http.MethodPost, auth.GroupsPath, "", http.StatusCreated}
			failed := (authTransport{server.URL, time.Second}).send(t.Context(), route, testToken(), &auth.GroupRequest{}, &mutation)
			if name == "valid" {
				require.Nil(t, failed)
				require.Equal(t, "finance-managers", mutation.Group.Name)
				return
			}
			require.NotNil(t, failed)
			require.Equal(t, "INVALID_RESPONSE", failed.Error.Code)
		})
	}
}

// A member's session is refused by the server on every group command, reads
// included, and nothing is mutated.
func TestGroupsAreAdministratorOnly(t *testing.T) {
	cliHome(t)
	fixture, server := groupFixture(t)
	fixture.mu.Lock()
	memberID := fixture.users[1].ID
	token := testToken()
	fixture.sessions[token] = auth.Identity{
		User:      auth.User{ID: memberID, Username: "alice", Role: auth.Member},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	}
	before := fixture.groupMutations
	fixture.mu.Unlock()
	runAs(t, server, token, auth.Identity{
		User:      auth.User{ID: memberID, Username: "alice", Role: auth.Member},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	})
	for _, args := range [][]string{
		{"groups", "list"},
		{"groups", "get", "--group", "finance-managers"},
		{"groups", "create", "--name", "warehouse-readers"},
		{"groups", "update", "--group", "finance-managers", "--description", "x"},
		{"groups", "delete", "--group", "finance-managers"},
		{"groups", "members", "--group", "finance-managers"},
		{"groups", "add-member", "--group", "finance-managers", "--user", "cli-test"},
		{"groups", "remove-member", "--group", "finance-managers", "--user", "alice"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			exit, result, _ := groupsRun(t, server, args...)
			require.Equal(t, 1, exit)
			require.Equal(t, auth.Forbidden, result.Error.Code)
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, before, fixture.groupMutations, "no member request may mutate")
}

func TestGroupsRequireCachedSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t, testToken())
	for _, args := range [][]string{
		{"groups", "list"},
		{"groups", "get", "--group", "finance-managers"},
		{"groups", "create", "--name", "finance-managers"},
		{"groups", "add-member", "--group", "finance-managers", "--user", "alice"},
	} {
		exit, result, _ := groupsRun(t, server, args...)
		require.Equal(t, 1, exit)
		require.Equal(t, auth.Unauthenticated, result.Error.Code)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.groupCalls)
}

// The two group listings are read under the listing response limit, not the
// general one: a legitimate listing above 64 KiB must not be refused.
func TestGroupListingsAreReadUnderTheListingLimit(t *testing.T) {
	require.Equal(t, auth.MaxListingBody, responseLimit(http.MethodGet, auth.GroupsPath))
	require.Equal(t, auth.MaxListingBody, responseLimit(http.MethodGet, groupPath(auth.GroupMembersPath, "finance-managers")))
	require.Equal(t, auth.MaxListingBody, responseLimit(http.MethodGet, auth.GrantsEffectivePath))

	cliHome(t)
	fixture, server := groupFixture(t)
	fixture.mu.Lock()
	for index := 0; index < 60; index++ {
		fixture.groups = append(fixture.groups, auth.Group{
			ID: testUserID(), Name: "g" + strconv.Itoa(index) + "-" + strings.Repeat("z", 58),
			Description: strings.Repeat("d", auth.MaxDescriptionLength),
			CreatedAt:   time.Now().UTC().Truncate(time.Second), UpdatedAt: time.Now().UTC().Truncate(time.Second),
		})
	}
	fixture.mu.Unlock()
	exit, result, output := groupsRun(t, server, "groups", "list")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.Greater(t, len(output), auth.MaxResponseBody, "the listing is past the general limit")
	require.Len(t, result.Data.(map[string]any)["groups"], 61)
}
