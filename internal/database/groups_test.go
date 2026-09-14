package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file is fixture setup, fault injection, or an independent
// assertion against persisted state. Application operations use LocalAuth.

func createGroup(t *testing.T, s *LocalAuth, admin auth.Session, name, description string) auth.Group {
	t.Helper()
	result, err := s.CreateGroup(t.Context(), admin, auth.GroupRequest{Name: name, Description: description}, false)
	require.NoError(t, err)
	require.False(t, result.DryRun)
	return result.Group
}

// signedInAdministrator is a second administrator with their own session, which
// concurrency tests need: two operations by one actor serialize on that
// actor's own row before they ever reach the rows under test.
func signedInAdministrator(t *testing.T, s *LocalAuth, admin auth.Session, username string) auth.Session {
	t.Helper()
	record, input := createMember(t, s, admin, username)
	_, err := s.SetRole(t.Context(), admin, record.ID, auth.Admin)
	require.NoError(t, err)
	return session(t, s, login(t, s, input), auth.CLI)
}

func groupNames(list auth.GroupList) []string {
	names := make([]string, 0, len(list.Groups))
	for _, record := range list.Groups {
		names = append(names, record.Name)
	}
	return names
}

func memberUsernames(list auth.MemberList) []string {
	names := make([]string, 0, len(list.Members))
	for _, record := range list.Members {
		names = append(names, record.Username)
	}
	return names
}

// groupOperations is every service call, keyed by its operation name, so
// denial and dry-run tests can cover them uniformly.
func groupOperations(ctx context.Context, s *LocalAuth, actor auth.Session,
	groupRef, userRef string, dryRun bool) map[string]func() error {
	return map[string]func() error{
		"groups.list":    func() error { _, err := s.ListGroups(ctx, actor, 0); return err },
		"groups.get":     func() error { _, err := s.GetGroup(ctx, actor, groupRef); return err },
		"groups.members": func() error { _, err := s.ListMembers(ctx, actor, groupRef, 0); return err },
		"groups.create": func() error {
			_, err := s.CreateGroup(ctx, actor, auth.GroupRequest{Name: "new-group"}, dryRun)
			return err
		},
		"groups.update": func() error {
			renamed := "renamed-group"
			_, err := s.UpdateGroup(ctx, actor, groupRef, auth.GroupUpdate{Name: &renamed}, dryRun)
			return err
		},
		"groups.delete":        func() error { _, err := s.DeleteGroup(ctx, actor, groupRef, dryRun); return err },
		"groups.add-member":    func() error { _, err := s.AddMember(ctx, actor, groupRef, userRef, dryRun); return err },
		"groups.remove-member": func() error { _, err := s.RemoveMember(ctx, actor, groupRef, userRef, dryRun); return err },
	}
}

func TestCreateGroupReadsBackByEitherReferenceAndBoundsTheListing(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)

	created := createGroup(t, s, admin, "finance-managers", "Finance managers")
	require.Equal(t, "finance-managers", created.Name)
	require.Equal(t, "Finance managers", created.Description)
	require.Zero(t, created.Members)
	require.Zero(t, created.Grants)
	require.True(t, auth.ValidUserID(created.ID), "groups carry a random stable UUID")
	// A fresh group has never been updated; both stamps come from the same
	// statement, which clock_timestamp() advances inside, so they are the same
	// instant rather than the same value.
	require.WithinDuration(t, created.CreatedAt, created.UpdatedAt, time.Millisecond)
	require.False(t, created.UpdatedAt.Before(created.CreatedAt))
	require.Equal(t, time.UTC, created.CreatedAt.Location())
	require.WithinDuration(t, time.Now(), created.CreatedAt, 5*time.Second)
	require.Equal(t, 1, countRows(t, pool, "groups"))

	byName, err := s.GetGroup(t.Context(), admin, "finance-managers")
	require.NoError(t, err)
	byID, err := s.GetGroup(t.Context(), admin, created.ID)
	require.NoError(t, err)
	require.Equal(t, created, byName)
	require.Equal(t, created, byID)

	createGroup(t, s, admin, "platform", "")
	createGroup(t, s, admin, "sre", "")
	list, err := s.ListGroups(t.Context(), admin, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"finance-managers", "platform", "sre"}, groupNames(list))
	require.False(t, list.Truncated)
	bounded, err := s.ListGroups(t.Context(), admin, 2)
	require.NoError(t, err)
	require.Len(t, bounded.Groups, 2)
	require.True(t, bounded.Truncated)
	over, err := s.ListGroups(t.Context(), admin, auth.MaxGroupListing*10)
	require.NoError(t, err)
	require.Len(t, over.Groups, 3)
	require.False(t, over.Truncated)

	// An unknown or unusable reference discloses nothing beyond not-found.
	for _, ref := range []string{"missing-group", randomTestID(t), "Not A Ref", ""} {
		_, err := s.GetGroup(t.Context(), admin, ref)
		code(t, err, auth.GroupNotFound, ref)
		require.Equal(t, hintGroupNotFound, hintOf(t, err), ref)
		_, err = s.ListMembers(t.Context(), admin, ref, 0)
		code(t, err, auth.GroupNotFound, ref)
	}
	require.Equal(t, 3, countRows(t, pool, "groups"), "reads change nothing")
}

func TestCreateGroupRefusesDuplicateAndMalformedNames(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	createGroup(t, s, admin, "finance-managers", "")

	repeat, err := s.CreateGroup(t.Context(), admin,
		auth.GroupRequest{Name: "finance-managers", Description: "second"}, false)
	code(t, err, auth.GroupExists)
	require.Equal(t, hintGroupExists, hintOf(t, err))
	require.Zero(t, repeat.Group.ID)

	for name, value := range map[string]string{
		"uuid shaped": randomTestID(t),
		"uppercase":   "Finance",
		"too short":   "ab",
		"leading dot": ".finance",
		"empty":       "",
		"spaces":      "finance managers",
	} {
		_, err := s.CreateGroup(t.Context(), admin, auth.GroupRequest{Name: value}, false)
		code(t, err, auth.InvalidArgument, name)
		require.Equal(t, hintGroupName, hintOf(t, err), name)
	}

	// The bound counts characters, not bytes, exactly as the column does.
	wide := createGroup(t, s, admin, "wide-description", strings.Repeat("é", auth.MaxDescriptionLength))
	require.Len(t, []rune(wide.Description), auth.MaxDescriptionLength)
	for name, description := range map[string]string{
		"one character over": strings.Repeat("é", auth.MaxDescriptionLength+1),
		"control character":  "line\nbreak",
	} {
		_, err := s.CreateGroup(t.Context(), admin,
			auth.GroupRequest{Name: "over-long", Description: description}, false)
		code(t, err, auth.InvalidArgument, name)
		require.Equal(t, hintGroupDescription, hintOf(t, err), name)
	}
	require.Equal(t, 2, countRows(t, pool, "groups"), "no refused creation wrote a row")
}

func TestUpdateGroupChangesSuppliedFieldsAndKeepsAccessOnRename(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	finance := createGroup(t, s, admin, "finance-managers", "Finance managers")
	other := createGroup(t, s, admin, "platform", "Platform")
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	_, err := s.AddMember(t.Context(), admin, finance.ID, "alice", false)
	require.NoError(t, err)
	_, err = s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: "payments-prod"}, false)
	require.NoError(t, err)

	description := "Finance leads"
	updated, err := s.UpdateGroup(t.Context(), admin, "finance-managers",
		auth.GroupUpdate{Description: &description}, false)
	require.NoError(t, err)
	require.Equal(t, description, updated.Group.Description)
	require.Equal(t, finance.Name, updated.Group.Name, "an absent field is untouched")
	require.Equal(t, 1, updated.Group.Members)
	require.Equal(t, 1, updated.Group.Grants)
	require.True(t, updated.Group.UpdatedAt.After(finance.UpdatedAt))
	require.Equal(t, finance.CreatedAt, updated.Group.CreatedAt)

	// A no-op update leaves updated_at where it was.
	same, err := s.UpdateGroup(t.Context(), admin, finance.ID, auth.GroupUpdate{Description: &description}, false)
	require.NoError(t, err)
	require.Equal(t, updated.Group.UpdatedAt, same.Group.UpdatedAt)

	cleared := ""
	empty, err := s.UpdateGroup(t.Context(), admin, finance.ID, auth.GroupUpdate{Description: &cleared}, false)
	require.NoError(t, err)
	require.Empty(t, empty.Group.Description)

	// A rename moves the name, never the access: both reference the UUID.
	renamed := "finance-leads"
	moved, err := s.UpdateGroup(t.Context(), admin, finance.ID, auth.GroupUpdate{Name: &renamed}, false)
	require.NoError(t, err)
	require.Equal(t, renamed, moved.Group.Name)
	require.Equal(t, finance.ID, moved.Group.ID)
	require.Equal(t, 1, moved.Group.Members)
	require.Equal(t, 1, moved.Group.Grants)
	members, err := s.ListMembers(t.Context(), admin, renamed, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, memberUsernames(members))
	granted, err := s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"payments-prod"}, summaryNames(granted))
	listed, err := s.ListGrants(t.Context(), admin, auth.GrantFilter{})
	require.NoError(t, err)
	require.Equal(t, []string{renamed}, grantUsernames(listed))

	// A colliding rename changes nothing at all, updatedAt included.
	before, err := s.GetGroup(t.Context(), admin, finance.ID)
	require.NoError(t, err)
	taken := other.Name
	_, err = s.UpdateGroup(t.Context(), admin, finance.ID, auth.GroupUpdate{Name: &taken}, false)
	code(t, err, auth.GroupExists)
	require.Equal(t, hintGroupExists, hintOf(t, err))
	after, err := s.GetGroup(t.Context(), admin, finance.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)

	// Validation runs before the transaction and names the failing field.
	for name, update := range map[string]auth.GroupUpdate{
		"no field":          {},
		"uuid shaped name":  {Name: ref(randomTestID(t))},
		"malformed name":    {Name: ref("Finance")},
		"over-long text":    {Description: ref(strings.Repeat("é", auth.MaxDescriptionLength+1))},
		"control character": {Description: ref("line\nbreak")},
	} {
		_, err := s.UpdateGroup(t.Context(), admin, finance.ID, update, false)
		code(t, err, auth.InvalidArgument, name)
	}
	unchanged, err := s.GetGroup(t.Context(), admin, finance.ID)
	require.NoError(t, err)
	require.Equal(t, before, unchanged)
	_, err = s.UpdateGroup(t.Context(), admin, "missing-group", auth.GroupUpdate{Name: &renamed}, false)
	code(t, err, auth.GroupNotFound)
	require.Equal(t, 2, countRows(t, pool, "groups"))
	require.Equal(t, 1, countRows(t, pool, "grants"))
	require.Equal(t, alice.ID, members.Members[0].ID)
}

func TestDeleteGroupIsGuardedByItsGrantsAndTakesMembershipsWithIt(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	for _, name := range []string{"payments-prod", "metrics-prod"} {
		createConnection(t, s, admin, connectionRequest(name))
	}
	finance := createGroup(t, s, admin, "finance-managers", "Finance managers")
	for _, username := range []string{"alice", "bob"} {
		createMember(t, s, admin, username)
		_, err := s.AddMember(t.Context(), admin, "finance-managers", username, false)
		require.NoError(t, err)
	}
	for _, connection := range []string{"payments-prod", "metrics-prod"} {
		_, err := s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: connection}, false)
		require.NoError(t, err)
	}

	// The guard counts what still stands in the way, on a dry run as well:
	// asking is exactly how a caller learns how much revoking is left.
	for _, remaining := range []int64{2, 1} {
		for _, dryRun := range []bool{true, false} {
			_, err := s.DeleteGroup(t.Context(), admin, "finance-managers", dryRun)
			code(t, err, auth.GroupInUse)
			require.Equal(t, hintRemainingGrants(remaining), hintOf(t, err))
		}
		revoked, err := s.RevokeGrant(t.Context(), admin, auth.GrantRequest{
			Group: finance.ID, Connection: []string{"payments-prod", "metrics-prod"}[2-remaining],
		}, false)
		require.NoError(t, err)
		require.True(t, revoked.Revoked)
	}
	require.Contains(t, hintRemainingGrants(2), "2 grants")
	require.Equal(t, 2, countRows(t, pool, "group_members"), "a refused delete removed nothing")

	deletion, err := s.DeleteGroup(t.Context(), admin, "finance-managers", false)
	require.NoError(t, err)
	require.Equal(t, auth.GrantParty{ID: finance.ID, Name: "finance-managers"}, deletion.Group)
	require.False(t, deletion.DryRun)
	require.Zero(t, countRows(t, pool, "groups"))
	require.Zero(t, countRows(t, pool, "group_members"), "memberships follow the group")
	require.Equal(t, 3, countRows(t, pool, "users"), "members outlive the group")

	// A group recreated with the same name inherits nothing.
	recreated := createGroup(t, s, admin, "finance-managers", "")
	require.NotEqual(t, finance.ID, recreated.ID)
	require.Zero(t, recreated.Members)
	require.Zero(t, recreated.Grants)
	members, err := s.ListMembers(t.Context(), admin, "finance-managers", 0)
	require.NoError(t, err)
	require.Empty(t, members.Members)

	for _, ref := range []string{"missing-group", randomTestID(t), "Not A Ref"} {
		_, err := s.DeleteGroup(t.Context(), admin, ref, false)
		code(t, err, auth.GroupNotFound, ref)
		require.Equal(t, hintGroupNotFound, hintOf(t, err), ref)
	}
	require.Equal(t, 1, countRows(t, pool, "groups"))
}

func TestMembershipIsIdempotentAndSurvivesBlocking(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	finance := createGroup(t, s, admin, "finance-managers", "")
	alice, _ := createMember(t, s, admin, "alice")
	bob, _ := createMember(t, s, admin, "bob")

	added, err := s.AddMember(t.Context(), admin, "finance-managers", "alice", false)
	require.NoError(t, err)
	require.True(t, added.Added)
	require.False(t, added.DryRun)
	require.Equal(t, auth.GrantParty{ID: finance.ID, Name: "finance-managers"}, added.Membership.Group)
	require.Equal(t, auth.GrantParty{ID: alice.ID, Name: "alice"}, added.Membership.User)
	require.Equal(t, auth.GrantParty{ID: admin.User.ID, Name: admin.User.Username}, added.Membership.CreatedBy)
	require.Equal(t, time.UTC, added.Membership.CreatedAt.Location())
	require.WithinDuration(t, time.Now(), added.Membership.CreatedAt, 5*time.Second)

	// A repeated add returns the membership that exists and leaves its row
	// alone: the time and the adding administrator never move.
	repeat, err := s.AddMember(t.Context(), admin, finance.ID, alice.ID, false)
	require.NoError(t, err)
	require.False(t, repeat.Added)
	require.Equal(t, added.Membership, repeat.Membership)
	require.Equal(t, 1, countRows(t, pool, "group_members"))

	// A blocked user may be added; the membership takes effect once the
	// account can sign in again, exactly as a grant does.
	blocked, err := s.SetUserDisabled(t.Context(), admin, "bob", true)
	require.NoError(t, err)
	require.True(t, blocked.User.Disabled)
	addedBlocked, err := s.AddMember(t.Context(), admin, "finance-managers", "bob", false)
	require.NoError(t, err)
	require.True(t, addedBlocked.Added)
	members, err := s.ListMembers(t.Context(), admin, "finance-managers", 0)
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "bob"}, memberUsernames(members))
	require.False(t, members.Truncated)
	require.True(t, members.Members[1].Disabled)
	require.Equal(t, auth.Member, members.Members[0].Role)
	require.Equal(t, added.Membership.CreatedAt, members.Members[0].AddedAt)
	require.Equal(t, auth.GrantParty{ID: admin.User.ID, Name: admin.User.Username}, members.Members[0].AddedBy)
	require.Equal(t, alice.ID, members.Members[0].ID)
	bounded, err := s.ListMembers(t.Context(), admin, "finance-managers", 1)
	require.NoError(t, err)
	require.Len(t, bounded.Members, 1)
	require.True(t, bounded.Truncated)
	group, err := s.GetGroup(t.Context(), admin, "finance-managers")
	require.NoError(t, err)
	require.Equal(t, 2, group.Members)

	// Blocking and unblocking a member never touches the membership.
	_, err = s.SetUserDisabled(t.Context(), admin, "alice", true)
	require.NoError(t, err)
	require.Equal(t, 2, countRows(t, pool, "group_members"))
	_, err = s.SetUserDisabled(t.Context(), admin, "alice", false)
	require.NoError(t, err)
	_, err = s.SetUserDisabled(t.Context(), admin, "bob", false)
	require.NoError(t, err)
	still, err := s.ListMembers(t.Context(), admin, finance.ID, 0)
	require.NoError(t, err)
	require.Equal(t, memberUsernames(members), memberUsernames(still))
	require.Equal(t, members.Members[0], still.Members[0])
	require.Equal(t, members.Members[1].AddedAt, still.Members[1].AddedAt, "the membership row never moved")
	require.False(t, still.Members[1].Disabled, "unblocking changed the account, not the membership")

	removed, err := s.RemoveMember(t.Context(), admin, "finance-managers", "bob", false)
	require.NoError(t, err)
	require.True(t, removed.Removed)
	require.Equal(t, auth.GrantParty{ID: bob.ID, Name: "bob"}, removed.User)
	require.Equal(t, auth.GrantParty{ID: finance.ID, Name: "finance-managers"}, removed.Group)
	again, err := s.RemoveMember(t.Context(), admin, finance.ID, bob.ID, false)
	require.NoError(t, err)
	require.False(t, again.Removed)
	require.Equal(t, 1, countRows(t, pool, "group_members"))

	// An unknown group or user is refused before anything is written.
	for name, call := range map[string]func() error{
		"unknown group": func() error {
			_, err := s.AddMember(t.Context(), admin, "missing-group", "alice", false)
			return err
		},
		"unknown group on remove": func() error {
			_, err := s.RemoveMember(t.Context(), admin, randomTestID(t), "alice", false)
			return err
		},
	} {
		code(t, call(), auth.GroupNotFound, name)
	}
	for name, call := range map[string]func() error{
		"unknown user": func() error {
			_, err := s.AddMember(t.Context(), admin, "finance-managers", "nobody-here", false)
			return err
		},
		"malformed user": func() error {
			_, err := s.AddMember(t.Context(), admin, "finance-managers", "Not A Ref", false)
			return err
		},
		"unknown user on remove": func() error {
			_, err := s.RemoveMember(t.Context(), admin, "finance-managers", randomTestID(t), false)
			return err
		},
	} {
		err := call()
		code(t, err, auth.UserNotFound, name)
		require.Equal(t, hintUserNotFound, hintOf(t, err), name)
	}
	require.Equal(t, 1, countRows(t, pool, "group_members"))
}

func TestGroupOperationsAreAdministratorOnlyAndRefuseRevokedSessions(t *testing.T) {
	pool, s, admin, input := adminFixture(t)
	createGroup(t, s, admin, "finance-managers", "")
	_, aliceSession := signedInMember(t, s, admin, "alice")
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	groups, memberships := countRows(t, pool, "groups"), countRows(t, pool, "group_members")

	for _, dryRun := range []bool{false, true} {
		for action, operation := range groupOperations(t.Context(), s, aliceSession, "finance-managers", "alice", dryRun) {
			code(t, operation(), auth.Forbidden, action)
		}
		for action, operation := range groupOperations(t.Context(), s, revoked, "finance-managers", "alice", dryRun) {
			code(t, operation(), auth.Unauthenticated, action)
		}
		for action, operation := range groupOperations(t.Context(), s, auth.Session{}, "finance-managers", "alice", dryRun) {
			code(t, operation(), auth.Unauthenticated, action)
		}
	}
	require.Equal(t, groups, countRows(t, pool, "groups"), "no denial wrote a group")
	require.Equal(t, memberships, countRows(t, pool, "group_members"))
}

func TestGroupDryRunsReportTheOutcomeAndLeaveNoTrace(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	finance := createGroup(t, s, admin, "finance-managers", "Finance managers")
	createGroup(t, s, admin, "platform", "")
	createMember(t, s, admin, "alice")
	_, err := s.AddMember(t.Context(), admin, "finance-managers", "alice", false)
	require.NoError(t, err)
	_, err = s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: "payments-prod"}, false)
	require.NoError(t, err)
	groups, memberships := countRows(t, pool, "groups"), countRows(t, pool, "group_members")
	before, err := s.GetGroup(t.Context(), admin, finance.ID)
	require.NoError(t, err)

	created, err := s.CreateGroup(t.Context(), admin, auth.GroupRequest{Name: "new-group", Description: "asked"}, true)
	require.NoError(t, err)
	require.True(t, created.DryRun)
	require.Equal(t, "new-group", created.Group.Name)
	renamed := "finance-leads"
	updated, err := s.UpdateGroup(t.Context(), admin, finance.ID, auth.GroupUpdate{Name: &renamed}, true)
	require.NoError(t, err)
	require.True(t, updated.DryRun)
	require.Equal(t, renamed, updated.Group.Name)
	require.Equal(t, 1, updated.Group.Members)

	// Membership answers the outcome it would have had, both ways round.
	removal, err := s.RemoveMember(t.Context(), admin, "finance-managers", "alice", true)
	require.NoError(t, err)
	require.True(t, removal.Removed)
	require.True(t, removal.DryRun)
	addition, err := s.AddMember(t.Context(), admin, "platform", "alice", true)
	require.NoError(t, err)
	require.True(t, addition.Added)
	require.True(t, addition.DryRun)
	existing, err := s.AddMember(t.Context(), admin, "finance-managers", "alice", true)
	require.NoError(t, err)
	require.False(t, existing.Added)
	absent, err := s.RemoveMember(t.Context(), admin, "platform", "alice", true)
	require.NoError(t, err)
	require.False(t, absent.Removed)

	// Guard failures and denials are reported by a dry run too, with the same
	// counted hint the real attempt would carry.
	_, err = s.DeleteGroup(t.Context(), admin, "finance-managers", true)
	code(t, err, auth.GroupInUse)
	require.Equal(t, hintRemainingGrants(1), hintOf(t, err))
	taken := "platform"
	_, err = s.UpdateGroup(t.Context(), admin, finance.ID, auth.GroupUpdate{Name: &taken}, true)
	code(t, err, auth.GroupExists)
	_, err = s.CreateGroup(t.Context(), admin, auth.GroupRequest{Name: "platform"}, true)
	code(t, err, auth.GroupExists)
	_, err = s.AddMember(t.Context(), admin, "missing-group", "alice", true)
	code(t, err, auth.GroupNotFound)
	deleted, err := s.DeleteGroup(t.Context(), admin, "platform", true)
	require.NoError(t, err)
	require.True(t, deleted.DryRun)
	require.Equal(t, "platform", deleted.Group.Name)

	require.Equal(t, groups, countRows(t, pool, "groups"))
	require.Equal(t, memberships, countRows(t, pool, "group_members"))
	after, err := s.GetGroup(t.Context(), admin, finance.ID)
	require.NoError(t, err)
	require.Equal(t, before, after, "a dry run leaves even updated_at alone")
}

func TestGroupMutationsSerializeOnTheirOwnKeyAndOnTheGroupAndUserRows(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	alice, aliceSession := signedInMember(t, s, admin, "alice")
	other := signedInAdministrator(t, s, admin, "second-admin")
	createGroup(t, s, admin, "finance-managers", "")

	// A held group key times the mutation out rather than queueing forever,
	// and no read and no other mutation family takes that key.
	blocker, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback(context.Background()) }()
	_, err = blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, groupMutationLock)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	start := time.Now()
	_, err = s.CreateGroup(bounded, admin, auth.GroupRequest{Name: "blocked-group"}, false)
	cancel()
	code(t, err, auth.ServiceUnavailable)
	require.Less(t, time.Since(start), 5*time.Second)
	list, err := s.ListGroups(t.Context(), admin, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"finance-managers"}, groupNames(list))
	_, err = s.GetGroup(t.Context(), admin, "finance-managers")
	require.NoError(t, err)
	_, err = s.ListMembers(t.Context(), admin, "finance-managers", 0)
	require.NoError(t, err)
	// The two advisory keys do not serialize each other.
	_, err = s.CreateGrant(t.Context(), admin, auth.GrantRequest{Group: "finance-managers", Connection: payments.ID}, false)
	require.NoError(t, err)
	require.NoError(t, blocker.Rollback(t.Context()))
	require.Equal(t, 1, countRows(t, pool, "groups"), "a timed-out mutation created nothing")

	// A membership change waits on the user row, which is what a block of the
	// same user holds: the two serialize instead of racing.
	holder, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(context.Background()) }()
	_, err = holder.Exec(t.Context(), `SELECT id FROM users WHERE id=$1 FOR UPDATE`, alice.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.AddMember(t.Context(), other, "finance-managers", "alice", false)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '-- name: LockMutationUsers :exec%'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting)
		return err == nil && waiting > 0
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, holder.Rollback(t.Context()))
	require.NoError(t, <-done)
	require.Equal(t, 1, countRows(t, pool, "group_members"))

	// Run it for real: whichever wins, the membership and the block both
	// apply, because neither observes a half-applied row of the other.
	adding, blocking := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := s.AddMember(t.Context(), other, "finance-managers", alice.ID, false)
		adding <- err
	}()
	go func() {
		_, err := s.SetUserDisabled(t.Context(), admin, alice.ID, true)
		blocking <- err
	}()
	require.NoError(t, <-adding)
	require.NoError(t, <-blocking)
	role, disabled := userState(t, pool, alice.ID)
	require.Equal(t, string(auth.Member), role)
	require.True(t, disabled)
	require.Equal(t, 1, countRows(t, pool, "group_members"))
	_, err = s.ListGrantedConnections(t.Context(), aliceSession, nil, 0)
	code(t, err, auth.Unauthenticated, "blocking revoked the member's sessions")
}

// A group delete and a grant to that group are serialized by the group row,
// not by an advisory key: the two families take different keys and never both.
// Whichever commits first decides, and the loser is refused rather than
// leaving a grant that outlives its group.
func TestGroupDeleteAndGroupGrantSerializeInBothOrders(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	payments := createConnection(t, s, admin, connectionRequest("payments-prod"))
	other := signedInAdministrator(t, s, admin, "second-admin")

	for _, deleteFirst := range []bool{false, true} {
		createGroup(t, s, admin, "finance-managers", "")
		granting, deleting := make(chan error, 1), make(chan error, 1)
		grant := func() {
			_, err := s.CreateGrant(t.Context(), other,
				auth.GrantRequest{Group: "finance-managers", Connection: payments.ID}, false)
			granting <- err
		}
		remove := func() {
			_, err := s.DeleteGroup(t.Context(), admin, "finance-managers", false)
			deleting <- err
		}
		if deleteFirst {
			go remove()
			go grant()
		} else {
			go grant()
			go remove()
		}
		grantErr, deleteErr := <-granting, <-deleting
		if deleteErr == nil {
			code(t, grantErr, auth.GroupNotFound)
			require.Equal(t, hintGroupNotFound, hintOf(t, grantErr))
			require.Zero(t, countRows(t, pool, "groups"))
			require.Zero(t, countRows(t, pool, "grants"), "no grant outlived its group")
		} else {
			require.NoError(t, grantErr)
			code(t, deleteErr, auth.GroupInUse)
			require.Equal(t, hintRemainingGrants(1), hintOf(t, deleteErr))
			require.Equal(t, 1, countRows(t, pool, "groups"))
			require.Equal(t, 1, countRows(t, pool, "grants"))
			_, err := s.RevokeGrant(t.Context(), admin,
				auth.GrantRequest{Group: "finance-managers", Connection: payments.ID}, false)
			require.NoError(t, err)
			_, err = s.DeleteGroup(t.Context(), admin, "finance-managers", false)
			require.NoError(t, err)
		}
		require.Zero(t, countRows(t, pool, "groups"))
	}
	require.Equal(t, 1, countRows(t, pool, "connections"))
}
