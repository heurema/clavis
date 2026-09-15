package auth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/heurema/clavis/internal/auth"
)

func TestGrantContracts(t *testing.T) {
	status, response := auth.FailureFor(&auth.Error{Code: auth.ConnectionDisabled, Hint: "run clavis connections enable"})
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "CONNECTION_DISABLED", response.Error.Code)
	require.Equal(t, "The connection is disabled", response.Error.Message)
	require.Equal(t, "run clavis connections enable", response.Error.Hint)

	grant := auth.Grant{
		Recipient:  auth.Recipient{Kind: auth.RecipientUser, ID: "u", Name: "alice"},
		Connection: auth.GrantParty{ID: "c", Name: "payments-prod-reporting"},
		CreatedAt:  time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC),
		CreatedBy:  auth.GrantParty{ID: "a", Name: "admin"},
	}
	encoded, err := json.Marshal(auth.GrantMutation{Grant: grant, Created: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"grant":{"recipient":{"kind":"user","id":"u","name":"alice"},"connection":{"id":"c","name":"payments-prod-reporting"},"createdAt":"2026-09-12T09:00:00Z","createdBy":{"id":"a","name":"admin"}},"created":true,"dryRun":false}`, string(encoded))
	group := grant
	group.Recipient = auth.Recipient{Kind: auth.RecipientGroup, ID: "g", Name: "finance-managers"}
	encoded, err = json.Marshal(auth.GrantMutation{Grant: group, Created: true})
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"recipient":{"kind":"group","id":"g","name":"finance-managers"}`)
	encoded, err = json.Marshal(auth.GrantRevocation{Recipient: grant.Recipient, Connection: grant.Connection, Revoked: false, DryRun: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"recipient":{"kind":"user","id":"u","name":"alice"},"connection":{"id":"c","name":"payments-prod-reporting"},"revoked":false,"dryRun":true}`, string(encoded))
	encoded, err = json.Marshal(auth.GrantList{Grants: []auth.Grant{}, Truncated: false})
	require.NoError(t, err)
	require.JSONEq(t, `{"grants":[],"truncated":false}`, string(encoded))
	require.Equal(t, "/api/admin/grants", auth.GrantsPath)
	require.Equal(t, "/api/admin/grants/revoke", auth.GrantRevokePath)
	require.Equal(t, "/api/admin/grants/effective", auth.GrantsEffectivePath)
	require.Equal(t, 1000, auth.MaxGrantListing)
	require.Equal(t, 1000, auth.MaxAccessListing)
}

// The recipient rule is the one thing neither the adapter nor the service can
// repair: a request that names both recipients or neither has no recipient.
func TestGrantRequestNamesExactlyOneRecipient(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request auth.GrantRequest
		kind    auth.RecipientKind
		ref     string
	}{
		{"user by name", auth.GrantRequest{User: "alice", Connection: "c"}, auth.RecipientUser, "alice"},
		{"user by id", auth.GrantRequest{User: "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba", Connection: "c"},
			auth.RecipientUser, "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"},
		{"group by name", auth.GrantRequest{Group: "finance-managers", Connection: "c"}, auth.RecipientGroup, "finance-managers"},
		{"group by id", auth.GrantRequest{Group: "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba", Connection: "c"},
			auth.RecipientGroup, "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, ref, ok := tc.request.RecipientRef()
			require.True(t, ok)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, tc.ref, ref)
		})
	}
	// Only both-or-neither is an argument failure; an unusable reference is
	// still the not-found the resolver answers with, per namespace.
	for _, request := range []auth.GrantRequest{
		{Connection: "c"},
		{User: "alice", Group: "finance-managers", Connection: "c"},
	} {
		_, _, ok := request.RecipientRef()
		require.False(t, ok, "%+v", request)
	}
	for _, bad := range []string{"ALICE", "ab", "a b"} {
		kind, recipientRef, ok := auth.GrantRequest{User: bad, Connection: "c"}.RecipientRef()
		require.True(t, ok)
		require.False(t, auth.ValidRecipientRef(kind, recipientRef), bad)
		kind, recipientRef, ok = auth.GrantRequest{Group: bad, Connection: "c"}.RecipientRef()
		require.True(t, ok)
		require.False(t, auth.ValidRecipientRef(kind, recipientRef), bad)
	}
	require.True(t, auth.ValidRecipientRef(auth.RecipientUser, "alice"))
	require.True(t, auth.ValidRecipientRef(auth.RecipientGroup, "finance-managers"))
	require.Contains(t, auth.RecipientHint, "exactly one")
}

// The three group codes join the wire allowlist with their documented statuses;
// an unknown code is still refused rather than defaulted.
func TestGroupFailureCodes(t *testing.T) {
	for code, status := range map[string]int{
		auth.GroupNotFound: http.StatusNotFound,
		auth.GroupExists:   http.StatusConflict,
		auth.GroupInUse:    http.StatusConflict,
	} {
		t.Run(code, func(t *testing.T) {
			got, failure, ok := auth.LookupFailure(code)
			require.True(t, ok)
			require.Equal(t, status, got)
			require.Equal(t, code, failure.Code)
			require.NotEmpty(t, failure.Message)
			require.Empty(t, failure.Hint, "the message is fixed; the hint is the service's")
			status, response := auth.FailureFor(&auth.Error{Code: code, Hint: "revoke the remaining grants"})
			require.Equal(t, got, status)
			require.Equal(t, code, response.Error.Code)
			require.Equal(t, "revoke the remaining grants", response.Error.Hint)
		})
	}
	_, _, ok := auth.LookupFailure("GROUP_UNKNOWN")
	require.False(t, ok)
}

func TestGroupContracts(t *testing.T) {
	require.Equal(t, "/api/admin/groups", auth.GroupsPath)
	require.Equal(t, "/api/admin/groups/{groupID}", auth.GroupPath)
	require.Equal(t, "/api/admin/groups/{groupID}/update", auth.GroupUpdatePath)
	require.Equal(t, "/api/admin/groups/{groupID}/delete", auth.GroupDeletePath)
	require.Equal(t, "/api/admin/groups/{groupID}/members", auth.GroupMembersPath)
	require.Equal(t, "/api/admin/groups/{groupID}/members/add", auth.GroupMemberAddPath)
	require.Equal(t, "/api/admin/groups/{groupID}/members/remove", auth.GroupMemberRemovePath)
	require.Equal(t, 1000, auth.MaxGroupListing)
	require.Equal(t, 1000, auth.MaxMemberListing)

	created := time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)
	encoded, err := json.Marshal(auth.GroupMutation{Group: auth.Group{
		ID: "g", Name: "finance-managers", Description: "Finance managers",
		CreatedAt: created, UpdatedAt: created, Members: 3, Grants: 2,
	}})
	require.NoError(t, err)
	require.JSONEq(t, `{"group":{"id":"g","name":"finance-managers","description":"Finance managers",`+
		`"createdAt":"2026-09-14T09:00:00Z","updatedAt":"2026-09-14T09:00:00Z","members":3,"grants":2},"dryRun":false}`, string(encoded))
	encoded, err = json.Marshal(auth.MemberList{Members: []auth.GroupMember{{
		UserRecord: auth.UserRecord{ID: "u", Username: "alice", Role: auth.Member, CreatedAt: created},
		AddedAt:    created, AddedBy: auth.GrantParty{ID: "a", Name: "admin"},
	}}})
	require.NoError(t, err)
	require.JSONEq(t, `{"members":[{"id":"u","username":"alice","role":"member","disabled":false,`+
		`"createdAt":"2026-09-14T09:00:00Z","addedAt":"2026-09-14T09:00:00Z","addedBy":{"id":"a","name":"admin"}}],"truncated":false}`, string(encoded))
	// A direct entry carries no group key at all, so a reader cannot mistake an
	// empty object for a group.
	encoded, err = json.Marshal(auth.AccessList{
		User: auth.UserRecord{ID: "u", Username: "alice", Role: auth.Member, CreatedAt: created},
		Entries: []auth.AccessEntry{
			{Connection: auth.GrantParty{ID: "c", Name: "payments"}, Source: auth.AccessDirect, CreatedAt: created},
			{Connection: auth.GrantParty{ID: "c", Name: "payments"}, Source: auth.AccessGroup,
				Group: &auth.GrantParty{ID: "g", Name: "finance-managers"}, CreatedAt: created},
		},
	})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), `"group":{}`)
	require.Contains(t, string(encoded), `"source":"direct"`)
	require.Contains(t, string(encoded), `"group":{"id":"g","name":"finance-managers"}`)
}

// Group names share the username grammar in their own namespace: the same text
// may name a user and a group, and --user and --group keep them apart.
func TestGroupReferencesAcceptUUIDOrName(t *testing.T) {
	require.True(t, auth.ValidGroupName("finance-managers"))
	require.True(t, auth.ValidGroupRef("finance-managers"))
	require.True(t, auth.ValidGroupRef("7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"))
	require.False(t, auth.ValidGroupName("7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"))
	for _, bad := range []string{"", "Finance", "ab", "1abc", "a b", "7fde7ce1-cc8d-4de8-a9c0"} {
		require.False(t, auth.ValidGroupRef(bad), bad)
		require.False(t, auth.ValidGroupName(bad), bad)
	}
	require.Equal(t, auth.ValidUsername("alice"), auth.ValidGroupName("alice"))
}

func TestIdentityGroupsAreOptionalAndTruncateIndependently(t *testing.T) {
	identity := auth.Identity{User: auth.User{ID: "u", Username: "alice", Role: auth.Member}}
	encoded, err := json.Marshal(identity)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "groups")
	identity.Groups = []string{"finance-managers"}
	identity.GroupsTruncated = true
	encoded, err = json.Marshal(identity)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"groups":["finance-managers"]`)
	require.Contains(t, string(encoded), `"groupsTruncated":true`)
	require.NotContains(t, string(encoded), "connectionsTruncated")
}

func TestConnectionSummaryCarriesNoTargetOrBounds(t *testing.T) {
	full := auth.Connection{
		ID: "id", Name: "payments-prod-reporting", Title: "Payments", Description: "reporting replica", Scope: "read",
		Provider: auth.ProviderPostgreSQL, Target: map[string]string{"host": "SENTINEL_HOST", "database": "SENTINEL_DB"},
		Labels: map[string]string{"env": "prod"}, Enabled: false,
		StatementTimeoutMS: 30000, MaxRows: 1000, MaxBytes: 1 << 20,
		LastCheck: &auth.CheckResult{Outcome: auth.CheckUnreachable, CheckedAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)},
	}
	summary := full.Summary()
	encoded, err := json.Marshal(auth.ConnectionSummaryList{Connections: []auth.ConnectionSummary{summary}})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "SENTINEL")
	for _, absent := range []string{"target", "statementTimeoutMs", "maxRows", "maxBytes", "secret", "createdAt", "updatedAt"} {
		require.NotContains(t, string(encoded), `"`+absent+`"`, absent)
	}
	for _, present := range []string{`"id":"id"`, `"name":"payments-prod-reporting"`, `"title":"Payments"`, `"description":"reporting replica"`,
		`"scope":"read"`, `"provider":"postgresql"`, `"labels":{"env":"prod"}`, `"enabled":false`, `"outcome":"unreachable"`, `"truncated":false`} {
		require.Contains(t, string(encoded), present, present)
	}
	require.NotContains(t, fmt.Sprintf("%v %+v", summary, summary), "SENTINEL")
}

func TestIdentityConnectionsAreOptional(t *testing.T) {
	identity := auth.Identity{User: auth.User{ID: "u", Username: "alice", Role: auth.Member}, ExpiresAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)}
	encoded, err := json.Marshal(identity)
	require.NoError(t, err)
	// Login responses never carry the connection fields.
	require.NotContains(t, string(encoded), "connections")
	identity.Connections = []string{"payments-prod-reporting"}
	identity.ConnectionsTruncated = true
	encoded, err = json.Marshal(identity)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"connections":["payments-prod-reporting"]`)
	require.Contains(t, string(encoded), `"connectionsTruncated":true`)
}

func TestUserReferencesAcceptUUIDOrUsername(t *testing.T) {
	require.True(t, auth.ValidUserRef("alice"))
	require.True(t, auth.ValidUserRef("7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"))
	for _, bad := range []string{"", "Alice", "ab", "1abc", "a b", "7fde7ce1-cc8d-4de8-a9c0"} {
		require.False(t, auth.ValidUserRef(bad), bad)
	}
	// A lowercase UUID matches the username characters but is a reference to
	// an id, never a name; the same value stays a valid reference.
	require.False(t, auth.ValidUsername("abcdef12-3456-4890-abcd-ef1234567890"))
	require.True(t, auth.ValidUserRef("abcdef12-3456-4890-abcd-ef1234567890"))
	require.Contains(t, auth.UsernameHint, "UUID")
}
