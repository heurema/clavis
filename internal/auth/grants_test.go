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
		User:       auth.GrantParty{ID: "u", Name: "alice"},
		Connection: auth.GrantParty{ID: "c", Name: "payments-prod-reporting"},
		CreatedAt:  time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC),
		CreatedBy:  auth.GrantParty{ID: "a", Name: "admin"},
	}
	encoded, err := json.Marshal(auth.GrantMutation{Grant: grant, Created: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"grant":{"user":{"id":"u","name":"alice"},"connection":{"id":"c","name":"payments-prod-reporting"},"createdAt":"2026-09-12T09:00:00Z","createdBy":{"id":"a","name":"admin"}},"created":true,"dryRun":false}`, string(encoded))
	encoded, err = json.Marshal(auth.GrantRevocation{User: grant.User, Connection: grant.Connection, Revoked: false, DryRun: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"user":{"id":"u","name":"alice"},"connection":{"id":"c","name":"payments-prod-reporting"},"revoked":false,"dryRun":true}`, string(encoded))
	encoded, err = json.Marshal(auth.GrantList{Grants: []auth.Grant{}, Truncated: false})
	require.NoError(t, err)
	require.JSONEq(t, `{"grants":[],"truncated":false}`, string(encoded))
	require.Equal(t, "/api/admin/grants", auth.GrantsPath)
	require.Equal(t, "/api/admin/grants/revoke", auth.GrantRevokePath)
	require.Equal(t, 1000, auth.MaxGrantListing)
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
