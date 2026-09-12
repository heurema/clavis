package auth_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

func TestSafeIdentityProjection(t *testing.T) {
	issued := auth.LoginResponse{
		Token: auth.Secret("fixture-token-not-a-credential"),
		Identity: auth.Identity{
			User:      auth.User{ID: "fixture-user", Username: "alice", Role: auth.Admin},
			ExpiresAt: time.Date(2026, 9, 10, 20, 0, 0, 0, time.UTC),
		},
	}
	transport, err := json.Marshal(issued)
	require.NoError(t, err)
	require.Contains(t, string(transport), string(issued.Token))
	safe, err := json.Marshal(issued.Identity)
	require.NoError(t, err)
	require.JSONEq(t, `{"user":{"id":"fixture-user","username":"alice","role":"admin"},"expiresAt":"2026-09-10T20:00:00Z"}`, string(safe))
	require.NotContains(t, string(safe), string(issued.Token))
	require.NotContains(t, fmt.Sprintf("%v %+v %#v", issued, issued, issued), string(issued.Token))
}

func TestCredentialEncodingBudget(t *testing.T) {
	request := auth.LoginRequest{Username: strings.Repeat("a", 64), Password: auth.Secret(strings.Repeat("\x01", auth.MaxPasswordBytes))}
	encoded, err := json.Marshal(request)
	require.NoError(t, err)
	require.Greater(t, len(encoded), 4*1024)
	require.LessOrEqual(t, len(encoded), auth.MaxCredentialBody)
	var decoded auth.LoginRequest
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, request, decoded)
}

func TestFailureAllowlist(t *testing.T) {
	for code, expected := range map[string]int{
		auth.InvalidArgument: http.StatusBadRequest, auth.InvalidCredentials: http.StatusUnauthorized,
		auth.Unauthenticated: http.StatusUnauthorized, auth.Forbidden: http.StatusForbidden,
		auth.UserNotFound: http.StatusNotFound, auth.RateLimited: http.StatusTooManyRequests,
		auth.UsernameTaken: http.StatusConflict, auth.LastAdministrator: http.StatusConflict, auth.SelfTarget: http.StatusConflict,
		auth.ServiceUnavailable:            http.StatusServiceUnavailable,
		platform.CodeDependencyUnavailable: http.StatusServiceUnavailable,
		platform.CodeInitializing:          http.StatusServiceUnavailable,
		platform.CodeSetupRequired:         http.StatusServiceUnavailable,
		platform.CodeBootstrapFailed:       http.StatusServiceUnavailable,
		platform.CodeSchemaError:           http.StatusServiceUnavailable,
	} {
		t.Run(code, func(t *testing.T) {
			status, response := auth.FailureFor(&auth.Error{Code: code})
			require.Equal(t, expected, status)
			require.Equal(t, code, response.Error.Code)
			require.NotEmpty(t, response.Error.Message)
		})
	}
	_, _, known := auth.LookupFailure("private-response")
	require.False(t, known)
	for _, err := range []error{errors.New("SENTINEL_SECRET"), &auth.Error{Code: "SENTINEL_SECRET"}} {
		status, response := auth.FailureFor(err)
		require.Equal(t, http.StatusServiceUnavailable, status)
		require.Equal(t, auth.ServiceUnavailable, response.Error.Code)
		require.NotContains(t, fmt.Sprint(response), "SENTINEL_SECRET")
	}
}

func TestAdministrationProjectionsAndEvents(t *testing.T) {
	record := auth.UserRecord{
		ID: "fixture-user", Username: "alice", Role: auth.Member, Disabled: true,
		CreatedAt: time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC),
	}
	encoded, err := json.Marshal(auth.UserMutation{User: record, SessionsRevoked: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"user":{"id":"fixture-user","username":"alice","role":"member","disabled":true,"createdAt":"2026-09-11T09:00:00Z"},"sessionsRevoked":true}`, string(encoded))
	encoded, err = json.Marshal(auth.UserList{Users: []auth.UserRecord{record}, Truncated: false})
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"truncated":false`)
	require.NotContains(t, string(encoded), "password")

	// Request DTOs are the only administration types allowed to carry secrets,
	// and ordinary formatting must still redact them.
	for _, value := range []any{
		auth.CreateUserRequest{Username: "alice", Password: auth.Secret("SENTINEL_SECRET_VALUE")},
		auth.ResetPasswordRequest{Password: auth.Secret("SENTINEL_SECRET_VALUE")},
	} {
		require.NotContains(t, fmt.Sprintf("%v %+v %#v", value, value, value), "SENTINEL_SECRET_VALUE")
		transport, err := json.Marshal(value)
		require.NoError(t, err)
		require.Contains(t, string(transport), "SENTINEL_SECRET_VALUE")
	}

	for _, action := range []auth.EventAction{
		auth.EventLogin, auth.EventLogout, auth.EventRevoke, auth.EventUserCreate, auth.EventUserBlock,
		auth.EventUserUnblock, auth.EventUserResetPassword, auth.EventUserPromote, auth.EventUserDemote, auth.EventUsersList,
	} {
		require.True(t, auth.ValidEventAction(action), string(action))
		require.True(t, auth.Event{Action: action, Outcome: auth.OutcomeForbidden}.Valid(), string(action))
	}
	for _, action := range []auth.EventAction{"", "bootstrap", "user.delete", "USER.CREATE", "user.create "} {
		require.False(t, auth.ValidEventAction(action), string(action))
		require.False(t, auth.Event{Action: action, Outcome: auth.OutcomeForbidden}.Valid(), string(action))
	}
	// The recorder boundary still accepts only adapter rejection outcomes.
	require.False(t, auth.Event{Action: auth.EventUserCreate, Outcome: "success"}.Valid())
	require.False(t, auth.Event{Action: auth.EventUserCreate, Outcome: "username_taken"}.Valid())
}

func TestConnectionContracts(t *testing.T) {
	for code, expected := range map[string]int{
		auth.ConnectionExists: http.StatusConflict, auth.ConnectionNotFound: http.StatusNotFound,
		auth.ConnectionInUse: http.StatusConflict, auth.CredentialsUnavailable: http.StatusConflict,
	} {
		status, response := auth.FailureFor(&auth.Error{Code: code, Hint: "run clavis connections update"})
		require.Equal(t, expected, status, code)
		require.Equal(t, "run clavis connections update", response.Error.Hint)
	}
	// Hints are optional and omitted from JSON when absent.
	_, response := auth.FailureFor(&auth.Error{Code: auth.ConnectionNotFound})
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "hint")
	for _, action := range []auth.EventAction{
		auth.EventConnectionCreate, auth.EventConnectionUpdate, auth.EventConnectionSecrets, auth.EventConnectionEnable,
		auth.EventConnectionDisable, auth.EventConnectionDelete, auth.EventConnectionCheck, auth.EventConnectionsList,
	} {
		require.True(t, auth.ValidEventAction(action), string(action))
	}
	require.False(t, auth.ValidEventAction("connection.delete "))

	// The secret-bearing request DTOs redact under ordinary formatting.
	for _, value := range []any{
		auth.CreateConnectionRequest{Name: "payments", Secret: auth.Secret("SENTINEL_SECRET_VALUE")},
		auth.SetConnectionCredentialsRequest{Secret: auth.Secret("SENTINEL_SECRET_VALUE")},
	} {
		require.NotContains(t, fmt.Sprintf("%v %+v %#v", value, value, value), "SENTINEL_SECRET_VALUE")
	}
	record := auth.Connection{ID: "id", Name: "payments-prod-reporting", Provider: auth.ProviderPostgreSQL,
		Target: map[string]string{"host": "db"}, Labels: map[string]string{"env": "prod"}, Enabled: true}
	encoded, err = json.Marshal(auth.ConnectionMutation{Connection: record, DryRun: true})
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"dryRun":true`)
	require.Contains(t, string(encoded), `"lastCheck":null`)
	require.NotContains(t, string(encoded), "secret")
}

func TestConnectionNamesLabelsAndSelectors(t *testing.T) {
	require.True(t, auth.ValidConnectionRef("payments-prod-reporting"))
	require.True(t, auth.ValidConnectionRef("7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba"))
	for _, bad := range []string{"", "Payments", "1abc", "a", strings.Repeat("a", 65), "a b", "7fde7ce1-cc8d-4de8-a9c0"} {
		require.False(t, auth.ValidConnectionRef(bad), bad)
	}
	// A lowercase UUID satisfies the username characters but must never be a
	// name, or the UUID-first lookup could shadow it.
	require.False(t, auth.ValidConnectionName("abcdef12-3456-4890-abcd-ef1234567890"))
	require.True(t, auth.ValidConnectionRef("abcdef12-3456-4890-abcd-ef1234567890"), "still a valid UUID reference")
	require.True(t, auth.ValidProvider(auth.ProviderVictoriaMetrics))
	require.False(t, auth.ValidProvider("mysql"))
	require.True(t, auth.ValidSecret("hunter2-hunter2"))
	require.False(t, auth.ValidSecret(""))
	require.False(t, auth.ValidSecret(auth.Secret("a\nb")))
	require.False(t, auth.ValidSecret(auth.Secret(strings.Repeat("x", auth.MaxSecretBytes+1))))

	labels, ok := auth.ParseLabels([]string{"env=prod", "service=payments", "team=finance"})
	require.True(t, ok)
	require.Equal(t, map[string]string{"env": "prod", "service": "payments", "team": "finance"}, labels)
	for _, bad := range [][]string{{"env"}, {"env="}, {"=prod"}, {"Env=prod"}, {"env=Prod"}, {"env=prod", "env=stage"}} {
		_, ok := auth.ParseLabels(bad)
		require.False(t, ok, strings.Join(bad, ","))
	}
	many := make([]string, auth.MaxLabels+1)
	for n := range many {
		many[n] = fmt.Sprintf("k%d=v", n)
	}
	_, ok = auth.ParseLabels(many)
	require.False(t, ok)

	terms, ok := auth.ParseSelector("env=prod, service!=legacy ,team")
	require.True(t, ok)
	require.Equal(t, []auth.SelectorTerm{
		{Key: "env", Op: auth.SelectorEquals, Value: "prod"},
		{Key: "service", Op: auth.SelectorNotEquals, Value: "legacy"},
		{Key: "team", Op: auth.SelectorExists},
	}, terms)
	terms, ok = auth.ParseSelector("  ")
	require.True(t, ok)
	require.Empty(t, terms)
	for _, bad := range []string{"env==prod", "=prod", "env!=", "Env", "a,b,c,d,e,f,g,h,i", "env=prod,,team"} {
		_, ok := auth.ParseSelector(bad)
		require.False(t, ok, bad)
	}
}
