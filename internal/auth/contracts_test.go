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
		auth.UsernameTaken: http.StatusConflict, auth.LastAdministrator: http.StatusConflict,
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
