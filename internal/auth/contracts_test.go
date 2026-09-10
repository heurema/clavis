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
