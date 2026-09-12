package server

import (
	"net/http"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestEarlyRevocationAuditRetainsOnlyVerifiedIdentity(t *testing.T) {
	const sessionID = "12345678-1234-4234-8234-123456789aaa"
	for _, tc := range []struct {
		name       string
		bearer     string
		authErr    error
		status     int
		identified bool
	}{
		{"verified actor invalid target", "Bearer " + string(fixtureToken), nil, 400, true},
		{"missing bearer", "", nil, 401, false},
		{"malformed bearer", "Bearer not-a-session", nil, 401, false},
		{"failed authentication with returned identity", "Bearer " + string(fixtureToken), &auth.Error{Code: auth.Unauthenticated}, 401, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &backendFixture{errorAuth: tc.authErr}
			handler := authHandler(t, f, nil, "https://clavis.example")
			headers := http.Header{}
			if tc.bearer != "" {
				headers.Set("Authorization", tc.bearer)
			}
			response := requestAuth(handler, http.MethodPost, "/api/admin/users/NOT-A-UUID/sessions/revoke", "", headers)
			require.Equal(t, tc.status, response.Code)
			require.Zero(t, f.revokeCalls)
			require.Len(t, f.events, 1)
			event := f.events[0]
			require.Equal(t, auth.EventRevoke, event.Action)
			require.Empty(t, event.TargetID)
			if tc.identified {
				require.Equal(t, fixtureIdentity.User.ID, event.ActorID)
				require.Equal(t, sessionID, event.SessionID)
				require.Equal(t, auth.OutcomeInvalidArgument, event.Outcome)
			} else {
				require.Empty(t, event.ActorID)
				require.Empty(t, event.SessionID)
				require.Equal(t, auth.OutcomeUnauthenticated, event.Outcome)
			}
		})
	}
}

func TestServiceOwnedRevocationRejectionHasNoAdapterDuplicate(t *testing.T) {
	f := &backendFixture{revokeErr: &auth.Error{Code: auth.Forbidden}}
	handler := authHandler(t, f, nil, "https://clavis.example")
	headers := http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}
	response := requestAuth(handler, http.MethodPost, "/api/admin/users/"+fixtureIdentity.User.ID+"/sessions/revoke", "", headers)
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Equal(t, 1, f.revokeCalls)
	require.Empty(t, f.events)
}
