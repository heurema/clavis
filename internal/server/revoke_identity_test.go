package server

import (
	"net/http"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestEarlyRevocationRejectionNeverReachesTheService(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bearer  string
		authErr error
		status  int
	}{
		{"verified actor invalid target", "Bearer " + string(fixtureToken), nil, 400},
		{"missing bearer", "", nil, 401},
		{"malformed bearer", "Bearer not-a-session", nil, 401},
		{"failed authentication with returned identity", "Bearer " + string(fixtureToken), &auth.Error{Code: auth.Unauthenticated}, 401},
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
		})
	}
}

func TestServiceOwnedRevocationRejectionKeepsItsStatus(t *testing.T) {
	f := &backendFixture{revokeErr: &auth.Error{Code: auth.Forbidden}}
	handler := authHandler(t, f, nil, "https://clavis.example")
	headers := http.Header{"Authorization": {"Bearer " + string(fixtureToken)}}
	response := requestAuth(handler, http.MethodPost, "/api/admin/users/"+fixtureIdentity.User.ID+"/sessions/revoke", "", headers)
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Equal(t, 1, f.revokeCalls)
}
