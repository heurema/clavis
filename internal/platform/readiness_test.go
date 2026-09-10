package platform_test

import (
	"encoding/json"
	"testing"

	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

func TestReadinessContract(t *testing.T) {
	for _, tc := range []struct {
		state platform.State
		code  string
	}{
		{platform.Ready, ""},
		{platform.DependencyUnavailable, platform.CodeDependencyUnavailable},
		{platform.Initializing, platform.CodeInitializing},
		{platform.SetupRequired, platform.CodeSetupRequired},
		{platform.BootstrapFailed, platform.CodeBootstrapFailed},
		{platform.SchemaError, platform.CodeSchemaError},
		{"", platform.CodeDependencyUnavailable},
		{"unrecognized", platform.CodeDependencyUnavailable},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
			value := platform.Readiness{State: tc.state}
			response := value.Response()
			require.Equal(t, tc.code == "", value.Ready())
			encoded, err := json.Marshal(response)
			require.NoError(t, err)
			if tc.code == "" {
				require.JSONEq(t, `{"status":"ready"}`, string(encoded))
				return
			}
			require.Equal(t, "not_ready", response.Status)
			require.Equal(t, tc.code, response.Error.Code)
			safe, ok := platform.LookupFailure(tc.code)
			require.True(t, ok)
			require.Equal(t, safe, *response.Error)
		})
	}
}

func TestLegacyDatabaseFailureAndUnknownCode(t *testing.T) {
	encoded, err := json.Marshal(platform.Readiness{State: platform.DependencyUnavailable}.Response())
	require.NoError(t, err)
	require.JSONEq(t, `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Database unavailable"}}`, string(encoded))
	_, ok := platform.LookupFailure("private driver failure")
	require.False(t, ok)
}
