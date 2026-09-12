package provider

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
)

// sentinel appears in rejected inputs and in probe secrets. No hint, error or
// outcome may ever contain it.
const sentinel = "SENTINEL"

// requireRejected asserts the single rejection shape the package produces and
// that nothing the caller submitted came back in it.
func requireRejected(t *testing.T, err error) {
	t.Helper()
	var failure *auth.Error
	require.ErrorAs(t, err, &failure)
	require.Equal(t, auth.InvalidArgument, failure.Code)
	require.NotEmpty(t, failure.Hint)
	requireNoSentinel(t, failure.Hint, failure.Error())
}

func requireNoSentinel(t *testing.T, values ...any) {
	t.Helper()
	require.NotContains(t, strings.ToUpper(fmt.Sprint(values...)), sentinel)
}

func TestLookup(t *testing.T) {
	for _, name := range []auth.ProviderType{auth.ProviderPostgreSQL, auth.ProviderVictoriaMetrics} {
		implementation, ok := Lookup(name)
		require.True(t, ok)
		require.Equal(t, name, implementation.Type())
	}
	unknown, ok := Lookup(auth.ProviderType(sentinel))
	require.False(t, ok)
	require.Nil(t, unknown)
	_, ok = Lookup("")
	require.False(t, ok)
}

func TestTypesIsSorted(t *testing.T) {
	require.Equal(t, []auth.ProviderType{auth.ProviderPostgreSQL, auth.ProviderVictoriaMetrics}, Types())
	for _, provider := range Types() {
		require.True(t, auth.ValidProvider(provider))
	}
}

func TestTypeHintListsEveryProvider(t *testing.T) {
	hint := TypeHint()
	for _, provider := range Types() {
		require.Contains(t, hint, string(provider))
	}
}

func TestExecuteUnsupportedProvider(t *testing.T) {
	implementation, ok := Lookup(auth.ProviderVictoriaMetrics)
	require.True(t, ok)
	// A provider without an execute operation says so without a network call,
	// so a query against one cannot reach a source or spend a credential.
	result, err := implementation.Execute(
		t.Context(),
		map[string]string{keyURL: "http://127.0.0.1:1", keyAuth: authNone},
		auth.Secret(sentinel),
		ExecuteRequest{SQL: "select " + sentinel},
	)
	require.ErrorIs(t, err, ErrUnsupported)
	require.Equal(t, ExecuteResult{}, result)
	requireNoSentinel(t, err.Error())
}

func TestExecuteFailuresAreDistinctAndSilent(t *testing.T) {
	failures := []error{ErrTimeout, ErrUnreachable, ErrAuthRejected, ErrUnsupported}
	for index, failure := range failures {
		require.NotEmpty(t, failure.Error())
		requireNoSentinel(t, failure.Error())
		// Each sentinel is its own value, so a caller's branch on one can
		// never catch another.
		for other := range failures {
			require.Equal(t, index == other, errors.Is(failure, failures[other]))
		}
	}
	// A source rejection carries the source's words in its failure block and
	// never in its own text, which is what keeps them out of a log.
	rejected := &SourceError{Failure: auth.SourceFailure{SQLState: "42601", Message: sentinel, Statement: 2}}
	require.NotEmpty(t, rejected.Error())
	requireNoSentinel(t, rejected.Error())
	require.Equal(t, sentinel, rejected.Failure.Message)
}
