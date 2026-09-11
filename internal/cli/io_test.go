package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunWithIOPreservesOutputAndExit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"SECRET"}}`)
	}))
	defer server.Close()

	for _, tc := range []struct {
		name string
		args []string
		exit int
		json bool
	}{
		{"help", []string{"--help"}, 0, false},
		{"version", []string{"version"}, 0, true},
		{"text", []string{"version", "--output=text"}, 0, false},
		{"invalid", []string{"--output=text", "--SECRET"}, 2, true},
		{"not-ready", []string{"doctor", "--server", server.URL}, 1, true},
		{"not-ready-text", []string{"doctor", "--server", server.URL, "--output=text"}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"clavis"}, tc.args...)
			var legacy, stdout, stderr bytes.Buffer
			wantExit := Run(context.Background(), args, &legacy)
			stdin := strings.NewReader("SECRET\n")
			gotExit := RunWithIO(context.Background(), args, IO{
				Stdin: stdin, Stdout: &stdout, Stderr: &stderr,
				ReadPassword: func(context.Context, io.Reader, io.Writer) ([]byte, error) {
					t.Fatal("existing commands must not prompt")
					return nil, nil
				},
			})
			assert.Equal(t, tc.exit, gotExit)
			assert.Equal(t, wantExit, gotExit)
			assert.Equal(t, legacy.String(), stdout.String())
			assert.Empty(t, stderr.String())
			assert.Equal(t, len("SECRET\n"), stdin.Len(), "existing commands must not consume stdin")
			assert.NotContains(t, stdout.String(), "SECRET")
			if tc.json {
				decode(t, stdout.String()) // Also rejects extra stdout documents.
			}
		})
	}
}

func TestIODefaultsAndInjectedPrompt(t *testing.T) {
	defaults := (IO{}).withDefaults()
	input, err := io.ReadAll(defaults.Stdin)
	require.NoError(t, err)
	assert.Empty(t, input)
	assert.Equal(t, io.Discard, defaults.Stdout)
	assert.Equal(t, io.Discard, defaults.Stderr)
	assert.Nil(t, defaults.ReadPassword)
	assert.Zero(t, RunWithIO(context.Background(), []string{"clavis", "version"}, IO{}))

	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("untouched")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	streams := (IO{
		Stdin: stdin, Stdout: &stdout, Stderr: &stderr,
		ReadPassword: func(gotCtx context.Context, gotInput io.Reader, prompt io.Writer) ([]byte, error) {
			assert.Same(t, ctx, gotCtx)
			assert.Same(t, stdin, gotInput)
			_, err := io.WriteString(prompt, "Password: ")
			require.NoError(t, err)
			return nil, gotCtx.Err()
		},
	}).withDefaults()
	password, err := streams.ReadPassword(ctx, streams.Stdin, streams.Stderr)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, password)
	assert.Equal(t, "Password: ", stderr.String())
	assert.Empty(t, stdout.String())
	assert.Equal(t, len("untouched"), stdin.Len())
}

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) {
	return 0, errors.New("SECRET")
}

func TestRunWithIOOutputFailure(t *testing.T) {
	for _, args := range [][]string{
		{"clavis", "--help"},
		{"clavis", "version"},
		{"clavis", "version", "--output=text"},
		{"clavis", "--SECRET"},
	} {
		var stderr bytes.Buffer
		assert.Equal(t, 1, RunWithIO(context.Background(), args, IO{
			Stdout: failingOutput{}, Stderr: &stderr,
		}))
		assert.Empty(t, stderr.String(), "writer errors must not leak to stderr")
	}
}
