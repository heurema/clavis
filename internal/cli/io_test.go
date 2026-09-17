package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/auth"
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
			var stdoutOnly, stdout, stderr bytes.Buffer
			wantExit := RunWithIO(context.Background(), args, IO{Stdout: &stdoutOnly})
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
			assert.Equal(t, stdoutOnly.String(), stdout.String())
			assert.Empty(t, stderr.String())
			assert.Equal(t, len("SECRET\n"), stdin.Len(), "existing commands must not consume stdin")
			assert.NotContains(t, stdout.String(), "SECRET")
			if tc.json {
				decode(t, stdout.String()) // Also rejects extra stdout documents.
			}
		})
	}
}

// serverText asserts that text output names the resolved server first and
// returns the rest, which is exactly what the command rendered below it.
func serverText(t *testing.T, output, origin, profile string) string {
	t.Helper()
	line := "Server: " + origin
	if profile != "" {
		line += " (profile " + profile + ")"
	}
	rest, found := strings.CutPrefix(output, line+"\n")
	require.True(t, found, "text output must name the server first: %q", output)
	return rest
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

// TestResultNamesServerAndProfile checks that every result after resolution
// names the target, on success and failure alike, and that nothing produced
// before resolution does.
func TestResultNamesServerAndProfile(t *testing.T) {
	home := cliHome(t)
	_, server := newCLIFixture(t)
	fields := func(t *testing.T, output string) map[string]json.RawMessage {
		t.Helper()
		var value map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(output), &value))
		return value
	}
	named := func(t *testing.T, output, origin, profile string) {
		t.Helper()
		value := fields(t, output)
		require.JSONEq(t, strconv.Quote(origin), string(value["server"]))
		require.JSONEq(t, strconv.Quote(profile), string(value["profile"]))
	}
	unnamed := func(t *testing.T, output string) {
		t.Helper()
		value := fields(t, output)
		require.NotContains(t, value, "server")
		require.NotContains(t, value, "profile")
	}

	// Resolution failing names nothing, and offline commands never name a
	// server.
	exit, _, output := cliInvoke(t, "", "whoami")
	require.Equal(t, 2, exit)
	unnamed(t, output)
	exit, _, output = cliInvoke(t, "", "whoami", "--server", server.URL, "--profile", "test")
	require.Equal(t, 2, exit)
	unnamed(t, output)
	exit, output = invoke(t, "version")
	require.Equal(t, 0, exit)
	unnamed(t, output)
	// skill show prints a bare document; only its refusal has an envelope.
	exit, output = invoke(t, "skill", "show", "--file", "missing.md")
	require.Equal(t, 2, exit)
	unnamed(t, output)

	// A one-off server reports its empty profile, and the fields follow ok.
	exit, _, output, _ = loginInvoke(t, "--server", server.URL)
	require.Equal(t, 0, exit)
	require.True(t, strings.HasPrefix(output,
		`{"schemaVersion":1,"ok":true,"server":"`+server.URL+`","profile":"","data":`), output)

	cliProfile(t, server.URL)
	exit, _, output = cliInvoke(t, "", "whoami")
	require.Equal(t, 0, exit)
	named(t, output, server.URL, "test")
	// Early failures after resolution are named too: argument validation,
	// which still forces JSON, and a missing session.
	exit, result, output := cliInvoke(t, "", "--output=text", "users", "set-role", "--user", "alice", "--role", "owner")
	require.Equal(t, 2, exit)
	require.Equal(t, auth.InvalidArgument, result.Error.Code)
	named(t, output, server.URL, "test")
	exit, _, _ = cliInvoke(t, "", "logout")
	require.Equal(t, 0, exit)
	exit, result, output = cliInvoke(t, "", "users", "list")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.Unauthenticated, result.Error.Code)
	named(t, output, server.URL, "test")

	// An unreachable server is named in JSON, and in text on the first line,
	// before the error line.
	cliProfile(t, "http://127.0.0.1:1")
	exit, result, output = cliInvoke(t, "", "whoami")
	require.Equal(t, 1, exit)
	require.Equal(t, "SERVER_UNREACHABLE", result.Error.Code)
	named(t, output, "http://127.0.0.1:1", "test")
	exit, output = invoke(t, "whoami", "--output=text")
	require.Equal(t, 1, exit)
	require.Equal(t, "Server: http://127.0.0.1:1 (profile test)\nSERVER_UNREACHABLE: Server could not be reached\n", output)
	exit, output = invoke(t, "whoami", "--server", "http://127.0.0.1:1", "--output=text")
	require.Equal(t, 1, exit)
	require.Equal(t, "Server: http://127.0.0.1:1\nSERVER_UNREACHABLE: Server could not be reached\n", output)

	// Unsafe storage is reported under the server it was opened for.
	require.NoError(t, os.Chmod(filepath.Join(home, ".clavis", "sessions"), 0o755))
	exit, result, output = cliInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 1, exit)
	require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
	named(t, output, server.URL, "")
}
