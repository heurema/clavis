//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func buildCLI(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	require.NoError(t, err)
	dir, err := os.MkdirTemp("", "clavis-cli-build-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	binary := filepath.Join(dir, "clavis")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, goTool, "build", "-o", binary, "../../cmd/clavis")
	// Only Go is on PATH, and the internal linker requires no C toolchain.
	// Build before changing HOME so this can use the already pinned Go cache.
	command.Env = append(os.Environ(), "PATH="+filepath.Dir(goTool), "CGO_ENABLED=0")
	out, err := command.CombinedOutput()
	require.NoError(t, err, "Go-only CLI build: %s", out)
	return binary
}

func processCLI(t *testing.T, binary, input string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdin = strings.NewReader(input)
	command.Env = append(os.Environ(), "PATH=")
	var out, errout bytes.Buffer
	command.Stdout, command.Stderr = &out, &errout
	err := command.Run()
	if err != nil {
		var exit *exec.ExitError
		require.True(t, errors.As(err, &exit), "could not execute isolated CLI")
	}
	require.NoError(t, ctx.Err(), "CLI subprocess hung")
	return command.ProcessState.ExitCode(), out.String(), errout.String()
}

func TestCLIProcesses(t *testing.T) {
	binary := buildCLI(t)
	t.Run("workflow-and-offline", func(t *testing.T) {
		home := cliHome(t)
		password := testToken()
		fixture, server := newCLIFixture(t, password)
		t.Setenv("CLAVIS_SERVER_URL", server.URL)
		exit, output, prompt := processCLI(t, binary, string(password)+"\n", "login", "--username=cli-test", "--password-stdin")
		require.Equal(t, 0, exit)
		require.True(t, decode(t, output).OK)
		require.Empty(t, prompt)
		require.False(t, strings.Contains(output, string(password)))
		exit, output, _ = processCLI(t, binary, "", "whoami", "--output=text")
		require.Equal(t, 0, exit)
		require.Contains(t, output, "User: cli-test")
		require.Contains(t, output, "Role: admin")
		fixture.mu.Lock()
		for token := range fixture.sessions {
			require.False(t, strings.Contains(output, string(token)))
		}
		fixture.mu.Unlock()
		secret := testToken()
		exit, output, prompt = processCLI(t, binary, string(secret)+"\n", "users", "create", "--username=alice", "--password-stdin")
		require.Equal(t, 0, exit)
		require.Empty(t, prompt)
		created := decode(t, output)
		require.True(t, created.OK)
		require.NotContains(t, output, "password")
		require.False(t, strings.Contains(output, string(secret)))
		alice, _ := created.Data.(map[string]any)["id"].(string)
		require.True(t, auth.ValidUserID(alice))
		exit, output, _ = processCLI(t, binary, "", "users", "list", "--output=text")
		require.Equal(t, 0, exit)
		require.Equal(t, testIdentity().User.ID+" cli-test admin enabled\n"+alice+" alice member enabled\n", output)
		exit, output, _ = processCLI(t, binary, "", "users", "block", "--user", alice, "--output=text")
		require.Equal(t, 0, exit)
		require.Contains(t, output, "User: alice ("+alice+")\nRole: member\nStatus: blocked\nCreated: ")
		require.True(t, strings.HasSuffix(output, "Z\nSessions revoked: true\n"))
		// A connection created by an agent reads its credential from a file:
		// the secret is never an argument and never reaches the output.
		connectionSecret := testToken()
		secretPath := filepath.Join(home, "connection-secret")
		require.NoError(t, os.WriteFile(secretPath, []byte(string(connectionSecret)+"\n"), 0o600))
		exit, output, prompt = processCLI(t, binary, "", "connections", "create",
			"--name", "payments-prod-reporting", "--provider", "postgresql",
			"--url", "postgres://reporting@db:5432/payments?sslmode=require",
			"--label", "env=prod", "--password-file", secretPath)
		require.Equal(t, 0, exit, output)
		require.Empty(t, prompt)
		require.False(t, strings.Contains(output, string(connectionSecret)))
		require.NotContains(t, output, "password")
		connection, _ := decode(t, output).Data.(map[string]any)["id"].(string)
		require.True(t, auth.ValidUserID(connection))
		exit, output, _ = processCLI(t, binary, "", "connections", "list", "--selector", "env=prod", "--output=text")
		require.Equal(t, 0, exit)
		require.Equal(t, connection+" payments-prod-reporting postgresql enabled unchecked\n", output)
		exit, output, _ = processCLI(t, binary, "", "connections", "check", "--connection", "payments-prod-reporting", "--output=text")
		require.Equal(t, 0, exit)
		require.Contains(t, output, "Check: reachable at ")
		exit, output, _ = processCLI(t, binary, "", "connections", "delete", "--connection", "payments-prod-reporting", "--dry-run", "--output=text")
		require.Equal(t, 1, exit)
		require.Equal(t, "CONNECTION_IN_USE: The connection must be disabled and have no grants before deletion\n"+
			"Hint: "+inUseHint+"\n", output)

		// Grants are addressed by name in the isolated process too, creating
		// one twice is idempotent, and a blocked user keeps the grant.
		exit, output, _ = processCLI(t, binary, "", "grants", "create", "--user", "alice", "--connection", "payments-prod-reporting", "--output=text")
		require.Equal(t, 0, exit, output)
		require.Contains(t, output, "Grant: alice → payments-prod-reporting\n")
		require.Contains(t, output, "Created: true\n")
		exit, output, _ = processCLI(t, binary, "", "grants", "create", "--user", alice, "--connection", "payments-prod-reporting", "--output=text")
		require.Equal(t, 0, exit, output)
		require.Contains(t, output, "Created: false\n")
		exit, output, _ = processCLI(t, binary, "", "grants", "list", "--output=text")
		require.Equal(t, 0, exit)
		require.Regexp(t, `^alice payments-prod-reporting \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\n$`, output)
		exit, output, _ = processCLI(t, binary, "", "grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting", "--output=text")
		require.Equal(t, 0, exit)
		require.Equal(t, "Revoked: true\n", output)
		exit, output, _ = processCLI(t, binary, "", "grants", "revoke", "--user", "alice", "--connection", "payments-prod-reporting", "--output=text")
		require.Equal(t, 0, exit)
		require.Equal(t, "Revoked: false\n", output)
		// A user command takes the username as readily as the UUID.
		exit, output, _ = processCLI(t, binary, "", "users", "unblock", "--user", "alice", "--output=text")
		require.Equal(t, 0, exit, output)
		require.Contains(t, output, "User: alice ("+alice+")\nRole: member\nStatus: enabled\n")

		exit, output, _ = processCLI(t, binary, "", "sessions", "revoke", "--user", testIdentity().User.ID, "--output=text")
		require.Equal(t, 0, exit)
		require.Equal(t, "Revoked: true\n", output)
		exit, output, _ = processCLI(t, binary, "", "whoami")
		require.Equal(t, 1, exit)
		require.Equal(t, "UNAUTHENTICATED", decode(t, output).Error.Code)
		exit, output, _ = processCLI(t, binary, "", "logout")
		require.Equal(t, 0, exit)
		require.True(t, decode(t, output).OK)
		server.Close()
		// Offline commands must not even inspect a deliberately unsafe cache.
		config, err := os.UserConfigDir()
		require.NoError(t, err)
		require.NoError(t, os.Chmod(filepath.Join(config, "clavis"), 0755))
		for _, args := range [][]string{
			{"--help"}, {"login", "--help"}, {"sessions", "revoke", "--help"}, {"users", "--help"}, {"users"},
			{"users", "list", "--help"}, {"users", "create", "--help"}, {"users", "block", "--help"}, {"users", "unblock", "--help"},
			{"users", "reset-password", "--help"}, {"users", "set-role", "--help"}, {"version"}, {"version", "--output=text"},
			{"connections", "--help"}, {"connections"}, {"connections", "list", "--help"}, {"connections", "get", "--help"},
			{"connections", "create", "--help"}, {"connections", "update", "--help"}, {"connections", "set-credentials", "--help"},
			{"connections", "enable", "--help"}, {"connections", "disable", "--help"}, {"connections", "delete", "--help"},
			{"connections", "check", "--help"},
			{"grants", "--help"}, {"grants"}, {"grants", "list", "--help"},
			{"grants", "create", "--help"}, {"grants", "revoke", "--help"},
		} {
			exit, output, prompt = processCLI(t, binary, "", args...)
			require.Equal(t, 0, exit, "%v: %s", args, output)
			require.Empty(t, prompt)
		}
		for _, args := range [][]string{
			{"login", "--username=cli-test", "--output=text"},
			{"users", "create", "--username=alice", "--output=text"},
			{"users", "reset-password", "--user", alice, "--output=text"},
			// A noninteractive create with no secret channel must not prompt.
			{"connections", "create", "--name", "metrics-prod", "--provider", "victoriametrics",
				"--url", "https://metrics.example:8428", "--auth", "bearer", "--output=text"},
			{"connections", "set-credentials", "--connection", "payments-prod-reporting", "--output=text"},
			{"connections", "create", "--name", "metrics-prod", "--provider", "victoriametrics",
				"--url", "https://metrics.example:8428", "--password-file", "relative", "--output=text"},
			{"grants", "create", "--user", "ALICE", "--connection", "payments-prod-reporting", "--output=text"},
			{"grants", "revoke", "--user", "alice", "--output=text"},
		} {
			exit, output, prompt = processCLI(t, binary, string(password), args...)
			require.Equal(t, 2, exit, "%v", args)
			require.Equal(t, "INVALID_ARGUMENT", decode(t, output).Error.Code)
			require.Empty(t, prompt, "noninteractive input must not prompt")
		}
	})
	t.Run("terminal-connections-credentials", func(t *testing.T) {
		home := cliHome(t)
		password := testToken()
		fixture, server := newCLIFixture(t, password)
		t.Setenv("CLAVIS_SERVER_URL", server.URL)
		exit, _, _ := processCLI(t, binary, string(password), "login", "--username=cli-test", "--password-stdin")
		require.Equal(t, 0, exit)
		secretPath := filepath.Join(home, "connection-secret")
		require.NoError(t, os.WriteFile(secretPath, []byte(string(testToken())), 0o600))
		exit, output, _ := processCLI(t, binary, "", "connections", "create", "--name", "payments-prod-reporting",
			"--provider", "postgresql", "--url", "postgres://reporting@db:5432/payments", "--password-file", secretPath)
		require.Equal(t, 0, exit, output)
		identifier, _ := decode(t, output).Data.(map[string]any)["id"].(string)
		master, slave := testPTY(t)
		original, err := term.GetState(int(slave.Fd()))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "connections", "set-credentials", "--connection", "payments-prod-reporting")
		command.Stdin, command.Stderr = slave, slave
		command.Env = append(os.Environ(), "PATH=")
		var out bytes.Buffer
		command.Stdout = &out
		require.NoError(t, command.Start())
		prompt := make([]byte, len("Password: "))
		for i := range prompt {
			b, err := inputByte(ctx, master)
			require.NoError(t, err)
			prompt[i] = b
		}
		require.Equal(t, "Password: ", string(prompt))
		replacement := testToken()
		_, err = io.WriteString(master, string(replacement)+"\r")
		require.NoError(t, err)
		require.NoError(t, command.Wait())
		require.NoError(t, ctx.Err(), "terminal subprocess hung")
		result := decode(t, out.String())
		require.True(t, result.OK)
		mutation, _ := result.Data.(map[string]any)
		require.Equal(t, identifier, mutation["connection"].(map[string]any)["id"])
		require.Equal(t, false, mutation["dryRun"])
		require.False(t, strings.Contains(out.String(), string(replacement)))
		require.NotContains(t, out.String(), "password")
		fixture.mu.Lock()
		require.Equal(t, replacement, fixture.connSecrets[identifier])
		fixture.mu.Unlock()
		restored, err := term.GetState(int(slave.Fd()))
		require.NoError(t, err)
		require.Equal(t, original, restored, "terminal state must always be restored")
		assertTerminalInputEmpty(t, slave)
		fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		require.NoError(t, err)
		require.Positive(t, n)
		var remaining [2048]byte
		n, err = master.Read(remaining[:])
		require.NoError(t, err)
		require.Equal(t, "\r\n", string(remaining[:n]), "nothing but the prompt newline may be echoed")
	})
	t.Run("terminal-users-reset", func(t *testing.T) {
		cliHome(t)
		password := testToken()
		_, server := newCLIFixture(t, password)
		t.Setenv("CLAVIS_SERVER_URL", server.URL)
		exit, _, _ := processCLI(t, binary, string(password), "login", "--username=cli-test", "--password-stdin")
		require.Equal(t, 0, exit)
		exit, output, _ := processCLI(t, binary, string(testToken()), "users", "create", "--username=alice", "--password-stdin")
		require.Equal(t, 0, exit)
		alice, _ := decode(t, output).Data.(map[string]any)["id"].(string)
		master, slave := testPTY(t)
		original, err := term.GetState(int(slave.Fd()))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "users", "reset-password", "--user", alice)
		command.Stdin, command.Stderr = slave, slave
		command.Env = append(os.Environ(), "PATH=")
		var out bytes.Buffer
		command.Stdout = &out
		require.NoError(t, command.Start())
		prompt := make([]byte, len("Password: "))
		for i := range prompt {
			b, err := inputByte(ctx, master)
			require.NoError(t, err)
			prompt[i] = b
		}
		require.Equal(t, "Password: ", string(prompt))
		replacement := testToken()
		_, err = io.WriteString(master, string(replacement)+"\r")
		require.NoError(t, err)
		require.NoError(t, command.Wait())
		require.NoError(t, ctx.Err(), "terminal subprocess hung")
		result := decode(t, out.String())
		require.True(t, result.OK)
		mutation, _ := result.Data.(map[string]any)
		require.Equal(t, true, mutation["sessionsRevoked"])
		require.Equal(t, alice, mutation["user"].(map[string]any)["id"])
		require.False(t, strings.Contains(out.String(), string(replacement)))
		require.NotContains(t, out.String(), "password")
		restored, err := term.GetState(int(slave.Fd()))
		require.NoError(t, err)
		require.Equal(t, original, restored, "terminal state must always be restored")
		assertTerminalInputEmpty(t, slave)
		fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		require.NoError(t, err)
		require.Positive(t, n)
		var remaining [2048]byte
		n, err = master.Read(remaining[:])
		require.NoError(t, err)
		require.Equal(t, "\r\n", string(remaining[:n]), "nothing but the prompt newline may be echoed")
		exit, output, _ = processCLI(t, binary, "", "users", "block", "--user", alice, "--output=text")
		require.Equal(t, 0, exit)
		require.True(t, strings.HasSuffix(output, "Sessions revoked: true\n"))
	})
	t.Run("concurrent-login-logout", func(t *testing.T) {
		cliHome(t)
		password := testToken()
		fixture, server := newCLIFixture(t, password)
		t.Setenv("CLAVIS_SERVER_URL", server.URL)
		var workers sync.WaitGroup
		for range 6 {
			workers.Go(func() {
				exit, output, _ := processCLI(t, binary, string(password), "login", "--username=cli-test", "--password-stdin", "--timeout=3s")
				require.Equal(t, 0, exit, "login result error: %+v", decode(t, output).Error)
				exit, output, _ = processCLI(t, binary, "", "logout", "--timeout=3s")
				require.Equal(t, 0, exit, "logout result error: %+v", decode(t, output).Error)
			})
		}
		workers.Wait()
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		require.Equal(t, 6, fixture.login)
		require.Empty(t, fixture.sessions)
		_, err := os.Stat(cachePath(t, server.URL))
		require.True(t, os.IsNotExist(err))
	})
	t.Run("lock-contention-and-process-exit", func(t *testing.T) {
		cliHome(t)
		password := testToken()
		_, server := newCLIFixture(t, password)
		cache, err := openCache(context.Background(), server.URL)
		require.NoError(t, err)
		start := time.Now()
		exit, output, _ := processCLI(t, binary, string(password), "login", "--username=cli-test", "--password-stdin", "--server", server.URL, "--timeout=60ms")
		require.Equal(t, 1, exit)
		require.Equal(t, "CREDENTIAL_STORAGE_FAILED", decode(t, output).Error.Code)
		require.Less(t, time.Since(start), time.Second)
		cache.close()
		exit, _, _ = processCLI(t, binary, string(password), "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
		require.Equal(t, 0, exit, "exited process must not retain a lock")
	})
	t.Run("stdin-cancellation", func(t *testing.T) {
		cliHome(t)
		input, writer, err := os.Pipe()
		require.NoError(t, err)
		defer func() { _ = input.Close(); _ = writer.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "login", "--username=cli-test", "--password-stdin")
		command.Stdin = input
		var out bytes.Buffer
		command.Stdout = &out
		require.NoError(t, command.Start())
		// Allow startup to install its signal handler before interrupting.
		time.Sleep(100 * time.Millisecond)
		require.NoError(t, command.Process.Signal(syscall.SIGTERM))
		require.Error(t, command.Wait())
		require.NoError(t, ctx.Err())
		require.Equal(t, 1, command.ProcessState.ExitCode())
		require.Equal(t, "TIMEOUT", decode(t, out.String()).Error.Code)
	})
	t.Run("killed-lock-holder", func(t *testing.T) {
		cliHome(t)
		entered := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.(http.Flusher).Flush()
			close(entered)
			<-r.Context().Done()
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "login", "--username=cli-test", "--password-stdin", "--server", server.URL)
		command.Stdin = strings.NewReader(string(testToken()))
		require.NoError(t, command.Start())
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("child never reached fixture while holding its credential lock")
		}
		require.NoError(t, command.Process.Kill())
		require.Error(t, command.Wait())
		lockCtx, lockCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer lockCancel()
		cache, err := openCache(lockCtx, server.URL)
		require.NoError(t, err, "OS must release a killed process's lock")
		cache.close()
	})
	for _, mode := range []string{"success", "ctrl-c", "signal", "oversized"} {
		t.Run("terminal-"+mode, func(t *testing.T) {
			cliHome(t)
			password := testToken()
			_, server := newCLIFixture(t, password)
			master, slave := testPTY(t)
			original, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "login", "--username=cli-test", "--server", server.URL)
			command.Stdin, command.Stderr = slave, slave
			var out bytes.Buffer
			command.Stdout = &out
			require.NoError(t, command.Start())
			prompt := make([]byte, len("Password: "))
			for i := range prompt {
				b, err := inputByte(ctx, master)
				require.NoError(t, err)
				prompt[i] = b
			}
			require.Equal(t, "Password: ", string(prompt))
			switch mode {
			case "success":
				_, err = io.WriteString(master, string(password)+"\r")
			case "ctrl-c":
				_, err = master.Write([]byte{3})
			case "signal":
				err = command.Process.Signal(syscall.SIGTERM)
			case "oversized":
				_, err = io.WriteString(master, strings.Repeat("x", 16*1024)+"SECRET-SUFFIX-MUST-NOT-REACH-SHELL\n")
			}
			require.NoError(t, err)
			waitErr := command.Wait()
			require.NoError(t, ctx.Err(), "terminal subprocess hung")
			if mode == "success" {
				require.NoError(t, waitErr)
				require.True(t, decode(t, out.String()).OK)
			} else {
				require.Error(t, waitErr)
				want := 1
				if mode == "oversized" {
					want = 2
				}
				require.Equal(t, want, command.ProcessState.ExitCode())
				require.False(t, decode(t, out.String()).OK)
			}
			restored, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			require.Equal(t, original, restored, "terminal state must always be restored")
			assertTerminalInputEmpty(t, slave)
			// Anything the terminal echoed would be visible on the master. Only
			// the final prompt newline is permitted, not even partial password.
			fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 100)
			require.NoError(t, err)
			require.Positive(t, n)
			var remaining [2048]byte
			n, err = master.Read(remaining[:])
			require.NoError(t, err)
			require.Equal(t, "\r\n", string(remaining[:n]))
			require.False(t, strings.Contains(out.String(), string(password)))
		})
	}
}
