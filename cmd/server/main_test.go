package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serverEnvironment(values ...string) []string {
	var result []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "CLAVIS_") && !strings.HasPrefix(entry, "PG") {
			result = append(result, entry)
		}
	}
	return append(result, values...)
}

func TestServerProcess(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "server")
	build := exec.Command("go", "build", "-o", binary, ".")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	// The credential encryption key is a required startup input like the
	// database URL; the test key never leaves the temporary directory.
	keyFile := filepath.Join(t.TempDir(), "encryption-key")
	require.NoError(t, os.WriteFile(keyFile, []byte(strings.Repeat("ab", 32)+"\n"), 0o600))
	keyEnv := "CLAVIS_ENCRYPTION_KEY_FILE=" + keyFile
	t.Run("invalid config is safe", func(t *testing.T) {
		for _, value := range []string{"", "postgres://user:SECRET@127.0.0.1/db?connect_timeout=SECRET"} {
			command := exec.Command(binary)
			command.Env = serverEnvironment("CLAVIS_DATABASE_URL="+value, keyEnv)
			output, err := command.CombinedOutput()
			require.Error(t, err)
			assert.Contains(t, string(output), "configuration_invalid")
			assert.NotContains(t, string(output), "SECRET")
			assert.NotContains(t, string(output), "server_started")
		}
	})
	t.Run("missing or unsafe encryption key is safe", func(t *testing.T) {
		unsafe := filepath.Join(t.TempDir(), "SECRETPATH-key")
		require.NoError(t, os.WriteFile(unsafe, []byte(strings.Repeat("ab", 32)+"\n"), 0o644))
		for name, value := range map[string]string{"missing": "", "relative": "relative/key", "absent": filepath.Join(t.TempDir(), "absent"), "unsafe": unsafe} {
			command := exec.Command(binary)
			command.Env = serverEnvironment("CLAVIS_DATABASE_URL=postgres://local@127.0.0.1/clavis", "CLAVIS_ENCRYPTION_KEY_FILE="+value)
			output, err := command.CombinedOutput()
			require.Error(t, err, name)
			assert.Contains(t, string(output), "configuration_invalid", name)
			assert.Contains(t, string(output), "CLAVIS_ENCRYPTION_KEY_FILE", name)
			assert.NotContains(t, string(output), "SECRETPATH", name)
			assert.NotContains(t, string(output), "abab", name)
			assert.NotContains(t, string(output), "server_started", name)
		}
	})
	t.Run("startup and shutdown with blocked database", func(t *testing.T) {
		db, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		accepted := make(chan net.Conn, 1)
		go func() {
			connection, err := db.Accept()
			if err == nil {
				accepted <- connection
			}
		}()
		reserve, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		address := reserve.Addr().String()
		require.NoError(t, reserve.Close())
		command := exec.Command(binary)
		command.Env = serverEnvironment("CLAVIS_HTTP_ADDR="+address, "CLAVIS_DATABASE_URL=postgres://local:SECRET@"+db.Addr().String()+"/clavis?sslmode=disable", "CLAVIS_DB_CHECK_TIMEOUT=30s", "CLAVIS_SHUTDOWN_TIMEOUT=100ms", keyEnv)
		logPath := filepath.Join(t.TempDir(), "server.log")
		log, err := os.Create(logPath)
		require.NoError(t, err)
		defer func() { _ = log.Close() }()
		command.Stderr = log
		require.NoError(t, command.Start())
		var waitErr error
		done := make(chan struct{})
		go func() { waitErr = command.Wait(); close(done) }()
		t.Cleanup(func() {
			select {
			case <-done:
			default:
				_ = command.Process.Kill()
				<-done
			}
		})
		client := &http.Client{Timeout: 100 * time.Millisecond}
		require.Eventually(t, func() bool {
			response, err := client.Get("http://" + address + "/health/live")
			if err != nil {
				return false
			}
			defer func() { _ = response.Body.Close() }()
			return response.StatusCode == 200
		}, 5*time.Second, 20*time.Millisecond, "liveness must start without database connectivity")
		requestCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		request, err := http.NewRequestWithContext(requestCtx, "GET", "http://"+address+"/health/ready", nil)
		require.NoError(t, err)
		requestDone := make(chan struct{})
		go func() {
			defer close(requestDone)
			response, err := http.DefaultClient.Do(request)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
		}()
		select {
		case connection := <-accepted:
			defer func() { _ = connection.Close() }()
		case <-time.After(5 * time.Second):
			t.Fatal("readiness did not reach database")
		}
		start := time.Now()
		require.NoError(t, command.Process.Signal(syscall.SIGTERM))
		select {
		case <-done:
			require.NoError(t, waitErr)
		case <-time.After(2 * time.Second):
			t.Fatal("server did not stop within bound")
		}
		assert.Less(t, time.Since(start), 500*time.Millisecond)
		cancel()
		<-requestDone
		output, err := os.ReadFile(logPath)
		require.NoError(t, err)
		assert.Contains(t, string(output), "server_started")
		assert.Contains(t, string(output), "server_stopped")
		assert.NotContains(t, string(output), "SECRET")
		response, err := client.Get("http://" + address + "/health/live")
		if response != nil {
			_ = response.Body.Close()
		}
		require.Error(t, err)
	})
}
