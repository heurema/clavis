package config

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	base := map[string]string{"CLAVIS_DATABASE_URL": "postgres://local:secret@127.0.0.1:5432/clavis"}
	cfg, err := Load(base)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8080", cfg.HTTPAddr)
	assert.Equal(t, 2*time.Second, cfg.DBCheckTimeout)
	assert.Equal(t, 10*time.Second, cfg.ShutdownTimeout)
	assert.Equal(t, slog.LevelInfo, cfg.Level())
	_, err = Load(map[string]string{"CLAVIS_DATABASE_URL": "postgresql://local:secret@127.0.0.1/clavis", "CLAVIS_HTTP_ADDR": "127.0.0.1:65535"})
	require.NoError(t, err, "postgresql URLs and the highest valid TCP port are accepted")
	for _, tc := range []struct{ field, value, category string }{
		{"CLAVIS_DATABASE_URL", "", "REQUIRED"},
		{"CLAVIS_DATABASE_URL", "postgres://%secret", "INVALID_DATABASE_URL"},
		{"CLAVIS_DATABASE_URL", "https://secret.invalid", "INVALID_DATABASE_URL"},
		{"CLAVIS_DATABASE_URL", "postgres://host/db?connect_timeout=secret", "INVALID_DATABASE_URL"},
		{"CLAVIS_HTTP_ADDR", "secret", "INVALID_ADDRESS"},
		{"CLAVIS_HTTP_ADDR", ":80", "INVALID_ADDRESS"},
		{"CLAVIS_HTTP_ADDR", "127.0.0.1:65536", "INVALID_PORT"},
		{"CLAVIS_HTTP_ADDR", "127.0.0.1:-1", "INVALID_PORT"},
		{"CLAVIS_HTTP_ADDR", "127.0.0.1:secret", "INVALID_PORT"},
		{"CLAVIS_DB_CHECK_TIMEOUT", "secret", "INVALID_DURATION"},
		{"CLAVIS_SHUTDOWN_TIMEOUT", "secret", "INVALID_DURATION"},
		{"CLAVIS_DB_CHECK_TIMEOUT", "0", "MUST_BE_POSITIVE"},
		{"CLAVIS_DB_CHECK_TIMEOUT", "-1s", "MUST_BE_POSITIVE"},
		{"CLAVIS_SHUTDOWN_TIMEOUT", "0s", "MUST_BE_POSITIVE"},
		{"CLAVIS_LOG_LEVEL", "secret", "INVALID_LEVEL"},
	} {
		t.Run(tc.field+"/"+tc.value, func(t *testing.T) {
			input := map[string]string{"CLAVIS_DATABASE_URL": base["CLAVIS_DATABASE_URL"], tc.field: tc.value}
			_, err := Load(input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.field)
			assert.Contains(t, err.Error(), tc.category)
			assert.NotContains(t, err.Error(), "secret")
		})
	}
	_, err = Load(map[string]string{})
	require.ErrorContains(t, err, "CLAVIS_DATABASE_URL")
	for level, expected := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		input := map[string]string{"CLAVIS_DATABASE_URL": base["CLAVIS_DATABASE_URL"], "CLAVIS_LOG_LEVEL": level, "CLAVIS_HTTP_ADDR": "127.0.0.1:0"}
		cfg, err := Load(input)
		require.NoError(t, err)
		assert.Equal(t, expected, cfg.Level())
	}
}

func TestAuthenticationConfigurationAndLazyBootstrap(t *testing.T) {
	base := map[string]string{"CLAVIS_DATABASE_URL": "postgres://local@127.0.0.1/clavis",
		"CLAVIS_BOOTSTRAP_USERNAME":      "OBSOLETE INVALID USER",
		"CLAVIS_BOOTSTRAP_PASSWORD_FILE": "/obsolete/unreadable"}
	cfg, err := Load(base)
	require.NoError(t, err)
	require.Equal(t, 8*time.Hour, cfg.SessionTTL)
	require.Equal(t, base["CLAVIS_BOOTSTRAP_USERNAME"], cfg.BootstrapUsername)
	for _, value := range []string{"4m", "25h", "secret", "0"} {
		base["CLAVIS_SESSION_TTL"] = value
		_, err := Load(base)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "secret")
	}
	delete(base, "CLAVIS_SESSION_TTL")
	for _, value := range []string{"5m", "24h"} {
		base["CLAVIS_SESSION_TTL"] = value
		_, err := Load(base)
		require.NoError(t, err)
	}
	delete(base, "CLAVIS_SESSION_TTL")
	base["CLAVIS_HTTP_ADDR"] = "0.0.0.0:8080"
	_, err = Load(base)
	require.Error(t, err)
	base["CLAVIS_PUBLIC_URL"] = "http://127.0.0.1:8080"
	_, err = Load(base)
	require.Error(t, err)
	base["CLAVIS_PUBLIC_URL"] = "https://clavis.example"
	_, err = Load(base)
	require.NoError(t, err)
}

func TestCanonicalOriginAndBoundPort(t *testing.T) {
	for input, want := range map[string]string{
		"https://Clavis.Example:443/": "https://clavis.example",
		"http://127.0.0.1:80":         "http://127.0.0.1",
		"http://[::1]:1234":           "http://[::1]:1234",
		"https://[2001:0db8::1]:443":  "https://[2001:db8::1]",
	} {
		got, err := CanonicalOrigin(input)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	for _, input := range []string{"http://localhost", "http://clavis.example", "https://user:secret@clavis.example", "https://clavis.example/path", "https://clavis.example?secret", "https://clavis.example#secret", "https://clavis.example:99999", "https://[fe80::1%25en0]"} {
		_, err := CanonicalOrigin(input)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "secret")
	}
	cfg := Config{HTTPAddr: "127.0.0.1:0"}
	got, err := cfg.ResolvePublicOrigin("127.0.0.1:32123")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:32123", got)
}
