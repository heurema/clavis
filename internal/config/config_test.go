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
