package config

import (
	"log/slog"
	"maps"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	base := map[string]string{"CLAVIS_DATABASE_URL": "postgres://local:secret@127.0.0.1:5432/clavis", "CLAVIS_ENCRYPTION_KEY_FILE": "/private/secret-key"}
	cfg, err := Load(base)
	require.NoError(t, err)
	assert.Equal(t, "/private/secret-key", cfg.EncryptionKeyFile)
	assert.Nil(t, cfg.Keys, "Load validates the setting; the entry point loads the key")
	// The key file is required and must be absolute; Load never opens it.
	for _, tc := range []struct{ value, category string }{{"", "REQUIRED"}, {"relative/secret-key", "INVALID_PATH"}} {
		_, err := Load(map[string]string{"CLAVIS_DATABASE_URL": base["CLAVIS_DATABASE_URL"], "CLAVIS_ENCRYPTION_KEY_FILE": tc.value})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CLAVIS_ENCRYPTION_KEY_FILE")
		assert.Contains(t, err.Error(), tc.category)
		assert.NotContains(t, err.Error(), "secret")
	}
	cfg, err = Load(base)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8080", cfg.HTTPAddr)
	assert.Equal(t, 2*time.Second, cfg.DBCheckTimeout)
	assert.Equal(t, 10*time.Second, cfg.ShutdownTimeout)
	assert.Equal(t, slog.LevelInfo, cfg.Level())
	_, err = Load(map[string]string{"CLAVIS_DATABASE_URL": "postgresql://local:secret@127.0.0.1/clavis", "CLAVIS_HTTP_ADDR": "127.0.0.1:65535", "CLAVIS_ENCRYPTION_KEY_FILE": "/private/secret-key"})
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
		{"CLAVIS_HTTP_ADDR", "127.0.0.1:-0", "INVALID_PORT"},
		{"CLAVIS_HTTP_ADDR", "127.0.0.1:+80", "INVALID_PORT"},
		{"CLAVIS_HTTP_ADDR", "127.0.0.1:secret", "INVALID_PORT"},
		{"CLAVIS_DB_CHECK_TIMEOUT", "secret", "INVALID_DURATION"},
		{"CLAVIS_SHUTDOWN_TIMEOUT", "secret", "INVALID_DURATION"},
		{"CLAVIS_DB_CHECK_TIMEOUT", "0", "MUST_BE_POSITIVE"},
		{"CLAVIS_DB_CHECK_TIMEOUT", "-1s", "MUST_BE_POSITIVE"},
		{"CLAVIS_SHUTDOWN_TIMEOUT", "0s", "MUST_BE_POSITIVE"},
		{"CLAVIS_LOG_LEVEL", "secret", "INVALID_LEVEL"},
	} {
		t.Run(tc.field+"/"+tc.value, func(t *testing.T) {
			input := map[string]string{"CLAVIS_DATABASE_URL": base["CLAVIS_DATABASE_URL"], "CLAVIS_ENCRYPTION_KEY_FILE": base["CLAVIS_ENCRYPTION_KEY_FILE"], tc.field: tc.value}
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
		input := map[string]string{"CLAVIS_DATABASE_URL": base["CLAVIS_DATABASE_URL"], "CLAVIS_ENCRYPTION_KEY_FILE": base["CLAVIS_ENCRYPTION_KEY_FILE"], "CLAVIS_LOG_LEVEL": level, "CLAVIS_HTTP_ADDR": "127.0.0.1:0"}
		cfg, err := Load(input)
		require.NoError(t, err)
		assert.Equal(t, expected, cfg.Level())
	}
}

func TestAuthenticationConfigurationAndLazyBootstrap(t *testing.T) {
	base := map[string]string{"CLAVIS_DATABASE_URL": "postgres://local@127.0.0.1/clavis",
		"CLAVIS_ENCRYPTION_KEY_FILE":     "/private/secret-key",
		"CLAVIS_BOOTSTRAP_USERNAME":      "OBSOLETE INVALID USER",
		"CLAVIS_BOOTSTRAP_PASSWORD_FILE": "/obsolete/unreadable"}
	cfg, err := Load(base)
	require.NoError(t, err)
	require.Equal(t, 168*time.Hour, cfg.SessionIdleTimeout)
	require.Equal(t, 720*time.Hour, cfg.SessionMaxLifetime)
	require.Equal(t, base["CLAVIS_BOOTSTRAP_USERNAME"], cfg.BootstrapUsername)
	const idle, lifetime = "CLAVIS_SESSION_IDLE_TIMEOUT", "CLAVIS_SESSION_MAX_LIFETIME"
	for _, tc := range []struct{ idle, lifetime, field string }{
		{"240h", "168h", idle},       // idle above the lifetime
		{"4m", "", idle},             // idle below 5m
		{"4m59s", "4m59s", idle},     // both below 5m: the idle value is named first
		{"2161h", "", idle},          // idle above 2160h
		{"secret", "", idle},         // unparseable, never echoed
		{"0", "", idle},              // zero
		{"", "2161h", lifetime},      // lifetime above 2160h
		{"5m", "4m", lifetime},       // lifetime below 5m
		{"", "secret", lifetime},     // unparseable, never echoed
		{"721h", "", idle},           // above the default lifetime
		{"", "167h", idle},           // below the default idle timeout
		{"2160h", "2159h", idle},     // both within bounds, idle above lifetime
		{"-5m", "", idle},            // negative
		{"", "-720h", lifetime},      // negative
		{"1h", "2160h1ms", lifetime}, // just above the bound
	} {
		input := maps.Clone(base)
		if tc.idle != "" {
			input[idle] = tc.idle
		}
		if tc.lifetime != "" {
			input[lifetime] = tc.lifetime
		}
		_, err := Load(input)
		var failure *Error
		require.ErrorAs(t, err, &failure, "%+v", tc)
		require.Equal(t, Error{tc.field, "INVALID_DURATION"}, *failure, "%+v", tc)
		require.NotContains(t, err.Error(), "secret")
	}
	for _, tc := range []struct{ idle, lifetime string }{{"5m", "5m"}, {"2160h", "2160h"}, {"1h", "1h"}, {"168h", "720h"}} {
		input := maps.Clone(base)
		input[idle], input[lifetime] = tc.idle, tc.lifetime
		loaded, err := Load(input)
		require.NoError(t, err, "%+v", tc)
		want, _ := time.ParseDuration(tc.idle)
		require.Equal(t, want, loaded.SessionIdleTimeout)
		want, _ = time.ParseDuration(tc.lifetime)
		require.Equal(t, want, loaded.SessionMaxLifetime)
	}
	// The removed fixed lifetime is not read: any value is ignored.
	base["CLAVIS_SESSION_TTL"] = "not a duration"
	cfg, err = Load(base)
	require.NoError(t, err)
	require.Equal(t, 168*time.Hour, cfg.SessionIdleTimeout)
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

func TestPublicOriginConfiguration(t *testing.T) {
	for _, tc := range []struct {
		address, publicURL, want, code string
	}{
		{"127.0.0.1:0", "http://127.0.0.1:0", "", "INVALID_ORIGIN"},
		{"127.0.0.1:0", "https://clavis.example:000", "", "INVALID_ORIGIN"},
		{"[::1]:0", "http://[::1]:0", "", "INVALID_ORIGIN"},
		{"127.0.0.1:0", "https://secret.example:", "", "INVALID_ORIGIN"},
		{"127.0.0.1:0", "http://[::ffff:127.0.0.1]", "http://[::ffff:127.0.0.1]", ""},
		{"127.0.0.1:0", "http://[::ffff:192.0.2.1]", "", "INVALID_ORIGIN"},
		{"127.0.0.1:0", "https://[::ffff:127.0.0.1]:443", "https://[::ffff:127.0.0.1]", ""},
		{"0.0.0.0:0", "", "", "REQUIRED"},
		{"[::]:0", "", "", "REQUIRED"},
		{"[::ffff:192.0.2.1]:0", "", "", "REQUIRED"},
		{"localhost:0", "", "", "REQUIRED"},
		{"0.0.0.0:0", "http://127.0.0.1:8080", "", "HTTPS_REQUIRED"},
		{"0.0.0.0:0", "http://[::ffff:127.0.0.1]", "", "HTTPS_REQUIRED"},
		{"[::]:0", "http://[::1]:8080", "", "HTTPS_REQUIRED"},
		{"[::ffff:192.0.2.1]:0", "http://127.0.0.1", "", "HTTPS_REQUIRED"},
		{"0.0.0.0:0", "http://secret.example", "", "INVALID_ORIGIN"},
		{"0.0.0.0:0", "https://Clavis.Example:0443/", "https://clavis.example", ""},
		{"[::]:0", "https://[2001:0db8::1]:00444", "https://[2001:db8::1]:444", ""},
	} {
		t.Run(tc.address+"/"+tc.publicURL, func(t *testing.T) {
			input := map[string]string{
				"CLAVIS_DATABASE_URL":        "postgres://local@127.0.0.1/clavis",
				"CLAVIS_ENCRYPTION_KEY_FILE": "/private/secret-key",
				"CLAVIS_HTTP_ADDR":           tc.address,
				"CLAVIS_PUBLIC_URL":          tc.publicURL,
			}
			cfg, err := Load(input)
			if tc.code != "" {
				require.Equal(t, &Error{"CLAVIS_PUBLIC_URL", tc.code}, err)
				require.NotContains(t, err.Error(), "secret")
				_, err = (Config{PublicURL: tc.publicURL}).ResolvePublicOrigin(tc.address)
				require.Equal(t, &Error{"CLAVIS_PUBLIC_URL", tc.code}, err)
				return
			}
			require.NoError(t, err)
			got, err := cfg.ResolvePublicOrigin(tc.address)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestEphemeralLoopbackOriginAfterBind(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0", "[::ffff:127.0.0.1]:0"} {
		t.Run(address, func(t *testing.T) {
			cfg, err := Load(map[string]string{
				"CLAVIS_DATABASE_URL":        "postgres://local@127.0.0.1/clavis",
				"CLAVIS_ENCRYPTION_KEY_FILE": "/private/secret-key",
				"CLAVIS_HTTP_ADDR":           address,
			})
			require.NoError(t, err, "port zero must be accepted before binding")
			_, err = cfg.ResolvePublicOrigin(address)
			require.Error(t, err, "port zero cannot be published as an actual origin")
			listener, err := net.Listen("tcp", cfg.HTTPAddr)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, listener.Close()) })
			bound := listener.Addr().(*net.TCPAddr)
			require.Positive(t, bound.Port)
			got, err := cfg.ResolvePublicOrigin(bound.String())
			require.NoError(t, err)
			require.Equal(t, "http://"+bound.String(), got)
		})
	}
	cfg := Config{}
	got, err := cfg.ResolvePublicOrigin("[::ffff:127.0.0.1]:32123")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:32123", got)
}
