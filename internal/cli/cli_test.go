package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func invoke(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := Run(context.Background(), append([]string{"clavis"}, args...), &out)
	return code, out.String()
}

func decode(t *testing.T, output string) Result {
	t.Helper()
	var value Result
	decoder := json.NewDecoder(strings.NewReader(output))
	require.NoError(t, decoder.Decode(&value))
	var extra any
	require.ErrorIs(t, decoder.Decode(&extra), io.EOF)
	assert.Equal(t, 1, value.SchemaVersion)
	return value
}

func TestOfflineAndInvalidCommands(t *testing.T) {
	t.Setenv("CLAVIS_SERVER_URL", "http://SECRET.invalid")
	for _, args := range [][]string{{"help"}, {"--help"}, {"doctor", "--help"}, {}} {
		code, out := invoke(t, args...)
		assert.Zero(t, code)
		assert.Contains(t, out, "clavis")
		assert.NotContains(t, out, "SECRET")
	}
	code, out := invoke(t, "version")
	assert.Zero(t, code)
	result := decode(t, out)
	assert.True(t, result.OK)
	assert.Nil(t, result.Error)
	assert.Contains(t, out, `"version":"dev"`)
	code, out = invoke(t, "version", "--output=text")
	assert.Zero(t, code)
	assert.Contains(t, out, "clavis dev")
	for _, args := range [][]string{
		{"SECRET"}, {"--SECRET"}, {"version", "SECRET"}, {"doctor", "SECRET"},
		{"version", "--output=SECRET"}, {"--output=text", "version", "--SECRET"},
		{"doctor", "--timeout=SECRET"}, {"doctor", "--timeout=0"}, {"doctor", "--timeout=-1s"},
		{"doctor", "--server=postgres://SECRET"}, {"doctor", "--server=http://user:SECRET@host"},
		{"doctor", "--output=text", "--server=postgres://SECRET"},
		{"doctor", "--server=http://host?SECRET"}, {"doctor", "--server=http://host#SECRET"},
		{"doctor", "--server=http://"}, {"doctor", "--server=http://host?"},
		{"doctor", "--server=http://127.0.0.1:65536"},
		{"doctor", "--output=text", "--server=http://127.0.0.1:999999999999999999999999"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out := invoke(t, args...)
			assert.Equal(t, 2, code)
			result := decode(t, out)
			require.NotNil(t, result.Error)
			assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
			assert.False(t, result.OK)
			assert.Nil(t, result.Data)
			assert.NotContains(t, out, "SECRET")
		})
	}
}

func TestDoctorResponses(t *testing.T) {
	for _, tc := range []struct {
		name                string
		status              int
		body                string
		exit                int
		code, api, database string
	}{
		{"ready", 200, `{"status":"ready"}`, 0, "", "reachable", "ready"},
		{"exact-body-limit", 200, `{"status":"ready"}` + strings.Repeat(" ", maxResponseBytes-len(`{"status":"ready"}`)), 0, "", "reachable", "ready"},
		{"one-byte-over-limit", 200, `{"status":"ready"}` + strings.Repeat(" ", maxResponseBytes-len(`{"status":"ready"}`)+1), 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"unavailable", 503, `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"SECRET"}}`, 1, "DEPENDENCY_UNAVAILABLE", "reachable", "unavailable"},
		{"bad-json", 200, `SECRET`, 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"wrong-status", 500, `{"status":"ready"}`, 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"mismatch", 200, `{"status":"not_ready"}`, 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"wrong-error", 503, `{"status":"not_ready","error":{"code":"SECRET"}}`, 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"oversized", 200, strings.Repeat("SECRET", maxResponseBytes), 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"trailing-json", 200, `{"status":"ready"}{}`, 1, "INVALID_RESPONSE", "reachable", "unknown"},
		{"contradictory", 200, `{"status":"ready","error":{"code":"SECRET"}}`, 1, "INVALID_RESPONSE", "reachable", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/health/ready", r.URL.Path)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			for _, format := range []string{"json", "text"} {
				code, out := invoke(t, "doctor", "--server", server.URL, "--output", format)
				assert.Equal(t, tc.exit, code)
				assert.NotContains(t, out, "SECRET")
				if format == "text" {
					assert.Contains(t, out, "API: "+tc.api)
					assert.Contains(t, out, "Database: "+tc.database)
					continue
				}
				result := decode(t, out)
				assert.Equal(t, map[string]any{"api": tc.api, "database": tc.database}, result.Data)
				if tc.code != "" {
					require.NotNil(t, result.Error)
					assert.Equal(t, tc.code, result.Error.Code)
				} else {
					assert.True(t, result.OK)
				}
			}
		})
	}
}

func TestDeadlineIncludesBodyAndNoRedirect(t *testing.T) {
	for _, flush := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if flush {
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
			}
			<-r.Context().Done()
		}))
		start := time.Now()
		result := Doctor(context.Background(), server.URL, 30*time.Millisecond)
		require.NotNil(t, result.Error)
		assert.Equal(t, "TIMEOUT", result.Error.Code)
		assert.Equal(t, Diagnosis{"unknown", "unknown"}, result.Data)
		assert.Less(t, time.Since(start), time.Second)
		server.Close()
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1", http.StatusFound)
	}))
	defer server.Close()
	result := Doctor(context.Background(), server.URL, time.Second)
	require.NotNil(t, result.Error)
	assert.Equal(t, "INVALID_RESPONSE", result.Error.Code)
}

func TestUnreachableAndURLPrecedence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	url := "http://" + listener.Addr().String()
	require.NoError(t, listener.Close())
	result := Doctor(context.Background(), url, time.Second)
	require.NotNil(t, result.Error)
	assert.Equal(t, "SERVER_UNREACHABLE", result.Error.Code)
	assert.Equal(t, Diagnosis{"unreachable", "unknown"}, result.Data)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"status":"ready"}`) }))
	defer server.Close()
	t.Setenv("CLAVIS_SERVER_URL", server.URL)
	code, out := invoke(t, "doctor")
	assert.Zero(t, code)
	assert.True(t, decode(t, out).OK)
	t.Setenv("CLAVIS_SERVER_URL", "SECRET")
	code, out = invoke(t, "doctor", "--server", server.URL)
	assert.Zero(t, code)
	assert.True(t, decode(t, out).OK)
	code, out = invoke(t, "doctor")
	assert.Equal(t, 2, code)
	assert.NotContains(t, out, "SECRET")
}
