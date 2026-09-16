package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/buildinfo"
	"github.com/heurema/clavis/internal/config"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDatabase struct {
	ping   func(context.Context) error
	closed chan struct{}
}

func (d *fakeDatabase) Ping(ctx context.Context) error { return d.ping(ctx) }
func (d *fakeDatabase) Check(ctx context.Context) platform.Readiness {
	if d.Ping(ctx) == nil {
		return platform.Readiness{State: platform.Ready}
	}
	return platform.Readiness{State: platform.DependencyUnavailable}
}
func (d *fakeDatabase) Close() {
	if d.closed != nil {
		close(d.closed)
	}
}

type closeOnlyDatabase struct{}

func (*closeOnlyDatabase) Close() {}

func TestCloseOnlyDatabaseFailsClosedWithoutChecker(t *testing.T) {
	db := &closeOnlyDatabase{}
	handler := Handler(time.Second, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	require.Equal(t, 503, response.Code)
	require.Contains(t, response.Body.String(), platform.CodeDependencyUnavailable)
}

func TestHealthAndRedaction(t *testing.T) {
	var logs bytes.Buffer
	var available atomic.Bool
	db := &fakeDatabase{ping: func(context.Context) error {
		if available.Load() {
			return nil
		}
		return errors.New("postgres://user:SECRET@database")
	}}
	handler := Handler(50*time.Millisecond, db, slog.New(slog.NewJSONHandler(&logs, nil)))
	const notReady = `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Database unavailable"}}`
	version := buildinfo.Current().Version
	for _, tc := range []struct {
		path   string
		ready  bool
		status int
		body   string
	}{
		{"/livez", false, 200, `{"status":"alive"}`},
		{"/readyz", true, 200, `{"status":"ready"}`},
		{"/readyz", false, 503, notReady},
		{"/readyz", true, 200, `{"status":"ready"}`},
		{"/healthz", true, 200, fmt.Sprintf(`{"status":"ok","version":%q,"checks":{"live":{"status":"alive"},"ready":{"status":"ready"}}}`, version)},
		{"/healthz", false, 503, fmt.Sprintf(`{"status":"unhealthy","version":%q,"checks":{"live":{"status":"alive"},"ready":%s}}`, version, notReady)},
	} {
		available.Store(tc.ready)
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", tc.path+"?token=SECRET", strings.NewReader("SECRET"))
		handler.ServeHTTP(response, request)
		assert.Equal(t, tc.status, response.Code)
		assert.JSONEq(t, tc.body, response.Body.String())
		assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		assert.Equal(t, "application/json", response.Header().Get("Content-Type"))
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/SECRET", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("SECRET", "/livez", nil))
	assert.NotContains(t, logs.String(), "SECRET")
	assert.Contains(t, logs.String(), `"route":"/readyz"`)
	assert.Contains(t, logs.String(), `"status":503`)
	assert.Contains(t, logs.String(), `"method":"GET"`)
	assert.Contains(t, logs.String(), `"method":"OTHER"`)
	assert.Contains(t, logs.String(), `"route":"/healthz"`)
}

// The startup entry is where an operator reads the build identity; the health
// bodies carry at most the version.
func TestStartupLogCarriesBuildIdentity(t *testing.T) {
	var logs bytes.Buffer
	db := &fakeDatabase{ping: func(context.Context) error { return nil }}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, config.Config{DBCheckTimeout: time.Second, ShutdownTimeout: time.Second}, db, slog.New(slog.NewJSONHandler(&logs, nil)))
	}()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown exceeded bound")
	}
	build := buildinfo.Current()
	assert.Contains(t, logs.String(), fmt.Sprintf(`"msg":"server_started","version":%q,"commit":%q,"date":%q`, build.Version, build.Commit, build.Date))
}

func TestReadinessDeadline(t *testing.T) {
	db := &fakeDatabase{ping: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
	handler := Handler(20*time.Millisecond, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	start := time.Now()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	assert.Equal(t, 503, response.Code)
	assert.Less(t, time.Since(start), time.Second)
}

func TestShutdownCancelsBlockedRequest(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	db := &fakeDatabase{closed: make(chan struct{}), ping: func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, config.Config{DBCheckTimeout: time.Minute, ShutdownTimeout: 50 * time.Millisecond}, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, err := http.Get("http://" + listener.Addr().String() + "/readyz")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request never reached database")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown exceeded bound")
	}
	assert.Less(t, time.Since(start), 300*time.Millisecond)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("request was not canceled")
	}
	select {
	case <-db.closed:
	case <-time.After(time.Second):
		t.Fatal("database was not closed")
	}
	<-clientDone
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err)
}
