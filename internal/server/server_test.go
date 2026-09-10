package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	for _, tc := range []struct {
		path   string
		ready  bool
		status int
		body   string
	}{
		{"/health/live", false, 200, `{"status":"alive"}`},
		{"/health/ready", true, 200, `{"status":"ready"}`},
		{"/health/ready", false, 503, `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Database unavailable"}}`},
		{"/health/ready", true, 200, `{"status":"ready"}`},
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
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("SECRET", "/health/live", nil))
	assert.NotContains(t, logs.String(), "SECRET")
	assert.Contains(t, logs.String(), `"route":"/health/ready"`)
	assert.Contains(t, logs.String(), `"status":503`)
	assert.Contains(t, logs.String(), `"method":"GET"`)
	assert.Contains(t, logs.String(), `"method":"OTHER"`)
}

func TestReadinessDeadline(t *testing.T) {
	db := &fakeDatabase{ping: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
	handler := Handler(20*time.Millisecond, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	start := time.Now()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/health/ready", nil))
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
		response, err := http.Get("http://" + listener.Addr().String() + "/health/ready")
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
