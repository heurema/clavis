package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssetRoutes(t *testing.T) {
	db := &fakeDatabase{ping: func(context.Context) error {
		t.Fatal("asset requests must not query the database")
		return nil
	}}
	handler := Handler(time.Second, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/assets/app.css", 200},
		{"GET", "/assets/htmx.min.js", 200},
		{"GET", "/assets/notices.txt", 200},
		{"HEAD", "/assets/app.css", 200},
		{"POST", "/assets/app.css", 405},
		{"GET", "/assets", 404},
		{"GET", "/assets/", 404},
		{"GET", "/assets/.env", 404},
		{"GET", "/assets/../go.mod", 404},
		{"GET", "/assets/%2e%2e/go.mod", 404},
		{"GET", "/assets/unknown.js", 404},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			assert.Equal(t, tc.status, response.Code)
			if tc.status == http.StatusOK {
				assert.Equal(t, "no-cache", response.Header().Get("Cache-Control"))
				assert.Equal(t, "nosniff", response.Header().Get("X-Content-Type-Options"))
			}
		})
	}
}

func TestInitialDocumentDoesNotCheckDatabase(t *testing.T) {
	db := &fakeDatabase{ping: func(context.Context) error {
		t.Fatal("the setup document must not wait for a database check")
		return errors.New("database unavailable")
	}}
	handler := Handler(time.Second, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, response.Body.String(), "<html")
	assert.Contains(t, response.Body.String(), "Checking your environment")
	assert.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Empty(t, response.Header().Get("X-Clavis-Fragment"))

	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/not-a-page", nil))
	assert.Equal(t, http.StatusNotFound, unknown.Code)
	assert.NotContains(t, unknown.Body.String(), "<html")
}

func TestHTMLReadiness(t *testing.T) {
	for _, ready := range []bool{false, true} {
		var logs bytes.Buffer
		calls := 0
		db := &fakeDatabase{ping: func(ctx context.Context) error {
			calls++
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			assert.WithinDuration(t, time.Now().Add(50*time.Millisecond), deadline, 20*time.Millisecond)
			if ready {
				return nil
			}
			return errors.New("postgres://user:SECRET@database")
		}}
		handler := Handler(50*time.Millisecond, db, slog.New(slog.NewJSONHandler(&logs, nil)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ui/readiness?SECRET", nil))
		assert.Equal(t, 1, calls)
		expected := http.StatusServiceUnavailable
		text := "Database unavailable"
		if ready {
			expected = http.StatusOK
			text = "Your environment is ready"
		}
		assert.Equal(t, expected, response.Code)
		assert.Contains(t, response.Body.String(), text)
		assert.Contains(t, response.Body.String(), `data-readiness-state=`)
		assert.Equal(t, "readiness", response.Header().Get("X-Clavis-Fragment"))
		assert.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		assert.NotContains(t, response.Body.String(), "SECRET")
		assert.NotContains(t, logs.String(), "SECRET")
	}
}

func TestBothReadinessRoutesHonorDeadline(t *testing.T) {
	for _, path := range []string{"/health/ready", "/ui/readiness"} {
		t.Run(path, func(t *testing.T) {
			db := &fakeDatabase{ping: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			}}
			handler := Handler(20*time.Millisecond, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
			start := time.Now()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusServiceUnavailable, response.Code)
			assert.Less(t, time.Since(start), time.Second)
		})
	}
}

func TestJSONIgnoresPresentationHeaders(t *testing.T) {
	for _, tc := range []struct {
		path   string
		ready  bool
		status int
		body   string
	}{
		{"/health/live", false, 200, `{"status":"alive"}`},
		{"/health/ready", true, 200, `{"status":"ready"}`},
		{"/health/ready", false, 503, `{"status":"not_ready","error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Database unavailable"}}`},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			db := &fakeDatabase{ping: func(context.Context) error {
				if tc.ready {
					return nil
				}
				return errors.New("SECRET")
			}}
			handler := Handler(time.Second, db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
			for _, headers := range []http.Header{
				{"Accept": {"text/html"}},
				{"Accept": {"text/html"}, "Hx-Request": {"true"}, "Hx-Target": {"readiness"}, "Hx-Boosted": {"true"}},
			} {
				request := httptest.NewRequest(http.MethodGet, tc.path, nil)
				request.Header = headers
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				assert.Equal(t, tc.status, response.Code)
				assert.JSONEq(t, tc.body, response.Body.String())
				assert.Equal(t, "application/json", response.Header().Get("Content-Type"))
				assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				assert.Empty(t, response.Header().Get("X-Clavis-Fragment"))
			}
		})
	}
}

func TestHTMLRenderFailureDoesNotLogDetails(t *testing.T) {
	var logs bytes.Buffer
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errors.New("SECRET"))
	handler := Handler(time.Second, &fakeDatabase{}, slog.New(slog.NewJSONHandler(&logs, nil)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.Equal(t, "<p>Unable to display this page. Try again.</p>", response.Body.String())
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Contains(t, logs.String(), "WEB_RESPONSE_FAILED")
	assert.NotContains(t, logs.String(), "SECRET")
}
