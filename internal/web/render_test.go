package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/a-h/templ"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferedRenderingFailure(t *testing.T) {
	sentinel := errors.New("private database connection SECRET")
	component := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, _ = io.WriteString(w, "<p>PARTIAL SECRET</p>")
		return sentinel
	})
	response := httptest.NewRecorder()
	response.Header().Set("X-Clavis-Fragment", "readiness")
	err := Render(response, httptest.NewRequest(http.MethodGet, "/ui/readiness", nil), http.StatusOK, component)
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.Equal(t, "<p>Unable to display this page. Try again.</p>", response.Body.String())
	assert.NotContains(t, response.Body.String(), "SECRET")
	assert.Empty(t, response.Header().Get("X-Clavis-Fragment"))
	assert.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", response.Header().Get("X-Content-Type-Options"))
}

func TestRendererUsesRequestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	component := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		return ctx.Err()
	})
	response := httptest.NewRecorder()
	err := Render(response, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx), http.StatusOK, component)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, http.StatusInternalServerError, response.Code)
}

func TestReadinessRendering(t *testing.T) {
	for _, ready := range []bool{true, false} {
		status := http.StatusServiceUnavailable
		heading := "Database unavailable"
		if ready {
			status = http.StatusOK
			heading = "Your environment is ready"
		}
		response := httptest.NewRecorder()
		response.Header().Set("X-Clavis-Fragment", "readiness")
		require.NoError(t, Render(response, httptest.NewRequest(http.MethodGet, "/ui/readiness", nil), status, Readiness(ready)))
		assert.Equal(t, status, response.Code)
		assert.Contains(t, response.Body.String(), heading)
		assert.Contains(t, response.Body.String(), `id="readiness"`)
		assert.Equal(t, "readiness", response.Header().Get("X-Clavis-Fragment"))
		assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	}
}

func TestPageAssetsAreEmbedded(t *testing.T) {
	response := httptest.NewRecorder()
	require.NoError(t, Render(response, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, Page()))
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, response.Body.String(), "<!doctype html>")
	assert.Contains(t, response.Body.String(), `<html lang="en">`)
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	references := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`).FindAllStringSubmatch(response.Body.String(), -1)
	require.Len(t, references, 3)
	for _, reference := range references {
		asset := httptest.NewRecorder()
		ServeAsset(asset, httptest.NewRequest(http.MethodGet, reference[1], nil))
		assert.Equal(t, http.StatusOK, asset.Code, reference[1])
		assert.NotEmpty(t, asset.Body.String())
	}
}
