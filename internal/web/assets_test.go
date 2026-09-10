package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicAssets(t *testing.T) {
	for _, tc := range []struct {
		name, contentType string
	}{
		{"app.css", "text/css; charset=utf-8"},
		{"htmx.min.js", "text/javascript; charset=utf-8"},
		{"notices.txt", "text/plain; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			ServeAsset(response, httptest.NewRequest(http.MethodGet, "/assets/"+tc.name, nil))
			require.Equal(t, http.StatusOK, response.Code)
			expected, err := publicAssets.ReadFile("assets/" + tc.name)
			require.NoError(t, err)
			require.NotEmpty(t, expected)
			assert.Equal(t, expected, response.Body.Bytes())
			assert.Equal(t, tc.contentType, response.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", response.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "no-cache", response.Header().Get("Cache-Control"))
			require.NotEmpty(t, response.Header().Get("ETag"))

			revalidate := httptest.NewRequest(http.MethodGet, "/assets/"+tc.name, nil)
			revalidate.Header.Set("If-None-Match", response.Header().Get("ETag"))
			cached := httptest.NewRecorder()
			ServeAsset(cached, revalidate)
			assert.Equal(t, http.StatusNotModified, cached.Code)
			assert.Empty(t, cached.Body.String())
			assert.Equal(t, "no-cache", cached.Header().Get("Cache-Control"))

			head := httptest.NewRecorder()
			ServeAsset(head, httptest.NewRequest(http.MethodHead, "/assets/"+tc.name, nil))
			assert.Equal(t, http.StatusOK, head.Code)
			assert.Empty(t, head.Body.String())
			assert.Equal(t, response.Header().Get("Content-Length"), head.Header().Get("Content-Length"))
		})
	}
}

func TestAssetBoundary(t *testing.T) {
	for _, path := range []string{
		"/", "/assets", "/assets/", "/assets/.", "/assets/..",
		"/assets//app.css", "/assets/unknown.css", "/assets/app.css/",
		"/assets/../go.mod", "/assets/%2e%2e/go.mod",
		"/assets/.env", "/assets/.git/config", "/assets/node_modules/htmx.org/package.json",
		"/assets/ui/button/button.templ", "/assets/page_templ.go", "/assets/assets.go",
	} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			ServeAsset(response, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusNotFound, response.Code)
			assert.Equal(t, "404 page not found\n", response.Body.String())
		})
	}
}
