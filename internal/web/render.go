package web

import (
	"bytes"
	"io"
	"net/http"

	"github.com/a-h/templ"
)

// Render buffers the entire component before committing its status and body.
// The caller may log a fixed error code, never the returned error's details.
func Render(w http.ResponseWriter, r *http.Request, status int, component templ.Component) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var buffer bytes.Buffer
	if err := component.Render(r.Context(), &buffer); err != nil {
		w.Header().Del("X-Clavis-Fragment")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "<p>Unable to display this page. Try again.</p>")
		return err
	}
	w.WriteHeader(status)
	_, err := w.Write(buffer.Bytes())
	return err
}
