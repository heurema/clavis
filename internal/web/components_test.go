package web_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/heurema/clavis/internal/web/testdata"
	"github.com/heurema/clavis/internal/web/ui/icon"
	"github.com/stretchr/testify/require"
)

func TestComponentComposition(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, testdata.Composition("<script>private & unsafe</script>").Render(t.Context(), &output))
	html := output.String()
	for _, expected := range []string{
		`id="component-fixture"`,
		`role="alert"`,
		`id="retry"`,
		`type="button"`,
		`hx-get="/ui/readiness"`,
		`Check again`,
		`id="appearance"`,
		`class="peer sr-only"`,
		`role="switch"`,
		`aria-label="Dark appearance"`,
		`&lt;script&gt;private &amp; unsafe&lt;/script&gt;`,
	} {
		require.Contains(t, html, expected)
	}
	require.NotContains(t, html, "<script")
	require.NotContains(t, html, `class="peer hidden"`)
}

func TestIconsEscapeDynamicClasses(t *testing.T) {
	for name, component := range map[string]func(...icon.Props) templ.Component{
		"arrow-right":     icon.ArrowRight,
		"database":        icon.Database,
		"key-round":       icon.KeyRound,
		"refresh-cw":      icon.RefreshCw,
		"server":          icon.Server,
		"square-terminal": icon.SquareTerminal,
		"loader-circle":   icon.LoaderCircle,
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, component(icon.Props{Class: `" onload="unsafe`}).Render(t.Context(), &output))
			html := output.String()
			require.Equal(t, 1, strings.Count(html, "<svg"))
			require.Contains(t, html, `aria-hidden="true"`)
			require.Contains(t, html, `focusable="false"`)
			require.NotContains(t, html, `" onload="`)
		})
	}
}
