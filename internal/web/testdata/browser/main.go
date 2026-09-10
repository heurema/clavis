// Render browser fixtures through the real components; no test-only routes ship
// in the server. Run only by the browser harness.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	"github.com/a-h/templ"
	"github.com/heurema/clavis/internal/web"
	switchcomp "github.com/heurema/clavis/internal/web/ui/switch"
)

func main() {
	fixtures := make(map[string]string)
	for name, component := range map[string]templ.Component{
		"ready":       web.Readiness(true),
		"unavailable": web.Readiness(false),
		"switch": switchcomp.Switch(switchcomp.Props{
			ID:         "inserted-appearance",
			Attributes: templ.Attributes{"data-appearance": "true", "aria-label": "Inserted appearance"},
		}),
	} {
		var buffer bytes.Buffer
		if err := component.Render(context.Background(), &buffer); err != nil {
			panic(err)
		}
		fixtures[name] = buffer.String()
	}
	if err := json.NewEncoder(os.Stdout).Encode(fixtures); err != nil {
		panic(err)
	}
}
