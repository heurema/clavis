# templUI components

Button, Card, Badge, Alert, Switch and the selected utility functions are copied
from [templUI v1.13.2](https://github.com/templui/templui/tree/75ff269e4b13e65e2ebc973835dea91e1112cca1),
resolved revision `75ff269e4b13e65e2ebc973835dea91e1112cca1`.
The upstream v1 module is `github.com/templui/templui`; a repository redirect to
shadcn-templ does not change this source baseline. The MIT license is retained in
`licenses/templui.txt`.

| Local source | Upstream source at that revision |
| --- | --- |
| `button/button.templ` | `components/button/button.templ` |
| `card/card.templ` | `components/card/card.templ` |
| `badge/badge.templ` | `components/badge/badge.templ` |
| `alert/alert.templ` | `components/alert/alert.templ` |
| `switch/switch.templ` | `components/switch/switch.templ` |
| `utils/templui.go` | `utils/templui.go` |
| `icon/icon.templ` | Selected paths from `components/icon/icon_data.go` |

Local modifications:

- Rewrite utility imports to `github.com/heurema/clavis/internal/web/ui/utils`.
- Retain only `TwMerge`, `If` and `RandomID` from the utilities. The class merger
  retains the upstream `github.com/Oudwins/tailwind-merge-go` v0.2.0 dependency;
  its MIT license is in `licenses/tailwind-merge-go.txt`.
- Use `peer sr-only` instead of `peer hidden` for the Switch input, preserving
  native checkbox focus and Space activation. Application-level Enter handling
  and appearance persistence belong to the later browser implementation.
- Convert only the seven setup-page icons to typed templ components, retaining
  their SVG paths. Dynamic classes use templ escaping instead of upstream string
  interpolation; decorative icons are hidden from assistive technology. No
  runtime icon registry, SVG-string cache or icon JavaScript is imported.
- Regenerate Go output with the application's pinned templ v0.3.1020 compiler.

The five selected controls have **no component JavaScript or transitive component
dependencies** in this snapshot. The Switch uses a native checkbox and CSS peer
selectors. There are consequently no templUI scripts to copy or initialize.
Do not import the upstream all-components script router or unrelated controls.

## Lucide icons

The templUI snapshot identifies its icon data as Lucide **0.576.0**. Clavis copies
`arrow-right`, `database`, `key-round`, `refresh-cw`, `server`, `square-terminal`
and `loader-circle` from that snapshot. The upstream ISC and Feather MIT notices
are retained in `licenses/lucide.txt`.

## Ownership

These are maintained local copies, not a runtime dependency on templUI. Component
updates are explicit: compare this revision with the selected new revision,
review local modifications and license changes, regenerate Go, and rerun
component/browser checks. Routine setup and builds never fetch component source.
The notices and license files are source inputs for the embedded asset build.
