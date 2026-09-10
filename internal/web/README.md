# Go web foundation

The templUI foundation is being added alongside the existing React page. It is
not mounted on the server yet.

## Source ownership

- `.templ` files are maintained source. Commit them with their generated
  `*_templ.go` companions; never hand-edit generated Go.
- `make generate-web` explicitly regenerates the Go files using the compiler
  version pinned by the runtime requirement in `go.mod`.
- `make check-web-generated` verifies generation and template formatting without
  changing source. `make check` runs this check and its failure-path tests.
- `make format` formats maintained Go/templates and explicitly regenerates Go.
- `ui/` contains only selected, locally maintained upstream components. See
  `ui/THIRD_PARTY_NOTICES.md` for provenance, licenses and modifications.
- `testdata/composition.templ` is a render-only compatibility fixture, not a
  product page or server route.

`assets/` and `.assets-*/` are reserved, ignored distribution/staging directories.
The next migration stage will populate them from pinned local inputs and embed
only the finished public distribution. Do not put source, configuration, secrets,
or manually maintained files in those directories.
