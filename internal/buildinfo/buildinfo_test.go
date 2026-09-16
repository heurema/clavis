package buildinfo

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

// reader returns a build-information reader for one fabricated build, so no
// case depends on how this test binary itself was compiled.
func reader(version string, settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main:     debug.Module{Path: "github.com/heurema/clavis", Version: version},
			Settings: settings,
		}, true
	}
}

func setting(key, value string) debug.BuildSetting {
	return debug.BuildSetting{Key: key, Value: value}
}

func TestResolve(t *testing.T) {
	checkout := []debug.BuildSetting{
		setting("vcs", "git"),
		setting("vcs.revision", "5121b0cd463e8fd86d898e0a8df5e628b7a62ce3"),
		setting("vcs.time", "2026-09-16T14:31:19Z"),
		setting("vcs.modified", "true"),
	}
	pseudo := "v0.1.0-rc.1.0.20260916143119-5121b0cd463e+dirty"

	for _, tc := range []struct {
		name                  string
		version, commit, date string
		read                  func() (*debug.BuildInfo, bool)
		want                  Info
	}{
		{
			// A release build: the linker supplied everything, and the
			// toolchain's own values never override it.
			name:    "stamped build wins over build information",
			version: "v1.2.3", commit: "abc", date: "2026-09-16T00:00:00Z",
			read: reader(pseudo, checkout...),
			want: Info{Version: "v1.2.3", Commit: "abc", Date: "2026-09-16T00:00:00Z"},
		},
		{
			// go install at a tag: the proxy records the module version and no
			// VCS settings, so the version is truthful and the rest is not known.
			name:    "module proxy install reports the tag",
			version: "dev", commit: "unknown", date: "unknown",
			read: reader("v0.1.0-rc.1"),
			want: Info{Version: "v0.1.0-rc.1", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "checkout build reports the pseudo-version, revision and commit time",
			version: "dev", commit: "unknown", date: "unknown",
			read: reader(pseudo, checkout...),
			want: Info{
				Version: pseudo,
				Commit:  "5121b0cd463e8fd86d898e0a8df5e628b7a62ce3",
				Date:    "2026-09-16T14:31:19Z",
			},
		},
		{
			// A test binary and a source export both land here: the toolchain
			// answers, but has no version for the module and no VCS settings.
			// This is what keeps the CLI's own version test asserting dev.
			name:    "development build stays unknown",
			version: "dev", commit: "unknown", date: "unknown",
			read: reader(devel),
			want: Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "empty module version is treated as absent",
			version: "dev", commit: "unknown", date: "unknown",
			read: reader(""),
			want: Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			// No build information at all, which the toolchain reports for a
			// binary it did not stamp.
			name:    "unreadable build information leaves the defaults",
			version: "dev", commit: "unknown", date: "unknown",
			read: func() (*debug.BuildInfo, bool) { return nil, false },
			want: Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "a nil build information is not read",
			version: "dev", commit: "unknown", date: "unknown",
			read: func() (*debug.BuildInfo, bool) { return nil, true },
			want: Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			// The three values are independent: a stamped version keeps its
			// place while the commit and date come from the checkout.
			name:    "stamped version beside a derived commit and date",
			version: "v1.2.3", commit: "unknown", date: "unknown",
			read: reader(pseudo, checkout...),
			want: Info{
				Version: "v1.2.3",
				Commit:  "5121b0cd463e8fd86d898e0a8df5e628b7a62ce3",
				Date:    "2026-09-16T14:31:19Z",
			},
		},
		{
			// The mirror of the case above: a stamped commit and date survive a
			// checkout that would otherwise supply both, which is what makes
			// the precedence rule hold for all three fields and not just one.
			name:    "stamped commit and date beside a derived version",
			version: "dev", commit: "abc", date: "2026-09-16T00:00:00Z",
			read: reader(pseudo, checkout...),
			want: Info{Version: pseudo, Commit: "abc", Date: "2026-09-16T00:00:00Z"},
		},
		{
			// An empty setting value is no better than an absent one.
			name:    "empty vcs settings leave the defaults",
			version: "dev", commit: "unknown", date: "unknown",
			read: reader(devel, setting("vcs.revision", ""), setting("vcs.time", "")),
			want: Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			// `make build-cli VERSION=` stamps an empty string, which is no
			// identity at all: it falls back rather than reporting nothing.
			name:    "an empty linker value is not an identity",
			version: "", commit: "", date: "",
			read: reader(pseudo, checkout...),
			want: Info{
				Version: pseudo,
				Commit:  "5121b0cd463e8fd86d898e0a8df5e628b7a62ce3",
				Date:    "2026-09-16T14:31:19Z",
			},
		},
		{
			// And with nothing to fall back to it reports the default, so an
			// empty field never reaches a startup log or an operator.
			name:    "an empty linker value with no build information",
			version: "", commit: "", date: "",
			read: func() (*debug.BuildInfo, bool) { return nil, false },
			want: Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolve(tc.version, tc.commit, tc.date, tc.read))
		})
	}
}

// A fully stamped build answers without consulting the toolchain at all.
func TestResolveSkipsTheReaderWhenEverythingIsStamped(t *testing.T) {
	read := func() (*debug.BuildInfo, bool) {
		t.Fatal("build information was read for a fully stamped build")
		return nil, false
	}
	assert.Equal(t,
		Info{Version: "v1.2.3", Commit: "abc", Date: "2026-09-16T00:00:00Z"},
		resolve("v1.2.3", "abc", "2026-09-16T00:00:00Z", read))
}

// Current is what every reader calls; under test it is the development build.
func TestCurrentIsStableAndReportsTheTestBinary(t *testing.T) {
	first := Current()
	assert.Equal(t, first, Current(), "the identity is resolved once")
	assert.Equal(t, "dev", first.Version)
	assert.Equal(t, "unknown", first.Commit)
	assert.Equal(t, "unknown", first.Date)
}
