// Package buildinfo reports which build of Clavis is running. Release builds
// stamp the three values with -ldflags; a build without them falls back to the
// identity the Go toolchain embeds, so an installation from a module proxy
// still reports the version it was installed at.
package buildinfo

import (
	"runtime/debug"
	"sync"
)

// Set by release builds with -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// The value each field keeps when neither the linker nor the toolchain supplied
// one. They double as the sentinels that mark a field as unstamped, which is
// why a release must never stamp them literally.
const (
	unknownVersion = "dev"
	unknownValue   = "unknown"
)

// devel is the main module version of a build the toolchain has no version
// for, such as a test binary. It is not an identity and never becomes one.
const devel = "(devel)"

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

var (
	once    sync.Once
	current Info
)

// Current is the resolved identity every reader uses. It is computed once:
// nothing about the running executable can change it.
func Current() Info {
	once.Do(func() { current = resolve(Version, Commit, Date, debug.ReadBuildInfo) })
	return current
}

// resolve fills each value the linker left at its default from the toolchain's
// embedded build information. A stamped value always wins, and the three are
// independent, so a build may carry a stamped version beside a derived commit.
// The reader is a parameter so a test never depends on how it was built itself.
func resolve(version, commit, date string, read func() (*debug.BuildInfo, bool)) Info {
	info := Info{Version: version, Commit: commit, Date: date}
	if info.Version != unknownVersion && info.Commit != unknownValue && info.Date != unknownValue {
		return info
	}
	build, ok := read()
	if !ok || build == nil {
		return info
	}
	// The toolchain already appends a dirty marker to a version it derives from
	// a modified checkout, so vcs.modified is not read separately.
	if info.Version == unknownVersion && build.Main.Version != "" && build.Main.Version != devel {
		info.Version = build.Main.Version
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == unknownValue && setting.Value != "" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if info.Date == unknownValue && setting.Value != "" {
				info.Date = setting.Value
			}
		}
	}
	return info
}
