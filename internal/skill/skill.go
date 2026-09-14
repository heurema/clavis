// Package skill carries the agent skill the CLI installs and prints. The
// documents live in clavis/ as the text an agent reads, so the prose is
// reviewed as prose and ships in the same binary as the commands it describes:
// the document and the tool can never come from two different builds.
package skill

import (
	"embed"
	"errors"
	"io/fs"
	"slices"
	"strings"

	"github.com/heurema/clavis/internal/buildinfo"
)

//go:embed clavis
var embedded embed.FS

const (
	// Directory is the embedded root and the name the skill installs under
	// inside an agent's skills directory.
	Directory = "clavis"
	// Entry is the document an agent loads first and the one that carries the
	// marker; the others are references it reads on demand.
	Entry = "SKILL.md"
	// MarkerField is the frontmatter key carrying the version of the CLI that
	// wrote the skill. It is also the ownership marker: a directory whose
	// entry carries it was installed by clavis and may be replaced.
	MarkerField = "x-clavis-skill"
	// fence opens and closes a frontmatter block.
	fence = "---"
)

// ErrUnknownFile names a file the skill does not carry. It is the only error a
// caller can cause: every other failure here is a malformed embedded document,
// which a test catches before a build ships.
var ErrUnknownFile = errors.New("unknown skill file")

// errNoFrontmatter reports an entry the marker cannot be stamped into. The
// embedded entry always opens with a terminated frontmatter block and a test
// asserts it, so this is a build-time mistake, never a caller's.
var errNoFrontmatter = errors.New("skill entry carries no frontmatter")

// Files is the embedded tree rooted at the skill directory, so a caller walks
// the names an agent sees rather than the repository path they live at.
func Files() fs.FS {
	sub, err := fs.Sub(embedded, Directory)
	if err != nil {
		// The path is the constant the embed directive above names, so this
		// cannot happen; returning the unrooted tree fails every lookup
		// loudly rather than serving a file from an unexpected place.
		return embedded
	}
	return sub
}

// Names lists the skill's files in a stable order, which is the order they are
// written in and the order a hint lists them in.
func Names() []string {
	entries, err := fs.ReadDir(Files(), ".")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names
}

// Version is the value the marker carries: the build version clavis version
// reports, never a number written into the prose by hand.
func Version() string { return buildinfo.Current().Version }

// Render returns one file as it is installed: the entry with the marker
// stamped into its frontmatter, every other file exactly as it is embedded.
func Render(name string) ([]byte, error) {
	if !slices.Contains(Names(), name) {
		return nil, ErrUnknownFile
	}
	body, err := fs.ReadFile(Files(), name)
	if err != nil {
		return nil, ErrUnknownFile
	}
	if name != Entry {
		return body, nil
	}
	return stamp(body, Version())
}

// Marker reads the version an installed entry was written by. A missing block,
// a missing line or an empty value all mean the same thing: this entry is not
// one clavis wrote, and the installer may not replace it.
func Marker(skill []byte) (string, bool) {
	lines := strings.Split(string(skill), "\n")
	if trimEnd(lines[0]) != fence {
		return "", false
	}
	for _, raw := range lines[1:] {
		line := trimEnd(raw)
		if line == fence {
			return "", false
		}
		if value, ok := strings.CutPrefix(line, MarkerField+":"); ok {
			version := strings.TrimSpace(value)
			return version, version != ""
		}
	}
	return "", false
}

// stamp puts the marker last in the frontmatter block, dropping any earlier
// one, so a stale stamp is replaced rather than joined by a second and the
// marker is always the line immediately above the closing fence.
func stamp(body []byte, version string) ([]byte, error) {
	lines := strings.Split(string(body), "\n")
	if trimEnd(lines[0]) != fence {
		return nil, errNoFrontmatter
	}
	closing := 0
	kept := make([]string, 0, len(lines)+1)
	kept = append(kept, lines[0])
	for index := 1; index < len(lines); index++ {
		line := trimEnd(lines[index])
		if line == fence {
			closing = index
			break
		}
		if !strings.HasPrefix(line, MarkerField+":") {
			kept = append(kept, lines[index])
		}
	}
	if closing == 0 {
		return nil, errNoFrontmatter
	}
	kept = append(kept, MarkerField+": "+version)
	kept = append(kept, lines[closing:]...)
	return []byte(strings.Join(kept, "\n")), nil
}

// trimEnd ignores trailing blanks and a carriage return, so a line ending an
// editor chose never decides whether a directory is ours.
func trimEnd(line string) string { return strings.TrimRight(line, " \t\r") }
