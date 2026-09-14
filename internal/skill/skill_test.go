package skill

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/buildinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedNamesAndVersion(t *testing.T) {
	names := Names()
	require.Equal(t, []string{"SKILL.md", "postgresql.md", "victorialogs.md", "victoriametrics.md"}, names)
	assert.True(t, slices.IsSorted(names), "names are listed in a stable order")
	assert.Equal(t, buildinfo.Current().Version, Version(), "the marker carries the build version, never a hand-written one")
	for _, name := range names {
		body, err := fs.ReadFile(Files(), name)
		require.NoError(t, err)
		assert.NotEmpty(t, body)
		if name == Entry {
			assert.True(t, strings.HasPrefix(string(body), "---\n"), "the entry opens with frontmatter")
		}
	}
}

func TestRenderStampsTheEntryOnlyOnce(t *testing.T) {
	entry, err := Render(Entry)
	require.NoError(t, err)
	marker := MarkerField + ": " + Version()
	assert.Equal(t, 1, strings.Count(string(entry), MarkerField+":"), "exactly one marker line")
	assert.Contains(t, string(entry), marker)
	version, ok := Marker(entry)
	require.True(t, ok, "the rendered entry round-trips through Marker")
	assert.Equal(t, Version(), version)
	// The marker is the last frontmatter line: it sits immediately above the
	// closing fence, whatever the document says before it.
	lines := strings.Split(string(entry), "\n")
	closing := slices.Index(lines[1:], fence) + 1
	require.Positive(t, closing)
	assert.Equal(t, marker, lines[closing-1])
	// Rendering twice is rendering once: an already stamped entry is not a
	// second stamp.
	again, err := stamp(entry, Version())
	require.NoError(t, err)
	assert.Equal(t, string(entry), string(again))
}

func TestRenderReplacesAStaleMarkerAndLeavesOtherFilesAlone(t *testing.T) {
	stale := "---\nname: clavis\n" + MarkerField + ": 0.5\ndescription: x\n---\nbody\n"
	version, ok := Marker([]byte(stale))
	require.True(t, ok)
	assert.Equal(t, "0.5", version)
	stamped, err := stamp([]byte(stale), "0.6")
	require.NoError(t, err)
	assert.Equal(t, "---\nname: clavis\ndescription: x\n"+MarkerField+": 0.6\n---\nbody\n", string(stamped))
	assert.Equal(t, 1, strings.Count(string(stamped), MarkerField+":"))
	for _, name := range Names() {
		if name == Entry {
			continue
		}
		rendered, err := Render(name)
		require.NoError(t, err)
		embeddedBody, err := fs.ReadFile(Files(), name)
		require.NoError(t, err)
		assert.Equal(t, embeddedBody, rendered, "%s is installed byte for byte", name)
		_, ok := Marker(rendered)
		assert.False(t, ok, "%s carries no marker", name)
	}
}

func TestMarkerRefusesWhatCLavisDidNotWrite(t *testing.T) {
	for name, document := range map[string]string{
		"no frontmatter":    "# Someone else's skill\n",
		"no marker":         "---\nname: other\n---\nbody\n",
		"empty value":       "---\n" + MarkerField + ":   \n---\nbody\n",
		"after the block":   "---\nname: other\n---\n" + MarkerField + ": 1.0\n",
		"unterminated":      "---\nname: other\n",
		"empty document":    "",
		"fence not leading": "\n---\n" + MarkerField + ": 1.0\n---\n",
	} {
		t.Run(name, func(t *testing.T) {
			version, ok := Marker([]byte(document))
			assert.False(t, ok)
			assert.Empty(t, version)
		})
	}
	// A carriage return an editor left behind does not change ownership.
	version, ok := Marker([]byte("---\r\n" + MarkerField + ": 1.0 \r\n---\r\n"))
	assert.True(t, ok)
	assert.Equal(t, "1.0", version)
}

func TestRenderRefusesAnUnknownName(t *testing.T) {
	for _, name := range []string{"", "skill.md", "clavis", "../skill.go", "postgresql.md/", "SKILL.MD"} {
		body, err := Render(name)
		require.ErrorIs(t, err, ErrUnknownFile, "%q", name)
		assert.Nil(t, body)
	}
}

func TestStampRefusesADocumentWithoutAFrontmatterBlock(t *testing.T) {
	for _, document := range []string{"", "body\n", "---\nname: x\n"} {
		body, err := stamp([]byte(document), "1.0")
		require.ErrorIs(t, err, errNoFrontmatter, "%q", document)
		assert.Nil(t, body)
	}
}
