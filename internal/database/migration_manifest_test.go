package database

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestEmbeddedMigrationsReturnsDefensiveCopy(t *testing.T) {
	root, err := fs.Sub(migrationFiles, "migrations")
	require.NoError(t, err)
	want, err := migrationManifest(root)
	require.NoError(t, err)

	first := embeddedMigrations()
	require.Equal(t, want, first)
	first[0] = migration{version: -1, sum: "caller mutation"}
	second := embeddedMigrations()
	require.Equal(t, want, second)
	require.NotEqual(t, first, second)
}

func TestEmbeddedMigrationsConcurrentCopies(t *testing.T) {
	root, err := fs.Sub(migrationFiles, "migrations")
	require.NoError(t, err)
	want, err := migrationManifest(root)
	require.NoError(t, err)

	for n := range 32 {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			for range 100 {
				got := embeddedMigrations()
				require.Equal(t, want, got)
				got[0] = migration{version: -1, sum: "private copy"}
			}
		})
	}
}

func TestMigrationManifestChecksumsAndNumericOrder(t *testing.T) {
	files := fstest.MapFS{
		"10_tenth.sql": {Data: []byte("-- +goose Up\nSELECT 10;\n")},
		"2_second.sql": {Data: []byte("-- +goose Up\nSELECT 2;\n")},
		"1_first.sql":  {Data: []byte("-- +goose Up\nSELECT 1;\n")},
	}
	want := []migration{
		{version: 1, sum: fmt.Sprintf("%x", sha256.Sum256(files["1_first.sql"].Data))},
		{version: 2, sum: fmt.Sprintf("%x", sha256.Sum256(files["2_second.sql"].Data))},
		{version: 10, sum: fmt.Sprintf("%x", sha256.Sum256(files["10_tenth.sql"].Data))},
	}
	for range 3 {
		got, err := migrationManifest(files)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}

	// Only immutable embedded inputs are cached; injected files remain live.
	files["2_second.sql"].Data = []byte("-- +goose Up\nSELECT 42;\n")
	want[1].sum = fmt.Sprintf("%x", sha256.Sum256(files["2_second.sql"].Data))
	got, err := migrationManifest(files)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
