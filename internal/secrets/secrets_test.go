package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeyBytes)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestSealAndOpenRoundTrip(t *testing.T) {
	ring, err := NewKeyring(testKey(t))
	require.NoError(t, err)
	plaintext := []byte("SENTINEL_SECRET_VALUE")
	first, err := ring.Seal(plaintext, "connection:11111111-1111-4111-8111-111111111111")
	require.NoError(t, err)
	second, err := ring.Seal(plaintext, "connection:11111111-1111-4111-8111-111111111111")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(first, "v1:"))
	require.NotEqual(t, first, second, "a fresh nonce must make identical plaintexts differ")
	require.NotContains(t, first, "SENTINEL")
	for _, envelope := range []string{first, second} {
		opened, err := ring.Open(envelope, "connection:11111111-1111-4111-8111-111111111111")
		require.NoError(t, err)
		require.True(t, bytes.Equal(plaintext, opened))
	}
}

func TestOpenRejectsMovedTamperedForeignAndMalformedEnvelopes(t *testing.T) {
	ring, err := NewKeyring(testKey(t))
	require.NoError(t, err)
	other, err := NewKeyring(testKey(t))
	require.NoError(t, err)
	envelope, err := ring.Seal([]byte("SENTINEL_SECRET_VALUE"), "connection:a")
	require.NoError(t, err)
	tampered := []byte(envelope)
	tampered[len(tampered)-1] ^= 1
	for name, tc := range map[string]struct {
		ring     *Keyring
		envelope string
		context  string
	}{
		"other row":       {ring, envelope, "connection:b"},
		"other key":       {other, envelope, "connection:a"},
		"tampered":        {ring, string(tampered), "connection:a"},
		"unknown version": {ring, "v2:" + strings.TrimPrefix(envelope, "v1:"), "connection:a"},
		"no version":      {ring, strings.TrimPrefix(envelope, "v1:"), "connection:a"},
		"empty":           {ring, "", "connection:a"},
		"short":           {ring, "v1:AAAA", "connection:a"},
		"bad base64":      {ring, "v1:!!!", "connection:a"},
		"empty context":   {ring, envelope, ""},
		"nil keyring":     {nil, envelope, "connection:a"},
	} {
		t.Run(name, func(t *testing.T) {
			opened, err := tc.ring.Open(tc.envelope, tc.context)
			require.ErrorIs(t, err, ErrEnvelope)
			require.Nil(t, opened)
			require.NotContains(t, err.Error(), "SENTINEL")
		})
	}
}

func TestSealBoundsAndKeyValidation(t *testing.T) {
	ring, err := NewKeyring(testKey(t))
	require.NoError(t, err)
	for name, args := range map[string]struct {
		plaintext []byte
		context   string
	}{
		"empty plaintext": {nil, "connection:a"},
		"oversized":       {bytes.Repeat([]byte("x"), maxPlaintext+1), "connection:a"},
		"empty context":   {[]byte("x"), ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ring.Seal(args.plaintext, args.context)
			require.Error(t, err)
		})
	}
	sealed, err := ring.Seal(bytes.Repeat([]byte("x"), maxPlaintext), "connection:a")
	require.NoError(t, err)
	require.NotEmpty(t, sealed)
	for _, length := range []int{0, 16, 31, 33, 64} {
		_, err := NewKeyring(make([]byte, length))
		require.Error(t, err, length)
	}
	var nilRing *Keyring
	_, err = nilRing.Seal([]byte("x"), "connection:a")
	require.Error(t, err)
}

func writeKeyFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func TestLoadKeyFileRules(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	encoded := hex.EncodeToString(key)
	good := writeKeyFile(t, dir, "good", encoded+"\n", 0o600)
	ring, err := LoadKeyFile(good)
	require.NoError(t, err)
	sealed, err := ring.Seal([]byte("x"), "connection:a")
	require.NoError(t, err)
	opened, err := ring.Open(sealed, "connection:a")
	require.NoError(t, err)
	require.Equal(t, []byte("x"), opened)

	// Deployment-managed symlinks to a protected regular file are accepted.
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(good, link))
	_, err = LoadKeyFile(link)
	require.NoError(t, err)
	crlf := writeKeyFile(t, dir, "crlf", encoded+"\r\n", 0o600)
	_, err = LoadKeyFile(crlf)
	require.NoError(t, err)
	upper := writeKeyFile(t, dir, "upper", strings.ToUpper(encoded), 0o400)
	_, err = LoadKeyFile(upper)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		path string
		code string
	}{
		"relative":       {"relative/key", CodeInvalidPath},
		"missing":        {filepath.Join(dir, "missing"), CodeUnreadable},
		"directory":      {dir, CodeUnreadable},
		"group writable": {writeKeyFile(t, dir, "group", encoded, 0o620), CodeUnsafePermissions},
		"world readable": {writeKeyFile(t, dir, "world", encoded, 0o604), CodeUnsafePermissions},
		"too short":      {writeKeyFile(t, dir, "short", encoded[:62], 0o600), CodeInvalidKey},
		"too long":       {writeKeyFile(t, dir, "long", encoded+"ab", 0o600), CodeInvalidKey},
		"oversized":      {writeKeyFile(t, dir, "big", encoded+"\n\n\n", 0o600), CodeInvalidKey},
		"not hex":        {writeKeyFile(t, dir, "hex", strings.Repeat("zz", 32), 0o600), CodeInvalidKey},
		"two newlines":   {writeKeyFile(t, dir, "nl", encoded+"\n\n", 0o600), CodeInvalidKey},
		"empty":          {writeKeyFile(t, dir, "empty", "", 0o600), CodeInvalidKey},
	} {
		t.Run(name, func(t *testing.T) {
			ring, err := LoadKeyFile(tc.path)
			require.Nil(t, ring)
			var failure *FileError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, tc.code, failure.Code)
			require.NotContains(t, err.Error(), dir, "paths never leave the boundary")
		})
	}
	// A symlink is followed, but the opened target is what gets validated.
	unsafeLink := filepath.Join(dir, "unsafe-link")
	require.NoError(t, os.Symlink(writeKeyFile(t, dir, "unsafe-target", encoded, 0o644), unsafeLink))
	_, err = LoadKeyFile(unsafeLink)
	var linked *FileError
	require.ErrorAs(t, err, &linked)
	require.Equal(t, CodeUnsafePermissions, linked.Code)
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, mkfifo(fifo))
	_, err = LoadKeyFile(fifo)
	var failure *FileError
	require.ErrorAs(t, err, &failure)
	require.Equal(t, CodeUnreadable, failure.Code)
}

// foreignGroup returns a group the process does not belong to, so the group
// rule can be exercised from the refusing side.
func foreignGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	require.NoError(t, err)
	member := map[int]bool{os.Getegid(): true}
	for _, gid := range groups {
		member[gid] = true
	}
	for gid := range 1000 {
		if !member[gid] {
			return gid
		}
	}
	t.Skip("the process belongs to every group in the searched range")
	return -1
}

// supplementaryGroup returns a group the process belongs to other than its
// effective one, so the membership rule is exercised beyond the effective gid.
// A file's owner may chown to any group it belongs to, so this needs no
// privileges.
func supplementaryGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	require.NoError(t, err)
	for _, gid := range groups {
		if gid != os.Getegid() {
			return gid
		}
	}
	t.Skip("the process has no group besides its effective one")
	return -1
}

// A Secret volume mounted under fsGroup arrives group-readable, so group read
// is accepted, but only for a group the process actually belongs to.
func TestLoadKeyFileGroupPermissions(t *testing.T) {
	dir := t.TempDir()
	encoded := hex.EncodeToString(testKey(t))
	for _, mode := range []os.FileMode{0o400, 0o600, 0o440, 0o640} {
		t.Run(fmt.Sprintf("accepts %04o", mode), func(t *testing.T) {
			path := writeKeyFile(t, dir, fmt.Sprintf("ok-%04o", mode), encoded, mode)
			require.NoError(t, os.Chown(path, -1, os.Getegid()))
			ring, err := LoadKeyFile(path)
			require.NoError(t, err)
			require.NotNil(t, ring)
		})
	}
	// A projected symlink to a group-readable target is accepted as well.
	shared := writeKeyFile(t, dir, "shared", encoded, 0o440)
	require.NoError(t, os.Chown(shared, -1, os.Getegid()))
	link := filepath.Join(dir, "shared-link")
	require.NoError(t, os.Symlink(shared, link))
	ring, err := LoadKeyFile(link)
	require.NoError(t, err)
	require.NotNil(t, ring)

	for _, mode := range []os.FileMode{0o460, 0o444, 0o404, 0o604, 0o620, 0o410} {
		t.Run(fmt.Sprintf("refuses %04o", mode), func(t *testing.T) {
			path := writeKeyFile(t, dir, fmt.Sprintf("bad-%04o", mode), encoded, mode)
			require.NoError(t, os.Chown(path, -1, os.Getegid()))
			_, err := LoadKeyFile(path)
			var failure *FileError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, CodeUnsafePermissions, failure.Code)
		})
	}

	// fsGroup need not be the process's primary group: any group it belongs to
	// unlocks a group-readable file.
	t.Run("accepts a supplementary group", func(t *testing.T) {
		path := writeKeyFile(t, dir, "supplementary", encoded, 0o440)
		require.NoError(t, os.Chown(path, -1, supplementaryGroup(t)))
		ring, err := LoadKeyFile(path)
		require.NoError(t, err)
		require.NotNil(t, ring)
	})

	t.Run("refuses a foreign group", func(t *testing.T) {
		foreign := writeKeyFile(t, dir, "foreign", encoded, 0o440)
		if err := os.Chown(foreign, -1, foreignGroup(t)); err != nil {
			t.Skip("changing a file's group to one the process does not belong to needs privileges")
		}
		_, err := LoadKeyFile(foreign)
		var failure *FileError
		require.ErrorAs(t, err, &failure)
		require.Equal(t, CodeUnsafePermissions, failure.Code)
	})
}

// stubInfo carries a chosen mode and group so the group rule is decided
// without the privileges a real chown to a foreign group would need.
type stubInfo struct {
	os.FileInfo
	mode os.FileMode
	gid  uint32
}

func (i stubInfo) Mode() os.FileMode { return i.mode }
func (i stubInfo) Sys() any          { return &syscall.Stat_t{Gid: i.gid} }

func TestProtectedFileGroupMembership(t *testing.T) {
	require.True(t, ProtectedFile(stubInfo{mode: 0o440, gid: uint32(os.Getegid())}))
	// Anything beyond group read is refused whatever the group is.
	require.False(t, ProtectedFile(stubInfo{mode: 0o460, gid: uint32(os.Getegid())}))
	// Membership, not the effective gid alone, decides a group-readable file.
	t.Run("supplementary group", func(t *testing.T) {
		require.True(t, ProtectedFile(stubInfo{mode: 0o440, gid: uint32(supplementaryGroup(t))}))
	})
	t.Run("foreign group", func(t *testing.T) {
		require.False(t, ProtectedFile(stubInfo{mode: 0o440, gid: uint32(foreignGroup(t))}))
		// An owner-only file is protected without consulting its group at all.
		require.True(t, ProtectedFile(stubInfo{mode: 0o400, gid: uint32(foreignGroup(t))}))
	})
}
