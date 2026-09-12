package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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
		"group readable": {writeKeyFile(t, dir, "group", encoded, 0o640), CodeUnsafePermissions},
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
