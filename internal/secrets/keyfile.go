package secrets

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// FileError categories mirror the configuration error vocabulary. They never
// carry the path or file contents.
const (
	CodeInvalidPath       = "INVALID_PATH"
	CodeUnreadable        = "UNREADABLE"
	CodeUnsafePermissions = "UNSAFE_PERMISSIONS"
	CodeInvalidKey        = "INVALID_KEY"
)

type FileError struct{ Code string }

func (e *FileError) Error() string { return "encryption key file: " + e.Code }

// maxKeyFileBytes is 64 hex characters plus one CRLF.
const maxKeyFileBytes = 66

// LoadKeyFile reads a 32-byte key encoded as 64 hexadecimal characters from a
// protected regular file, following the bootstrap secret-file rules: absolute
// path, projected symlinks allowed but the opened target validated, special
// files opened nonblocking, no group or world permission bits, bounded size,
// at most one terminal newline removed.
func LoadKeyFile(path string) (*Keyring, error) {
	if !filepath.IsAbs(path) {
		return nil, &FileError{CodeInvalidPath}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &FileError{CodeUnreadable}
	}
	file := os.NewFile(uintptr(fd), "encryption-key")
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, &FileError{CodeUnreadable}
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, &FileError{CodeUnsafePermissions}
	}
	if info.Size() > maxKeyFileBytes {
		return nil, &FileError{CodeInvalidKey}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return nil, &FileError{CodeUnreadable}
	}
	if len(data) > maxKeyFileBytes {
		return nil, &FileError{CodeInvalidKey}
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) != len(data) {
		value = strings.TrimSuffix(value, "\r")
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != KeyBytes {
		return nil, &FileError{CodeInvalidKey}
	}
	return NewKeyring(key)
}
