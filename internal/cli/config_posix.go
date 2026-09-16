//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

// saveConfig applies change to config.toml under config.lock in the Clavis
// home. The file is re-read and validated under the lock, so two writers never
// lose each other's change, and replaced by rename, so a reader sees the old
// file or the new one. A change that returns a failure writes nothing.
func saveConfig(ctx context.Context, home string, change func(*clientConfig) *Result) *Result {
	path := filepath.Join(home, "config.toml")
	fd, err := openHome(home, true)
	var unsafe storageError
	if errors.As(err, &unsafe) {
		return argumentFailure(unsafe.Error(), "")
	}
	if err != nil {
		return argumentFailure(home+" could not be opened", "")
	}
	defer func() { _ = unix.Close(fd) }()
	lockCtx, cancel := context.WithTimeout(ctx, sharedTimeout)
	defer cancel()
	lock, err := openLock(lockCtx, fd, "config.lock")
	if err == nil {
		defer func() { _ = unix.Close(lock) }()
		if err = checkPrivate(lock, false, true); err == nil {
			err = flockWithin(lockCtx, lock)
		}
	}
	if lockCtx.Err() != nil {
		r := failure("TIMEOUT", "Another clavis process holds "+filepath.Join(home, "config.lock"), nil)
		return &r
	}
	if err != nil {
		return argumentFailure(filepath.Join(home, "config.lock")+" must be a regular file with mode 0600", "")
	}
	config, failed := loadConfig(home)
	if failed != nil {
		return failed
	}
	if failed := change(&config); failed != nil {
		return failed
	}
	var body bytes.Buffer
	if err := toml.NewEncoder(&body).SetIndentTables(false).Encode(config); err != nil {
		return argumentFailure(path+": could not be encoded", "")
	}
	if err := replaceConfig(fd, body.Bytes()); err != nil {
		return argumentFailure(path+": could not be written", "")
	}
	return nil
}

// replaceConfig writes a private temporary file beside config.toml and renames
// it into place.
func replaceConfig(directory int, body []byte) error {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	name := "config." + hex.EncodeToString(random) + ".tmp"
	fd, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(directory, name, 0) }()
	file := os.NewFile(uintptr(fd), "config")
	if err = checkPrivate(fd, false, true); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return unix.Renameat(directory, name, directory, "config.toml")
}
