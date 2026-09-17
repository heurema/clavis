//go:build darwin || linux

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// saveConfig applies change to config.toml under config.lock in the Clavis
// home. The file is re-read and validated under the lock, so two writers never
// lose each other's change, and replaced by rename, so a reader sees the old
// file or the new one. A change that returns a failure writes nothing.
func saveConfig(ctx context.Context, home string, change func(*clientConfig) *Result) *Result {
	path, lockPath := filepath.Join(home, "config.toml"), filepath.Join(home, "config.lock")
	fd, err := openHome(home, true)
	if err != nil {
		// The home is the session store's too, and is reported the same way.
		r := storageFailure(err)
		return &r
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
	if err != nil && lockCtx.Err() != nil {
		r := failure("TIMEOUT", lockPath+" was not locked in time; config.toml is unchanged", nil)
		return &r
	}
	if err != nil {
		return writeFailure(lockPath + " must be a regular file with mode 0600")
	}
	config, failed := loadConfig(home)
	if failed != nil {
		return failed
	}
	if failed := change(&config); failed != nil {
		return failed
	}
	body, err := encodeConfig(config)
	if err != nil {
		return writeFailure(path + " could not be encoded")
	}
	if err := replaceConfig(fd, body); err != nil {
		return writeFailure(path + " could not be written")
	}
	return nil
}

// writeFailure is an operation failure, not an invalid argument: the request
// was valid and the file is unchanged.
func writeFailure(message string) *Result {
	r := failure("CONFIGURATION_WRITE_FAILED", message+"; config.toml is unchanged", nil)
	return &r
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
