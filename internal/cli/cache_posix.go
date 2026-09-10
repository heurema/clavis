//go:build darwin || linux

package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// All session and lock operations are relative to a checked, held directory
// descriptor. Lock files remain in place: unlinking them would split the lock
// between an old waiter and a new process.
type credentialCache struct {
	directory int
	lock      int
	name      string
	origin    string
}

func openCache(ctx context.Context, origin string) (*credentialCache, error) {
	config, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(config) {
		return nil, errors.New("private configuration directory unavailable")
	}
	fd, err := openConfigDirectory(config)
	if err != nil {
		return nil, errors.Join(errors.New("open config"), err)
	}
	if err = checkPrivate(fd, true, false); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	for _, component := range []string{"clavis", "sessions"} {
		err = unix.Mkdirat(fd, component, 0700)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			return nil, err
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, errors.Join(errors.New("open private directory"), openErr)
		}
		fd = next
		if err = checkPrivate(fd, true, true); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	digest := sha256.Sum256([]byte(origin))
	cache := &credentialCache{directory: fd, lock: -1, name: hex.EncodeToString(digest[:]), origin: origin}
	lock, err := openLock(ctx, fd, cache.name+".lock")
	if err != nil {
		cache.close()
		return nil, errors.Join(errors.New("open lock"), err)
	}
	cache.lock = lock
	if err = checkPrivate(lock, false, true); err != nil {
		cache.close()
		return nil, err
	}
	for {
		if err = ctx.Err(); err != nil {
			cache.close()
			return nil, err
		}
		err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return cache, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			cache.close()
			return nil, err
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func openLock(ctx context.Context, directory int, name string) (int, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	for attempt := 0; attempt < 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		fd, err := unix.Openat(directory, name, flags, 0)
		if !errors.Is(err, unix.ENOENT) {
			return fd, err
		}
		// Exclusive creation separates an absent lock from one another process
		// just created. In particular Darwin's O_CREAT|O_NOFOLLOW can report
		// ENOENT during simultaneous non-exclusive creation.
		fd, err = unix.Openat(directory, name, flags|unix.O_CREAT|unix.O_EXCL, 0600)
		if !errors.Is(err, unix.EEXIST) {
			return fd, err
		}
	}
	return -1, errors.New("credential lock changed repeatedly")
}

// Traverse without following symlinks, including in the configuration ancestry.
// Root-owned system ancestors (including sticky temporary roots in isolated
// tests) are trusted; user-owned ancestors must not be writable by others.
func openConfigDirectory(path string) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		err = unix.Mkdirat(fd, component, 0700)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			return -1, errors.Join(errors.New("mkdir config component"), err)
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, errors.Join(errors.New("open config component"), err)
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) ||
			(uint32(stat.Mode)&0022 != 0 && (stat.Uid != 0 || uint32(stat.Mode)&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe configuration ancestor")
		}
	}
	return fd, nil
}

func checkPrivate(fd int, directory, exact bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	return checkPrivateMetadata(stat, directory, exact)
}

func checkPrivateMetadata(stat unix.Stat_t, directory, exact bool) error {
	expectedType, mode := uint32(unix.S_IFREG), uint32(0600)
	if directory {
		expectedType, mode = unix.S_IFDIR, 0700
	}
	if stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&unix.S_IFMT != expectedType ||
		uint32(stat.Mode)&0022 != 0 || (exact && uint32(stat.Mode)&07777 != mode) ||
		(!directory && stat.Nlink != 1) {
		return errors.New("unsafe credential storage")
	}
	return nil
}

func (c *credentialCache) close() {
	if c.lock >= 0 {
		_ = unix.Close(c.lock)
	}
	_ = unix.Close(c.directory)
}

func (c *credentialCache) read() (*cachedSession, error) {
	fd, err := unix.Openat(c.directory, c.name+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "credential")
	defer func() { _ = file.Close() }()
	if err := checkPrivate(fd, false, true); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(file, maxResponseBytes+1))
	var value cachedSession
	if err != nil || len(body) > maxResponseBytes || !strictJSON(body, &value) ||
		value.Origin != c.origin || !validToken(value.Token) || !validIdentity(value.Identity) {
		return nil, errors.New("invalid credential storage")
	}
	return &value, nil
}

func (c *credentialCache) write(value cachedSession) error {
	// Recheck any existing target rather than silently replacing corrupt or unsafe
	// state. Other conforming processes hold this same origin lock.
	if _, err := c.read(); err != nil {
		return err
	}
	if err := checkPrivate(c.directory, true, true); err != nil {
		return err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	name := c.name + "." + hex.EncodeToString(random) + ".tmp"
	fd, err := unix.Openat(c.directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(c.directory, name, 0) }()
	file := os.NewFile(uintptr(fd), "credential")
	if err = checkPrivate(fd, false, true); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return unix.Renameat(c.directory, name, c.directory, c.name+".json")
}

func (c *credentialCache) remove(value *cachedSession) error {
	current, err := c.read()
	if err != nil || current == nil {
		return err
	}
	if value == nil || current.Token != value.Token {
		return errors.New("credential changed")
	}
	return unix.Unlinkat(c.directory, c.name+".json", 0)
}
