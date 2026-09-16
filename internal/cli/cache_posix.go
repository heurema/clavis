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

	"github.com/heurema/clavis/internal/auth"
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
	home, err := clavisHome()
	if err != nil {
		return nil, err
	}
	fd, err := openSessions(home, true)
	if err != nil {
		return nil, err
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
	if err = flockWithin(ctx, lock); err != nil {
		cache.close()
		return nil, err
	}
	return cache, nil
}

// readStoredSession reads the session stored for an origin and creates
// nothing: an absent home, sessions directory or session file is no session.
// It takes no lock, because opening a lock that does not exist yet would create
// it; a session file is only ever replaced by rename or unlinked, so a read
// sees a whole file or none.
func readStoredSession(home, origin string) (*cachedSession, error) {
	fd, err := openSessions(home, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(origin))
	cache := &credentialCache{directory: fd, lock: -1, name: hex.EncodeToString(digest[:]), origin: origin}
	defer cache.close()
	return cache.read()
}

// openSessions opens the checked sessions directory in the home. Without
// create, a missing home or sessions directory is os.ErrNotExist and nothing
// is made.
func openSessions(home string, create bool) (int, error) {
	fd, err := openHome(home, create)
	if err != nil {
		return -1, err
	}
	sessions := storageError{path: filepath.Join(home, "sessions"), requirement: "a directory with mode 0700"}
	if create {
		err = unix.Mkdirat(fd, "sessions", 0700)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			return -1, sessions
		}
	}
	next, err := unix.Openat(fd, "sessions", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = unix.Close(fd)
	if !create && errors.Is(err, unix.ENOENT) {
		return -1, os.ErrNotExist
	}
	if err != nil {
		return -1, sessions
	}
	if err = checkPrivate(next, true, true); err != nil {
		_ = unix.Close(next)
		return -1, sessions
	}
	return next, nil
}

// openHome opens the checked Clavis home.
func openHome(home string, create bool) (int, error) {
	// The home itself must be the user's, not merely a trusted ancestor.
	unsafeHome := storageError{path: home, requirement: "a directory owned by you and not writable by group or others"}
	fd, err := openConfigDirectory(home, create)
	var unsafe storageError
	if errors.As(err, &unsafe) && unsafe.path == home {
		return -1, unsafeHome
	}
	if err != nil {
		return -1, err
	}
	if err = checkPrivate(fd, true, false); err != nil {
		_ = unix.Close(fd)
		return -1, unsafeHome
	}
	return fd, nil
}

// flockWithin takes an exclusive lock, waiting no longer than the context.
func flockWithin(ctx context.Context, lock int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
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

// Traverse without following symlinks, including in the home's ancestry.
// Root-owned system ancestors (including sticky temporary roots in isolated
// tests) are trusted; user-owned ancestors must not be writable by others.
// Without create, a missing component is os.ErrNotExist.
func openConfigDirectory(path string, create bool) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	current := "/"
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		current = filepath.Join(current, component)
		unsafe := storageError{path: current, requirement: "a directory owned by you or root and not writable by group or others"}
		if create {
			err = unix.Mkdirat(fd, component, 0700)
			if err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, unsafe
			}
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if !create && errors.Is(err, unix.ENOENT) {
			return -1, os.ErrNotExist
		}
		if err != nil {
			return -1, unsafe
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
			return -1, unsafe
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
	body, err := io.ReadAll(io.LimitReader(file, auth.MaxResponseBody+1))
	var value cachedSession
	if err != nil || len(body) > auth.MaxResponseBody || !strictJSON(body, &value) ||
		value.Origin != c.origin || !auth.ValidToken(value.Token) || !validIdentity(value.Identity) {
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
