//go:build darwin || linux

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func cachePath(t *testing.T, origin string) string {
	t.Helper()
	home, err := clavisHome()
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(origin))
	return filepath.Join(home, "sessions", hex.EncodeToString(digest[:])+".json")
}

func TestCacheProtectionAndAtomicReplacement(t *testing.T) {
	cliHome(t)
	origin := "https://cli.example.test"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cache, err := openCache(ctx, origin)
	require.NoError(t, err)
	defer cache.close()
	value := cachedSession{Origin: origin, LoginResponse: auth.LoginResponse{Token: testToken(), Identity: testIdentity()}}
	require.NoError(t, cache.write(value))
	path := cachePath(t, origin)
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{path, 0600}, {path[:len(path)-5] + ".lock", 0600},
		{filepath.Dir(path), 0700}, {filepath.Dir(filepath.Dir(path)), 0700},
	} {
		info, err := os.Lstat(tc.path)
		require.NoError(t, err)
		require.Equal(t, tc.mode, info.Mode().Perm())
	}
	// A held descriptor sees the old complete file after atomic replacement.
	old, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = old.Close() }()
	replacement := value
	replacement.Token = testToken()
	require.NoError(t, cache.write(replacement))
	var observed cachedSession
	require.NoError(t, json.NewDecoder(old).Decode(&observed))
	require.True(t, observed.Token == value.Token)
	current, err := cache.read()
	require.NoError(t, err)
	require.True(t, current.Token == replacement.Token)
	require.Error(t, cache.remove(&value), "must not remove an unrelated replacement")
	require.NoError(t, cache.remove(&replacement))
	current, err = cache.read()
	require.NoError(t, err)
	require.Nil(t, current)
	files, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, files, 1, "only the persistent lock should remain")
}

func TestCacheConcurrentOpen(t *testing.T) {
	cliHome(t)
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			cache, err := openCache(ctx, "https://cli.example.test")
			require.NoError(t, err)
			cache.close()
		})
	}
	workers.Wait()
}

func TestCacheRejectsUnsafeState(t *testing.T) {
	for _, state := range []string{"symlink", "fifo", "directory", "mode", "hardlink", "corrupt", "oversized", "other-origin", "unknown-field", "unsafe-directory", "symlink-directory", "symlink-ancestor", "lock-symlink", "lock-fifo", "lock-mode"} {
		t.Run(state, func(t *testing.T) {
			home := cliHome(t)
			origin := "https://cli.example.test"
			cache, err := openCache(context.Background(), origin)
			require.NoError(t, err)
			value := cachedSession{Origin: origin, LoginResponse: auth.LoginResponse{Token: testToken(), Identity: testIdentity()}}
			require.NoError(t, cache.write(value))
			cache.close()
			path := cachePath(t, origin)
			body, err := os.ReadFile(path)
			require.NoError(t, err)
			switch state {
			case "symlink", "fifo", "directory":
				require.NoError(t, os.Remove(path))
				switch state {
				case "symlink":
					require.NoError(t, os.Symlink(filepath.Join(home, "absent"), path))
				case "fifo":
					require.NoError(t, unix.Mkfifo(path, 0600))
				case "directory":
					require.NoError(t, os.Mkdir(path, 0700))
				}
			case "mode":
				require.NoError(t, os.Chmod(path, 0644))
			case "hardlink":
				require.NoError(t, os.Link(path, filepath.Join(home, "alias")))
			case "corrupt":
				require.NoError(t, os.WriteFile(path, []byte(`{`), 0600))
			case "oversized":
				require.NoError(t, os.WriteFile(path, make([]byte, auth.MaxResponseBody+1), 0600))
			case "other-origin":
				value.Origin = "https://other.example.test"
				body, err = json.Marshal(value)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, body, 0600))
			case "unknown-field":
				body = append(body[:len(body)-1], []byte(`,"unknown":true}`)...)
				require.NoError(t, os.WriteFile(path, body, 0600))
			case "unsafe-directory":
				require.NoError(t, os.Chmod(filepath.Dir(path), 0755))
			case "symlink-directory", "symlink-ancestor":
				dir := filepath.Dir(path)
				if state == "symlink-ancestor" {
					dir = home
					t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir+"-moved")) })
				}
				require.NoError(t, os.Rename(dir, dir+"-moved"))
				require.NoError(t, os.Symlink(dir+"-moved", dir))
			case "lock-symlink", "lock-fifo", "lock-mode":
				lock := path[:len(path)-5] + ".lock"
				if state == "lock-mode" {
					require.NoError(t, os.Chmod(lock, 0644))
				} else {
					require.NoError(t, os.Remove(lock))
					if state == "lock-fifo" {
						require.NoError(t, unix.Mkfifo(lock, 0600))
					} else {
						require.NoError(t, os.Symlink(path, lock))
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			cache, err = openCache(ctx, origin)
			if err == nil {
				_, err = cache.read()
				cache.close()
			}
			require.Error(t, err)
			require.Less(t, time.Since(start), time.Second)
		})
	}
}

func TestCacheLockBoundAndPersistenceCleanup(t *testing.T) {
	cliHome(t)
	origin := "https://cli.example.test"
	cache, err := openCache(context.Background(), origin)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = openCache(ctx, origin)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
	cache.close()
	cache, err = openCache(context.Background(), origin)
	require.NoError(t, err)
	cache.close()

	for _, stalledCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed-cleanup", true: "bounded-cleanup"}[stalledCleanup], func(t *testing.T) {
			cliHome(t)
			var origin string
			issued := testToken()
			var cleanup atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == auth.LoginPath {
					// Change permissions after issuance starts to force a real
					// persistence failure, without a production fault-injection hook.
					path := cachePath(t, origin)
					require.NoError(t, os.Chmod(filepath.Dir(path), 0755))
					_ = json.NewEncoder(w).Encode(auth.LoginResponse{Token: issued, Identity: testIdentity()})
					return
				}
				require.True(t, r.Header.Get("Authorization") == "Bearer "+string(issued))
				cleanup.Add(1)
				if stalledCleanup {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				_ = json.NewEncoder(w).Encode(auth.Revocation{Revoked: true})
			}))
			defer server.Close()
			origin = server.URL
			start := time.Now()
			exit, result, output := cliInvoke(t, string(testToken()), "login", "--username=cli-test", "--password-stdin", "--timeout=80ms", "--server", origin)
			require.Equal(t, 1, exit)
			require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
			require.False(t, strings.Contains(output, string(issued)))
			require.Equal(t, int32(1), cleanup.Load())
			require.Less(t, time.Since(start), time.Second)
			_, err := os.Stat(cachePath(t, origin))
			require.True(t, os.IsNotExist(err))
		})
	}
}

func TestCacheOwnership(t *testing.T) {
	// Exercise foreign ownership without requiring chown privileges or touching
	// another user's files.
	var stat unix.Stat_t
	stat.Mode = unix.S_IFREG | 0600
	stat.Nlink = 1
	stat.Uid = uint32(os.Geteuid())
	require.NoError(t, checkPrivateMetadata(stat, false, true))
	stat.Uid++
	require.Error(t, checkPrivateMetadata(stat, false, true))
}

func TestPersistenceFailurePreservesPreviousAndLogoutDeletionFails(t *testing.T) {
	cliHome(t)
	var origin string
	old, issued := testToken(), testToken()
	var revokedNew atomic.Int32
	var breakDeletion atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := cachePath(t, origin)
		if r.URL.Path == auth.LoginPath {
			require.NoError(t, os.Chmod(filepath.Dir(path), 0755))
			_ = json.NewEncoder(w).Encode(auth.LoginResponse{Token: issued, Identity: testIdentity()})
			return
		}
		if r.Header.Get("Authorization") == "Bearer "+string(issued) {
			revokedNew.Add(1)
		} else {
			require.True(t, r.Header.Get("Authorization") == "Bearer "+string(old))
		}
		if breakDeletion.Load() {
			// An unsafe target appearing before deletion must never be removed
			// as though it were the matching credential.
			require.NoError(t, os.Chmod(path, 0644))
		}
		_ = json.NewEncoder(w).Encode(auth.Revocation{Revoked: true})
	}))
	defer server.Close()
	origin = server.URL
	cache, err := openCache(context.Background(), origin)
	require.NoError(t, err)
	require.NoError(t, cache.write(cachedSession{Origin: origin, LoginResponse: auth.LoginResponse{Token: old, Identity: testIdentity()}}))
	cache.close()
	before, err := os.ReadFile(cachePath(t, origin))
	require.NoError(t, err)
	exit, result, _ := cliInvoke(t, string(testToken()), "login", "--username=cli-test", "--password-stdin", "--server", origin)
	require.Equal(t, 1, exit)
	require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
	require.Equal(t, int32(1), revokedNew.Load())
	after, err := os.ReadFile(cachePath(t, origin))
	require.NoError(t, err)
	require.True(t, string(before) == string(after), "previous credential changed on persistence failure")
	require.NoError(t, os.Chmod(filepath.Dir(cachePath(t, origin)), 0700))
	breakDeletion.Store(true)
	exit, result, _ = cliInvoke(t, "", "logout", "--server", origin)
	require.Equal(t, 1, exit)
	require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
	require.Nil(t, result.Data)
	_, err = os.Stat(cachePath(t, origin))
	require.NoError(t, err)
}

func TestCacheHomeCreatedOwnerOnly(t *testing.T) {
	home := cliHome(t)
	t.Setenv("CLAVIS_HOME", filepath.Join(home, "missing", "nested", "clavis"))
	cache, err := openCache(context.Background(), "https://cli.example.test")
	require.NoError(t, err)
	cache.close()
	for _, path := range []string{"missing", "missing/nested", "missing/nested/clavis", "missing/nested/clavis/sessions"} {
		info, err := os.Lstat(filepath.Join(home, path))
		require.NoError(t, err)
		require.True(t, info.IsDir())
		require.Equal(t, os.FileMode(0700), info.Mode().Perm(), path)
	}
}

func TestCacheHomeUnderNormalUmaskAndIndependentOrigins(t *testing.T) {
	home := cliHome(t)
	require.NoError(t, os.Mkdir(filepath.Join(home, ".clavis"), 0700))
	require.NoError(t, os.Chmod(filepath.Join(home, ".clavis"), 0755))
	tokens := map[string]auth.Secret{"https://one.example.test": testToken(), "https://two.example.test": testToken()}
	for origin, token := range tokens {
		cache, err := openCache(context.Background(), origin)
		require.NoError(t, err)
		require.NoError(t, cache.write(cachedSession{Origin: origin, LoginResponse: auth.LoginResponse{Token: token, Identity: testIdentity()}}))
		cache.close()
	}
	for origin, token := range tokens {
		cache, err := openCache(context.Background(), origin)
		require.NoError(t, err)
		current, err := cache.read()
		cache.close()
		require.NoError(t, err)
		require.True(t, current.Token == token, origin)
		require.Equal(t, filepath.Join(home, ".clavis", "sessions"), filepath.Dir(cachePath(t, origin)))
	}
}

func TestCacheUnsafeHomeNamesPath(t *testing.T) {
	const homeRule = "a directory owned by you and not writable by group or others"
	for _, tc := range []struct {
		name        string
		prepare     func(t *testing.T, home string)
		path        string
		requirement string
	}{
		{"home-group-writable", func(t *testing.T, home string) {
			require.NoError(t, os.Chmod(filepath.Join(home, ".clavis"), 0775))
		}, ".clavis", homeRule},
		{"home-symlink", func(t *testing.T, home string) {
			require.NoError(t, os.Rename(filepath.Join(home, ".clavis"), filepath.Join(home, "elsewhere")))
			require.NoError(t, os.Symlink(filepath.Join(home, "elsewhere"), filepath.Join(home, ".clavis")))
		}, ".clavis", homeRule},
		{"sessions-mode", func(t *testing.T, home string) {
			require.NoError(t, os.Chmod(filepath.Join(home, ".clavis", "sessions"), 0755))
		}, ".clavis/sessions", "a directory with mode 0700"},
		{"sessions-symlink", func(t *testing.T, home string) {
			sessions := filepath.Join(home, ".clavis", "sessions")
			require.NoError(t, os.Rename(sessions, filepath.Join(home, "elsewhere")))
			require.NoError(t, os.Symlink(filepath.Join(home, "elsewhere"), sessions))
		}, ".clavis/sessions", "a directory with mode 0700"},
		{"ancestor-writable", func(t *testing.T, home string) {
			require.NoError(t, os.Mkdir(filepath.Join(home, "shared"), 0700))
			require.NoError(t, os.Chmod(filepath.Join(home, "shared"), 0777))
			t.Setenv("CLAVIS_HOME", filepath.Join(home, "shared", "clavis"))
		}, "shared", "a directory owned by you or root and not writable by group or others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := cliHome(t)
			cache, err := openCache(context.Background(), "http://127.0.0.1:1")
			require.NoError(t, err)
			cache.close()
			tc.prepare(t, home)
			exit, result, output := cliInvoke(t, "", "whoami", "--server", "http://127.0.0.1:1")
			require.Equal(t, 1, exit, output)
			require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
			require.Equal(t, filepath.Join(home, tc.path)+" must be "+tc.requirement+"; credentials were not displayed", result.Error.Message)
		})
	}
}

func TestCacheRootOwnedHomeRefused(t *testing.T) {
	cliHome(t)
	// A root-owned sticky directory passes the ancestor rule, so only the
	// home's own ownership check refuses it.
	home := "/tmp"
	if runtime.GOOS == "darwin" {
		home = "/private/tmp"
	}
	info, err := os.Lstat(home)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSticky == 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Skip(home + " is not a root-owned sticky directory")
	}
	_, err = os.Lstat(filepath.Join(home, "sessions"))
	existed := err == nil
	t.Setenv("CLAVIS_HOME", home)
	exit, result, _ := cliInvoke(t, "", "whoami", "--server", "http://127.0.0.1:1")
	require.Equal(t, 1, exit)
	require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
	require.Equal(t, home+" must be a directory owned by you and not writable by group or others; credentials were not displayed", result.Error.Message)
	if !existed {
		require.NoDirExists(t, filepath.Join(home, "sessions"))
	}
}

func TestCacheRelativeHomeRefused(t *testing.T) {
	cliHome(t)
	t.Setenv("CLAVIS_HOME", "relative-clavis-home")
	exit, result, _ := cliInvoke(t, "", "logout", "--server", "http://127.0.0.1:1")
	require.Equal(t, 1, exit)
	require.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
	require.Equal(t, "CLAVIS_HOME must be an absolute path; credentials were not displayed", result.Error.Message)
	require.NoDirExists(t, "relative-clavis-home")
	t.Setenv("CLAVIS_HOME", "")
	t.Setenv("HOME", "")
	exit, result, _ = cliInvoke(t, "", "logout", "--server", "http://127.0.0.1:1")
	require.Equal(t, 1, exit)
	require.Equal(t, "HOME must be set to an absolute path; credentials were not displayed", result.Error.Message)
}

func TestCacheFormerLocationIgnored(t *testing.T) {
	cliHome(t)
	origin := "http://127.0.0.1:1"
	config, err := os.UserConfigDir()
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(origin))
	former := filepath.Join(config, "clavis", "sessions", hex.EncodeToString(digest[:])+".json")
	require.NoError(t, os.MkdirAll(filepath.Dir(former), 0700))
	body, err := json.Marshal(cachedSession{Origin: origin, LoginResponse: auth.LoginResponse{Token: testToken(), Identity: testIdentity()}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(former, body, 0600))
	cache, err := openCache(context.Background(), origin)
	require.NoError(t, err)
	current, err := cache.read()
	cache.close()
	require.NoError(t, err)
	require.Nil(t, current, "a session in the former location is not read")
	exit, _, _ := cliInvoke(t, "", "logout", "--server", origin)
	require.Equal(t, 0, exit)
	after, err := os.ReadFile(former)
	require.NoError(t, err)
	require.True(t, string(body) == string(after), "the former session file is left untouched")
}
