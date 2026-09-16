//go:build darwin || linux

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// profilesRun runs a profiles command and returns the exit code, the top-level
// JSON fields and the data object. It fails the test if the result names a
// server or profile, which no local command may do.
func profilesRun(t *testing.T, args ...string) (int, Result, map[string]json.RawMessage) {
	t.Helper()
	code, out := invoke(t, append([]string{"profiles"}, args...)...)
	result := decode(t, out)
	var top, data map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(out), &top))
	assert.NotContains(t, top, "server")
	assert.NotContains(t, top, "profile")
	if result.OK {
		require.NoError(t, json.Unmarshal(top["data"], &data))
	}
	return code, result, data
}

// profilesText runs a profiles command with text output.
func profilesText(t *testing.T, args ...string) (int, string) {
	t.Helper()
	return invoke(t, append(append([]string{"profiles"}, args...), "--output", "text")...)
}

// listenerServer is a loopback origin whose listener counts every connection,
// so a test can prove no command reached it.
func listenerServer(t *testing.T) (string, func() int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	return "http://" + listener.Addr().String(), accepts.Load
}

func storeSession(t *testing.T, origin, username string, expires time.Time) {
	t.Helper()
	cache, err := openCache(context.Background(), origin)
	require.NoError(t, err)
	defer cache.close()
	identity := testIdentity()
	identity.User.Username, identity.ExpiresAt = username, expires.UTC().Truncate(time.Second)
	require.NoError(t, cache.write(cachedSession{Origin: origin, LoginResponse: auth.LoginResponse{Token: testToken(), Identity: identity}}))
}

func readConfigFile(t *testing.T) string {
	t.Helper()
	home, err := clavisHome()
	require.NoError(t, err)
	body, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(t, err)
	return string(body)
}

func jsonField[T any](t *testing.T, data map[string]json.RawMessage, key string) T {
	t.Helper()
	raw, ok := data[key]
	require.True(t, ok, "data must carry %s", key)
	var value T
	require.NoError(t, json.Unmarshal(raw, &value))
	return value
}

func TestProfilesSet(t *testing.T) {
	cliHome(t)
	server, accepts := listenerServer(t)

	code, _, data := profilesRun(t, "set", "fce", "--server", "https://Clavis.example.com:443/")
	require.Equal(t, 0, code)
	assert.Equal(t, []string{"created", "madeCurrent", "name", "server"}, sortedKeys(data))
	assert.Equal(t, "https://clavis.example.com", jsonField[string](t, data, "server"))
	assert.True(t, jsonField[bool](t, data, "created"))
	assert.True(t, jsonField[bool](t, data, "madeCurrent"))
	requireNoStore(t)
	home, err := clavisHome()
	require.NoError(t, err)
	config, failed := loadConfig(home)
	require.Nil(t, failed)
	assert.Equal(t, clientConfig{Current: "fce", Profiles: map[string]clientProfile{"fce": {Server: "https://clavis.example.com"}}}, config)
	info, err := os.Stat(filepath.Join(home, "config.toml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	code, _, data = profilesRun(t, "set", "local", "--server", server)
	require.Equal(t, 0, code)
	assert.True(t, jsonField[bool](t, data, "created"))
	assert.False(t, jsonField[bool](t, data, "madeCurrent"))
	config, _ = loadConfig(home)
	assert.Equal(t, "fce", config.Current)

	// Changing a server leaves the former server's session alone.
	storeSession(t, "https://clavis.example.com", "alice", time.Now().Add(time.Hour))
	session, err := os.ReadFile(cachePath(t, "https://clavis.example.com"))
	require.NoError(t, err)
	code, _, data = profilesRun(t, "set", "fce", "--server", "https://clavis2.example.com")
	require.Equal(t, 0, code)
	assert.False(t, jsonField[bool](t, data, "created"))
	assert.False(t, jsonField[bool](t, data, "madeCurrent"))
	after, err := os.ReadFile(cachePath(t, "https://clavis.example.com"))
	require.NoError(t, err)
	assert.Equal(t, session, after)

	code, out := profilesText(t, "set", "stage", "--server", server)
	require.Equal(t, 0, code)
	assert.Equal(t, "Profile stage set to "+server+"\n", out)
	assert.Zero(t, accepts(), "profiles set never contacts the server")
}

func TestProfilesSetFirstTextAndEncoding(t *testing.T) {
	cliHome(t)
	code, out := profilesText(t, "set", "fce", "--server", "https://clavis.example.com/")
	require.Equal(t, 0, code)
	assert.Equal(t, "Profile fce set to https://clavis.example.com, now current\n", out)
	code, _, _ = profilesRun(t, "set", "alpha", "--server", "http://127.0.0.1:8080")
	require.Equal(t, 0, code)
	body := readConfigFile(t)
	assert.Less(t, strings.Index(body, "profiles.alpha"), strings.Index(body, "profiles.fce"), "profiles are written sorted")
	assert.Equal(t, strings.ToLower(body), body, "keys are lowercase")
}

func TestProfilesConcurrentSet(t *testing.T) {
	cliHome(t)
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := invoke(t, "profiles", "set", name, "--server", fmt.Sprintf("http://127.0.0.1:%d", 8000+i))
			assert.Equal(t, 0, code)
		}()
	}
	wg.Wait()
	home, err := clavisHome()
	require.NoError(t, err)
	config, failed := loadConfig(home)
	require.Nil(t, failed)
	assert.Len(t, config.Profiles, len(names), "every concurrent write lands")
	assert.Contains(t, names, config.Current)
}

func TestProfilesUseCurrentAndList(t *testing.T) {
	cliHome(t)
	server, accepts := listenerServer(t)
	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n\n[profiles.local]\nserver = \""+server+"\"\n")
	expires := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	storeSession(t, "https://clavis.example.com", "alice", expires)
	stamp := expires.Format("2006-01-02T15:04:05Z")

	// The expired session is reported as stored, not verified.
	code, out := profilesText(t, "list")
	require.Equal(t, 0, code)
	assert.Equal(t, "* fce https://clavis.example.com stored session: alice until "+stamp+"\n  local "+server+" not signed in\n", out)
	code, _, data := profilesRun(t, "list")
	require.Equal(t, 0, code)
	assert.Equal(t, "fce", jsonField[string](t, data, "current"))
	assert.Empty(t, jsonField[string](t, data, "override"))
	profiles := jsonField[[]map[string]json.RawMessage](t, data, "profiles")
	require.Len(t, profiles, 2)
	assert.Equal(t, []string{"current", "name", "server", "session"}, sortedKeys(profiles[0]))
	assert.JSONEq(t, `{"username":"alice","expiresAt":"`+stamp+`"}`, string(profiles[0]["session"]))
	assert.Equal(t, "null", string(profiles[1]["session"]))

	storeSession(t, server, "bob", time.Now().Add(time.Hour))
	code, _, data = profilesRun(t, "use", "local")
	require.Equal(t, 0, code)
	assert.Equal(t, []string{"override", "profile"}, sortedKeys(data))
	entry := jsonField[ProfileEntry](t, data, "profile")
	assert.Equal(t, "local", entry.Name)
	assert.True(t, entry.Current)
	require.NotNil(t, entry.Session)
	assert.Equal(t, "bob", entry.Session.Username)
	home, err := clavisHome()
	require.NoError(t, err)
	config, _ := loadConfig(home)
	assert.Equal(t, "local", config.Current)

	code, out = profilesText(t, "use", "fce")
	require.Equal(t, 0, code)
	assert.Equal(t, "Profile: fce\nServer: https://clavis.example.com\nstored session: alice until "+stamp+"\n", out)

	code, _, data = profilesRun(t, "current")
	require.Equal(t, 0, code)
	assert.Equal(t, "config", jsonField[string](t, data, "source"))
	assert.Equal(t, "fce", jsonField[ProfileEntry](t, data, "profile").Name)
	t.Setenv("CLAVIS_PROFILE", "local")
	code, _, data = profilesRun(t, "current")
	require.Equal(t, 0, code)
	assert.Equal(t, "environment", jsonField[string](t, data, "source"))
	entry = jsonField[ProfileEntry](t, data, "profile")
	assert.Equal(t, "local", entry.Name)
	assert.False(t, entry.Current, "current is the file's current profile")
	code, out = profilesText(t, "current")
	require.Equal(t, 0, code)
	assert.True(t, strings.HasPrefix(out, "Profile: local\n"))
	assert.True(t, strings.HasSuffix(out, "Source: environment\n"))
	assert.Zero(t, accepts(), "no profiles command contacts a server")
}

func TestProfilesEnvironmentOverride(t *testing.T) {
	cliHome(t)
	path := writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n\n[profiles.local]\nserver = \"http://127.0.0.1:8080\"\n")

	t.Setenv("CLAVIS_PROFILE", "fce")
	code, _, data := profilesRun(t, "use", "local")
	require.Equal(t, 0, code)
	assert.Equal(t, "fce", jsonField[string](t, data, "override"))
	code, out := profilesText(t, "use", "local")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "Note: CLAVIS_PROFILE=fce selects fce in this environment\n")
	code, out = profilesText(t, "list")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "Note: CLAVIS_PROFILE=fce selects fce in this environment\n")

	t.Setenv("CLAVIS_PROFILE", "local")
	code, out = profilesText(t, "list")
	require.Equal(t, 0, code)
	assert.NotContains(t, out, "Note:", "no note when the override is the current profile")

	t.Setenv("CLAVIS_PROFILE", "staging")
	code, _, data = profilesRun(t, "list")
	require.Equal(t, 0, code)
	assert.Equal(t, "staging", jsonField[string](t, data, "override"))
	for _, command := range []string{"list", "use"} {
		args := []string{command}
		if command == "use" {
			args = append(args, "fce")
		}
		code, out = profilesText(t, args...)
		require.Equal(t, 0, code)
		assert.Contains(t, out, "Note: CLAVIS_PROFILE=staging names no profile; networked commands in this environment exit 2\n")
	}
	code, result, _ := profilesRun(t, "current")
	require.Equal(t, 2, code)
	assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
	assert.Equal(t, profileListHint, result.Error.Hint)

	before := readConfigFile(t)
	t.Setenv("CLAVIS_PROFILE", "Not-A-Name!")
	for _, args := range [][]string{{"use", "local"}, {"current"}, {"list"}} {
		code, out := invoke(t, append([]string{"profiles"}, args...)...)
		require.Equal(t, 2, code, args)
		result := decode(t, out)
		assert.Equal(t, "CLAVIS_PROFILE is not a valid profile name", result.Error.Message)
		assert.NotContains(t, out, "Not-A-Name")
	}
	assert.Equal(t, before, readConfigFile(t))
	assert.FileExists(t, path)
}

func TestProfilesInvalidArguments(t *testing.T) {
	cliHome(t)
	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n")
	before := readConfigFile(t)
	for _, args := range [][]string{
		{"set", "local"}, {"set", "local", "--server="}, {"set", "local", "--server", "http://clavis.example.com"},
		{"set", "local", "--server", "https://clavis.example.com/base"}, {"set", "Bad!", "--server", "https://clavis.example.com"},
		{"set", "--server", "https://clavis.example.com"}, {"set", "a", "b", "--server", "https://clavis.example.com"},
		{"use"}, {"use", "fce", "local"}, {"use", "Bad!"}, {"remove"}, {"remove", "fce", "local"},
		{"list", "fce"}, {"current", "fce"},
		{"use", "missing"}, {"remove", "missing"},
	} {
		code, result, _ := profilesRun(t, args...)
		assert.Equal(t, 2, code, args)
		require.NotNil(t, result.Error, args)
		assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code, args)
		assert.NotEmpty(t, result.Error.Hint, args)
		assert.NotContains(t, result.Error.Message, "Bad!", args)
		if args[len(args)-1] == "missing" {
			assert.Equal(t, profileListHint, result.Error.Hint, args)
		}
	}
	assert.Equal(t, before, readConfigFile(t), "a refused command leaves the file unchanged")
	// A positional argument is still refused on every other command.
	code, _ := invoke(t, "whoami", "set")
	assert.Equal(t, 2, code)
}

func TestProfilesNothingCurrentAndNoHome(t *testing.T) {
	home := cliHome(t)
	code, result, _ := profilesRun(t, "current")
	require.Equal(t, 2, code)
	assert.Equal(t, profileSetupHint, result.Error.Hint)
	code, _, data := profilesRun(t, "list")
	require.Equal(t, 0, code)
	assert.Equal(t, "[]", string(data["profiles"]))
	code, _, _ = profilesRun(t, "use", "fce")
	require.Equal(t, 2, code)
	code, _, _ = profilesRun(t, "remove", "fce")
	require.Equal(t, 2, code)
	assert.NoDirExists(t, filepath.Join(home, ".clavis"), "reading profiles creates nothing")

	// A home without a sessions directory has no stored session and gains none.
	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n")
	code, _, _ = profilesRun(t, "list")
	require.Equal(t, 0, code)
	code, _, _ = profilesRun(t, "use", "fce")
	require.Equal(t, 0, code)
	requireNoStore(t)
}

func TestProfilesRemove(t *testing.T) {
	cliHome(t)
	server, accepts := listenerServer(t)
	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \""+server+"\"\n\n[profiles.local]\nserver = \"http://127.0.0.1:8080\"\n")
	storeSession(t, server, "alice", time.Now().Add(time.Hour))

	code, out := profilesText(t, "remove", "local")
	require.Equal(t, 0, code)
	assert.Equal(t, "Removed local\n", out)
	code, _, data := profilesRun(t, "remove", "fce")
	require.Equal(t, 0, code)
	assert.Equal(t, []string{"currentCleared", "name"}, sortedKeys(data))
	assert.True(t, jsonField[bool](t, data, "currentCleared"))
	assert.FileExists(t, cachePath(t, server), "removing a profile keeps its session")
	home, err := clavisHome()
	require.NoError(t, err)
	config, failed := loadConfig(home)
	require.Nil(t, failed)
	assert.Equal(t, clientConfig{}, config)

	code, whoami := invoke(t, "whoami")
	require.Equal(t, 2, code)
	assert.Equal(t, profileSetupHint, decode(t, whoami).Error.Hint)
	assert.Zero(t, accepts())

	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \""+server+"\"\n")
	code, out = profilesText(t, "remove", "fce")
	require.Equal(t, 0, code)
	assert.Equal(t, "Removed fce; no profile is current now\n", out)
}

func TestProfilesUnsafeStorage(t *testing.T) {
	cliHome(t)
	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n\n[profiles.local]\nserver = \"http://127.0.0.1:8080\"\n")
	storeSession(t, "https://clavis.example.com", "alice", time.Now().Add(time.Hour))
	sessions := filepath.Dir(cachePath(t, "https://clavis.example.com"))
	require.NoError(t, os.Chmod(sessions, 0o755))
	before := readConfigFile(t)
	for _, args := range [][]string{{"use", "local"}, {"list"}, {"current"}} {
		code, result, _ := profilesRun(t, args...)
		assert.Equal(t, 1, code, args)
		require.NotNil(t, result.Error, args)
		assert.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code, args)
		assert.Contains(t, result.Error.Message, sessions+" must be a directory with mode 0700", args)
	}
	assert.Equal(t, before, readConfigFile(t), "a storage failure leaves the file unchanged")
	// set and remove never open the session store.
	code, _, _ := profilesRun(t, "set", "stage", "--server", "https://stage.example.com")
	assert.Equal(t, 0, code)
	code, _, _ = profilesRun(t, "remove", "stage")
	assert.Equal(t, 0, code)
}

func TestProfilesSymlinkedConfig(t *testing.T) {
	home := cliHome(t)
	const valid = "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n"
	clavis := filepath.Join(home, ".clavis")
	require.NoError(t, os.MkdirAll(clavis, 0o700))
	real := filepath.Join(home, "real.toml")
	require.NoError(t, os.WriteFile(real, []byte(valid), 0o600))
	path := filepath.Join(clavis, "config.toml")
	require.NoError(t, os.Symlink(real, path))
	for _, args := range [][]string{
		{"list"}, {"current"}, {"use", "fce"}, {"set", "local", "--server", "http://127.0.0.1:8080"}, {"remove", "fce"},
	} {
		code, result, _ := profilesRun(t, args...)
		assert.Equal(t, 2, code, args)
		require.NotNil(t, result.Error, args)
		assert.Equal(t, path+": must be a regular file", result.Error.Message, args)
	}
	body, err := os.ReadFile(real)
	require.NoError(t, err)
	assert.Equal(t, valid, string(body), "the link's target is unchanged")
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the link is not replaced")
}

func TestProfilesWriteFailures(t *testing.T) {
	home := cliHome(t)
	path := writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n")
	clavis := filepath.Dir(path)
	lock := filepath.Join(clavis, "config.lock")
	before := readConfigFile(t)

	// Another writer holds config.lock: the write gives up at its deadline.
	held, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600)
	require.NoError(t, err)
	require.NoError(t, unix.Flock(int(held.Fd()), unix.LOCK_EX))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	failed := saveConfig(ctx, clavis, func(*clientConfig) *Result {
		t.Error("no change is applied without the lock")
		return nil
	})
	cancel()
	require.NotNil(t, failed)
	assert.Equal(t, "TIMEOUT", failed.Error.Code)
	assert.Contains(t, failed.Error.Message, lock)
	require.NoError(t, held.Close())
	assert.Equal(t, before, readConfigFile(t))

	// An unsafe lock file is an operation failure naming it.
	require.NoError(t, os.Chmod(lock, 0o644))
	code, result, _ := profilesRun(t, "set", "local", "--server", "http://127.0.0.1:8080")
	assert.Equal(t, 1, code)
	require.NotNil(t, result.Error)
	assert.Equal(t, "CONFIGURATION_WRITE_FAILED", result.Error.Code)
	assert.Contains(t, result.Error.Message, lock)
	assert.Equal(t, before, readConfigFile(t))
	require.NoError(t, os.Chmod(lock, 0o600))

	// An unsafe home is reported as the session store reports it.
	require.NoError(t, os.Chmod(clavis, 0o775))
	for _, args := range [][]string{{"set", "local", "--server", "http://127.0.0.1:8080"}, {"use", "fce"}, {"remove", "fce"}} {
		code, result, _ := profilesRun(t, args...)
		assert.Equal(t, 1, code, args)
		require.NotNil(t, result.Error, args)
		assert.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code, args)
		assert.Contains(t, result.Error.Message, clavis+" must be", args)
	}
	require.NoError(t, os.Chmod(clavis, 0o700))
	assert.Equal(t, before, readConfigFile(t))
	assert.NoDirExists(t, filepath.Join(home, ".clavis", "sessions"))
}

func TestProfilesCorruptFiles(t *testing.T) {
	cliHome(t)
	path := writeConfig(t, "current = \"fce\"\noutput = \"text\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n")
	before := readConfigFile(t)
	for _, args := range [][]string{
		{"set", "local", "--server", "http://127.0.0.1:8080"}, {"use", "fce"}, {"current"}, {"list"}, {"remove", "fce"},
	} {
		code, result, _ := profilesRun(t, args...)
		assert.Equal(t, 2, code, args)
		require.NotNil(t, result.Error, args)
		assert.Equal(t, path+": output is not a known key", result.Error.Message, args)
	}
	assert.Equal(t, before, readConfigFile(t), "a corrupt file is never rewritten")

	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://clavis.example.com\"\n")
	storeSession(t, "https://clavis.example.com", "alice", time.Now().Add(time.Hour))
	require.NoError(t, os.WriteFile(cachePath(t, "https://clavis.example.com"), []byte(`{`), 0o600))
	code, result, _ := profilesRun(t, "list")
	assert.Equal(t, 1, code)
	require.NotNil(t, result.Error)
	assert.Equal(t, "CREDENTIAL_STORAGE_FAILED", result.Error.Code)
}

func sortedKeys(values map[string]json.RawMessage) []string {
	return slices.Sorted(maps.Keys(values))
}
