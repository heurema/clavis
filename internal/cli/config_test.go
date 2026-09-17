//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConfig writes config.toml into the Clavis home of the current test
// environment and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	home, err := clavisHome()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(home, 0o700))
	path := filepath.Join(home, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// strictInvoke runs the CLI with stdin that must stay unread and a password
// reader that must never be called, and reports how much stdin is left.
func strictInvoke(t *testing.T, stdin string, args ...string) (int, Result, int) {
	t.Helper()
	var out bytes.Buffer
	input := strings.NewReader(stdin)
	exit := RunWithIO(context.Background(), append([]string{"clavis"}, args...), IO{
		Stdin: input, Stdout: &out,
		ReadPassword: func(context.Context, io.Reader, io.Writer) ([]byte, error) {
			t.Fatal("a password must not be read when resolution fails")
			return nil, nil
		},
	})
	return exit, decode(t, out.String()), input.Len()
}

func requireNoStore(t *testing.T) {
	t.Helper()
	home, err := clavisHome()
	require.NoError(t, err)
	require.NoDirExists(t, filepath.Join(home, "sessions"), "no session store may be opened")
}

func TestResolveTargetOrder(t *testing.T) {
	const withCurrent = `current = "fce"

[profiles.fce]
server = "https://FCE.example.com:443/"

[profiles.local]
server = "http://127.0.0.1:8080"
`
	const withoutCurrent = `[profiles.fce]
server = "https://fce.example.com"

[profiles.local]
server = "http://127.0.0.1:8080"
`
	unset := "\x00unset"
	for _, tc := range []struct {
		name, file, server, profile, env string
		origin, selected, hint           string
	}{
		{name: "current", file: withCurrent, env: unset, origin: "https://fce.example.com", selected: "fce"},
		{name: "environment beats current", file: withCurrent, env: "local", origin: "http://127.0.0.1:8080", selected: "local"},
		{name: "empty environment is unset", file: withCurrent, env: "", origin: "https://fce.example.com", selected: "fce"},
		{name: "flag beats environment", file: withCurrent, profile: "fce", env: "local", origin: "https://fce.example.com", selected: "fce"},
		{name: "flag beats current", file: withCurrent, profile: "local", env: unset, origin: "http://127.0.0.1:8080", selected: "local"},
		{name: "server beats environment", file: withCurrent, server: "https://other.example.com/", env: "local", origin: "https://other.example.com"},
		{name: "environment without current", file: withoutCurrent, env: "local", origin: "http://127.0.0.1:8080", selected: "local"},
		{name: "flag without current", file: withoutCurrent, profile: "fce", env: unset, origin: "https://fce.example.com", selected: "fce"},
		{name: "nothing current", file: withoutCurrent, env: unset, hint: profileSetupHint},
		{name: "empty environment and nothing current", file: withoutCurrent, env: "", hint: profileSetupHint},
		{name: "absent file", env: unset, hint: profileSetupHint},
		{name: "server and profile", file: withCurrent, server: "https://fce.example.com", profile: "fce", env: unset},
		{name: "unknown flag profile", file: withCurrent, profile: "staging", env: unset, hint: profileListHint},
		{name: "unknown environment profile", file: withCurrent, env: "staging", hint: profileListHint},
		{name: "unknown flag profile with absent file", profile: "staging", env: unset, hint: profileListHint},
		{name: "invalid flag profile", file: withCurrent, profile: "SECRET", env: unset, hint: profileListHint},
		{name: "invalid environment profile", file: withCurrent, env: "SECRET\n", hint: profileListHint},
		{name: "invalid server", file: withCurrent, server: "http://SECRET.example.com", env: unset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliHome(t)
			if tc.env != unset {
				t.Setenv("CLAVIS_PROFILE", tc.env)
			}
			if tc.file != "" {
				writeConfig(t, tc.file)
			}
			got, failed := resolveTarget(tc.server, tc.profile)
			if tc.origin != "" {
				require.Nil(t, failed)
				assert.Equal(t, target{Origin: tc.origin, Profile: tc.selected}, got)
				return
			}
			require.NotNil(t, failed)
			assert.Equal(t, "INVALID_ARGUMENT", failed.Error.Code)
			assert.Equal(t, tc.hint, failed.Error.Hint)
			assert.NotContains(t, failed.Error.Message, "SECRET")
		})
	}
}

// The former server variable is not a step of resolution.
func TestServerVariableIgnored(t *testing.T) {
	cliHome(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	t.Setenv("CLAVIS_SERVER_URL", server.URL)
	for _, args := range [][]string{{"whoami"}, {"doctor"}, {"users", "list"}} {
		exit, result, _ := strictInvoke(t, "", args...)
		require.Equal(t, 2, exit)
		assert.Equal(t, profileSetupHint, result.Error.Hint)
	}
	writeConfig(t, "[profiles.fce]\nserver = \"https://fce.example.com\"\n")
	exit, result, _ := strictInvoke(t, "", "whoami")
	require.Equal(t, 2, exit)
	assert.Equal(t, profileSetupHint, result.Error.Hint)
	assert.Zero(t, requests)
	requireNoStore(t)
}

func TestLoadConfigRejectsInvalidFiles(t *testing.T) {
	for _, tc := range []struct {
		name, body, key, hint string
	}{
		{name: "unparseable", body: "current = \n", key: "line 1"},
		{name: "keyless syntax error", body: "= 1\n", key: "line 1 is not valid TOML"},
		{name: "unterminated table", body: "[profiles.fce\nserver = \"https://fce.example.com\"\n", key: "line 1"},
		{name: "unknown top-level key", body: "output = \"text\"\n", key: "output is not a known key"},
		{name: "unknown profile key", body: "[profiles.fce]\nserver = \"https://fce.example.com\"\nusername = \"alice\"\n", key: "profiles.fce.username is not a known key"},
		{name: "wrong type", body: "current = 3\n", key: "current"},
		{name: "case-folded current", body: "Current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", key: "Current is not a known key"},
		{name: "case-folded profiles", body: "[Profiles.fce]\nserver = \"https://fce.example.com\"\n", key: "Profiles is not a known key"},
		{name: "case-folded server", body: "[profiles.fce]\nSERVER = \"https://SECRET.example.com\"\n", key: "profiles.fce.SERVER is not a known key"},
		{name: "profile not a table", body: "[profiles]\nfce = \"https://fce.example.com\"\n", key: "profiles.fce"},
		{name: "invalid name", body: "[profiles.Prod]\nserver = \"https://fce.example.com\"\n", key: "profiles.Prod is not a valid profile name", hint: profileNameHint},
		{name: "quoted invalid name", body: "[profiles.\"a b\"]\nserver = \"https://fce.example.com\"\n", key: `profiles."a b" is not a valid profile name`, hint: profileNameHint},
		{name: "uuid name", body: "[profiles.7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba]\nserver = \"https://fce.example.com\"\n", key: "profiles.7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba is not a valid profile name", hint: profileNameHint},
		{name: "missing server", body: "[profiles.fce]\n", key: "profiles.fce.server"},
		{name: "base path server", body: "[profiles.fce]\nserver = \"https://fce.example.com/clavis\"\n", key: "profiles.fce.server"},
		{name: "non-loopback http server", body: "[profiles.fce]\nserver = \"http://fce.example.com\"\n", key: "profiles.fce.server"},
		{name: "dangling current", body: "current = \"prod\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", key: "current names no configured profile"},
		{name: "oversized", body: "# " + strings.Repeat("x", maxConfigBytes) + "\n", key: "larger than 64 KiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliHome(t)
			path := writeConfig(t, tc.body)
			home := filepath.Dir(path)
			_, failed := loadConfig(home)
			require.NotNil(t, failed)
			assert.Equal(t, "INVALID_ARGUMENT", failed.Error.Code)
			assert.True(t, strings.HasPrefix(failed.Error.Message, path+": "), failed.Error.Message)
			assert.NotContains(t, failed.Error.Message, "SECRET", "values are never echoed")
			assert.Contains(t, failed.Error.Message, tc.key)
			assert.Equal(t, tc.hint, failed.Error.Hint)
			// Nothing from a rejected file is used, even a valid profile in it.
			_, resolveFailed := resolveTarget("", "fce")
			require.NotNil(t, resolveFailed)
			assert.Equal(t, failed.Error.Message, resolveFailed.Error.Message)
		})
	}
}

func TestLoadConfigAcceptsValidFiles(t *testing.T) {
	home := cliHome(t)
	config, failed := loadConfig(filepath.Join(home, ".clavis"))
	require.Nil(t, failed)
	assert.Equal(t, clientConfig{}, config)
	require.NoDirExists(t, filepath.Join(home, ".clavis"), "reading creates nothing")
	path := writeConfig(t, "# hand-written\ncurrent = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n\n[profiles.\"local-dev\"]\nserver = \"http://[::1]:8080/\"\n")
	config, failed = loadConfig(filepath.Dir(path))
	require.Nil(t, failed)
	assert.Equal(t, clientConfig{Current: "fce", Profiles: map[string]clientProfile{
		"fce": {Server: "https://fce.example.com"}, "local-dev": {Server: "http://[::1]:8080/"},
	}}, config)
	got, failed := resolveTarget("", "local-dev")
	require.Nil(t, failed)
	assert.Equal(t, "http://[::1]:8080", got.Origin)
	// The bound is inclusive: a file of exactly 64 KiB still loads.
	path = writeConfig(t, "# "+strings.Repeat("x", maxConfigBytes-3)+"\n")
	_, failed = loadConfig(filepath.Dir(path))
	require.Nil(t, failed)
}

func TestLoadConfigRefusesLinksAndSpecialFiles(t *testing.T) {
	const valid = "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n"
	for _, kind := range []string{"symlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			home := cliHome(t)
			clavis := filepath.Join(home, ".clavis")
			require.NoError(t, os.MkdirAll(clavis, 0o700))
			path := filepath.Join(clavis, "config.toml")
			switch kind {
			case "symlink":
				real := filepath.Join(home, "real.toml")
				require.NoError(t, os.WriteFile(real, []byte(valid), 0o600))
				require.NoError(t, os.Symlink(real, path))
				t.Cleanup(func() {
					body, err := os.ReadFile(real)
					require.NoError(t, err)
					assert.Equal(t, valid, string(body), "the link's target is unchanged")
				})
			case "directory":
				require.NoError(t, os.Mkdir(path, 0o700))
			case "fifo":
				require.NoError(t, syscall.Mkfifo(path, 0o600))
			}
			for _, args := range [][]string{{"whoami"}, {"doctor"}, {"login", "--username=cli-test", "--password-stdin"}} {
				exit, result, unread := strictInvoke(t, "password-that-stays", args...)
				require.Equal(t, 2, exit)
				assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
				assert.Equal(t, path+": must be a regular file", result.Error.Message)
				assert.Equal(t, len("password-that-stays"), unread)
			}
			requireNoStore(t)
		})
	}
}

// A direct server never depends on the file, so a broken one cannot stop it.
func TestDirectServerIgnoresCorruptConfig(t *testing.T) {
	cliHome(t)
	writeConfig(t, "output = \"text\"\n")
	fixture, server := newCLIFixture(t, testToken())
	exit, result, _ := strictInvoke(t, "", "whoami", "--server", server.URL)
	require.Equal(t, 1, exit)
	assert.Equal(t, auth.Unauthenticated, result.Error.Code)
	fixture.mu.Lock()
	assert.Equal(t, 1, fixture.requests, "the request reached the direct server")
	fixture.mu.Unlock()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"status":"ready"}`) }))
	defer ready.Close()
	exit, _, _ = strictInvoke(t, "", "doctor", "--server", ready.URL)
	require.Equal(t, 0, exit)
	exit, result, _ = strictInvoke(t, "", "whoami")
	require.Equal(t, 2, exit)
	assert.Contains(t, result.Error.Message, "output is not a known key")
}

// Resolution runs before any password, secret or statement input and before
// the session store is opened.
func TestResolutionFailsBeforeInputAndStorage(t *testing.T) {
	const password = "correct-horse-battery-staple"
	for _, tc := range []struct {
		name string
		file string
		env  map[string]string
		args []string
		want string
	}{
		{name: "login with a corrupt file", file: "[profiles.fce]\nserver = \"https://fce.example.com\"\nextra = 1\n",
			args: []string{"login", "--profile", "fce", "--username=cli-test", "--password-stdin"}, want: "config.toml: profiles.fce.extra is not a known key"},
		{name: "relative home", env: map[string]string{"CLAVIS_HOME": "relative/dir"},
			args: []string{"login", "--server", "https://clavis.example.com", "--username=cli-test", "--password-stdin"}, want: "CLAVIS_HOME must be an absolute path"},
		{name: "relative home before argument checks", env: map[string]string{"CLAVIS_HOME": "relative/dir"},
			args: []string{"login", "--server", "SECRET", "--password-stdin"}, want: "CLAVIS_HOME must be an absolute path"},
		{name: "empty server flag", file: "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", args: []string{"login", "--server=", "--username=cli-test", "--password-stdin"}, want: "--server must not be empty"},
		{name: "empty quoted server flag", file: "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", args: []string{"whoami", "--server", ""}, want: "--server must not be empty"},
		{name: "empty profile flag", file: "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", args: []string{"login", "--profile=", "--username=cli-test", "--password-stdin"}, want: "--profile must not be empty"},
		{name: "empty server with a profile", file: "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", args: []string{"login", "--server=", "--profile", "fce", "--username=cli-test", "--password-stdin"}, want: "--server must not be empty"},
		{name: "empty doctor flags", file: "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", args: []string{"doctor", "--server=", "--profile", "fce"}, want: "--server must not be empty"},
		{name: "empty doctor profile", file: "current = \"fce\"\n\n[profiles.fce]\nserver = \"https://fce.example.com\"\n", args: []string{"doctor", "--profile="}, want: "--profile must not be empty"},
		{name: "server and profile", args: []string{"login", "--server", "https://clavis.example.com", "--profile", "fce", "--username=cli-test", "--password-stdin"}, want: "not both"},
		{name: "unknown profile for a new user", file: "[profiles.fce]\nserver = \"https://fce.example.com\"\n",
			args: []string{"users", "create", "--profile", "prod", "--username=alice", "--password-stdin"}, want: "No profile named prod"},
		{name: "nothing configured for a query", args: []string{"query", "--connection", "payments", "--sql-stdin"}, want: "No server is configured"},
		{name: "unknown environment profile for a secret", file: "[profiles.fce]\nserver = \"https://fce.example.com\"\n", env: map[string]string{"CLAVIS_PROFILE": "prod"},
			args: []string{"connections", "set-credentials", "--connection", "payments", "--password-stdin"}, want: "No profile named prod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliHome(t)
			if tc.file != "" {
				writeConfig(t, tc.file)
			}
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			exit, result, unread := strictInvoke(t, password, tc.args...)
			require.Equal(t, 2, exit)
			assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
			assert.Contains(t, result.Error.Message, tc.want)
			assert.NotContains(t, result.Error.Message, "SECRET")
			assert.Equal(t, len(password), unread, "stdin must not be read")
			require.NoDirExists(t, "relative")
			t.Setenv("CLAVIS_HOME", "")
			requireNoStore(t)
		})
	}
}

// Commands reach the server resolution picked, and login never writes the
// configuration.
func TestProfilesSelectTheServer(t *testing.T) {
	home := cliHome(t)
	password := testToken()
	fce, fceServer := newCLIFixture(t, password)
	local, localServer := newCLIFixture(t, password)
	path := writeConfig(t, "# written by hand\ncurrent = \"fce\"\n\n[profiles.fce]\nserver = \""+fceServer.URL+"\"\n\n[profiles.local]\nserver = \""+localServer.URL+"/\"\n")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, os.Chtimes(path, old, old))
	logins := func() (int, int) {
		fce.mu.Lock()
		defer fce.mu.Unlock()
		local.mu.Lock()
		defer local.mu.Unlock()
		return fce.login, local.login
	}

	exit, _, _ := cliInvoke(t, string(password), "login", "--username=cli-test", "--password-stdin")
	require.Equal(t, 0, exit)
	fceLogins, localLogins := logins()
	assert.Equal(t, [2]int{1, 0}, [2]int{fceLogins, localLogins}, "login goes to the current profile")
	exit, _, _ = cliInvoke(t, string(password), "login", "--profile", "local", "--username=cli-test", "--password-stdin")
	require.Equal(t, 0, exit)
	t.Setenv("CLAVIS_PROFILE", "local")
	exit, _, _ = cliInvoke(t, string(password), "login", "--username=cli-test", "--password-stdin")
	require.Equal(t, 0, exit)
	fceLogins, localLogins = logins()
	assert.Equal(t, [2]int{1, 2}, [2]int{fceLogins, localLogins})
	t.Setenv("CLAVIS_PROFILE", "")
	exit, _, _ = cliInvoke(t, string(password), "login", "--server", fceServer.URL, "--username=cli-test", "--password-stdin")
	require.Equal(t, 0, exit)

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "login never writes the configuration")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(old), "login never rewrites the configuration")
	entries, err := os.ReadDir(filepath.Join(home, ".clavis"))
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	assert.Equal(t, []string{"config.toml", "sessions"}, names)

	// Each result names the server it went to and the profile that chose it.
	whoami := func(server, profile string, args ...string) (int, int) {
		t.Helper()
		exit, result, _ := cliInvoke(t, "", append([]string{"whoami"}, args...)...)
		require.Equal(t, 0, exit)
		require.NotNil(t, result.Server)
		require.NotNil(t, result.Profile)
		assert.Equal(t, [2]string{server, profile}, [2]string{*result.Server, *result.Profile})
		fce.mu.Lock()
		defer fce.mu.Unlock()
		local.mu.Lock()
		defer local.mu.Unlock()
		return fce.whoami, local.whoami
	}
	f, l := whoami(fceServer.URL, "fce")
	assert.Equal(t, [2]int{1, 0}, [2]int{f, l}, "current profile")
	t.Setenv("CLAVIS_PROFILE", "local")
	f, l = whoami(localServer.URL, "local")
	assert.Equal(t, [2]int{1, 1}, [2]int{f, l}, "environment beats current")
	f, l = whoami(fceServer.URL, "fce", "--profile", "fce")
	assert.Equal(t, [2]int{2, 1}, [2]int{f, l}, "flag beats environment")
	f, l = whoami(localServer.URL, "", "--server", localServer.URL)
	assert.Equal(t, [2]int{2, 2}, [2]int{f, l}, "a direct server")

	ready := 0
	doctorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready++
		assert.Equal(t, "/readyz", r.URL.Path)
		_, _ = io.WriteString(w, `{"status":"ready"}`)
	}))
	defer doctorServer.Close()
	t.Setenv("CLAVIS_PROFILE", "")
	writeConfig(t, "current = \"fce\"\n\n[profiles.fce]\nserver = \""+doctorServer.URL+"\"\n")
	code, out := invoke(t, "doctor")
	require.Equal(t, 0, code)
	diagnosis := decode(t, out)
	assert.True(t, diagnosis.OK)
	require.NotNil(t, diagnosis.Server)
	require.NotNil(t, diagnosis.Profile)
	assert.Equal(t, [2]string{doctorServer.URL, "fce"}, [2]string{*diagnosis.Server, *diagnosis.Profile})
	assert.Equal(t, 1, ready, "doctor checks the current profile's server")
}

func TestProfilesNamingOneServerShareASession(t *testing.T) {
	cliHome(t)
	password := testToken()
	_, server := newCLIFixture(t, password)
	writeConfig(t, "current = \"prod\"\n\n[profiles.prod]\nserver = \""+server.URL+"\"\n\n[profiles.prod-admin]\nserver = \""+server.URL+"/\"\n")

	exit, _, _ := cliInvoke(t, string(password), "login", "--username=cli-test", "--password-stdin")
	require.Equal(t, 0, exit)
	// Sessions are keyed by origin, so the other profile needs no sign-in.
	exit, result, _ := cliInvoke(t, "", "whoami", "--profile", "prod-admin")
	require.Equal(t, 0, exit)
	assert.Equal(t, "prod-admin", *result.Profile)
	// Signing out through one profile signs out the other.
	exit, _, _ = cliInvoke(t, "", "logout", "--profile", "prod-admin")
	require.Equal(t, 0, exit)
	exit, result, _ = cliInvoke(t, "", "whoami")
	require.Equal(t, 1, exit)
	assert.Equal(t, auth.Unauthenticated, result.Error.Code)
}
