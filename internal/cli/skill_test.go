package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heurema/clavis/internal/skill"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skillEnvelope decodes the install report into its own shape rather than a
// map, so a renamed field is a compilation failure here as well as a contract
// change there.
type skillEnvelope struct {
	SchemaVersion int          `json:"schemaVersion"`
	OK            bool         `json:"ok"`
	Data          SkillInstall `json:"data"`
	Error         *Error       `json:"error"`
}

func install(t *testing.T, args ...string) (int, skillEnvelope) {
	t.Helper()
	code, out := invoke(t, append([]string{"skill", "install"}, args...)...)
	var value skillEnvelope
	require.NoError(t, json.Unmarshal([]byte(out), &value), "install output: %s", out)
	assert.Equal(t, 1, value.SchemaVersion)
	return code, value
}

// skillDirectory is the path one agent's skill lands at under a root.
func skillDirectory(root, base string) string {
	return filepath.Join(root, base, "skills", skill.Directory)
}

// assertInstalled checks the directory holds every embedded document exactly
// as it renders, which is what an agent will read.
func assertInstalled(t *testing.T, path string) {
	t.Helper()
	for _, name := range skill.Names() {
		want, err := skill.Render(name)
		require.NoError(t, err)
		got, err := os.ReadFile(filepath.Join(path, name))
		require.NoError(t, err, "%s is installed", name)
		assert.Equal(t, string(want), string(got))
		info, err := os.Stat(filepath.Join(path, name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	}
	version, ok := skill.Marker(readFile(t, filepath.Join(path, skill.Entry)))
	assert.True(t, ok, "the installed entry carries the marker")
	assert.Equal(t, skill.Version(), version)
}

// resolvedTempDir is a temporary directory named the way the process itself
// will name it, so a path the CLI reports can be compared with one a test
// built. On macOS the temporary root is reached through a symbolic link.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return path
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	return body
}

// seed writes a directory as if an earlier CLI, or something else entirely,
// had put it there.
func seed(t *testing.T, path, entry string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(path, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(path, skill.Entry), []byte(entry), 0o644))
}

func TestSkillInstallDetectsEveryAgentPresent(t *testing.T) {
	home := cliHome(t)
	for _, base := range []string{".claude", ".codex"} {
		require.NoError(t, os.MkdirAll(filepath.Join(home, base, "skills"), 0o755))
	}
	code, result := install(t)
	require.Equal(t, 0, code)
	require.True(t, result.OK)
	require.Nil(t, result.Error)
	assert.Equal(t, skill.Version(), result.Data.Version)
	assert.False(t, result.Data.DryRun)
	require.Len(t, result.Data.Targets, 2)
	for index, base := range []string{".claude", ".codex"} {
		target := result.Data.Targets[index]
		assert.Equal(t, []string{"claude", "codex"}[index], target.Agent)
		assert.Equal(t, skillDirectory(home, base), target.Path)
		assert.True(t, filepath.IsAbs(target.Path))
		assert.Equal(t, outcomeWritten, target.Outcome)
		assert.Empty(t, target.PreviousVersion)
		assertInstalled(t, target.Path)
	}
}

func TestSkillInstallCreatesClaudeWhenNothingIsPresent(t *testing.T) {
	home := cliHome(t)
	code, result := install(t)
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, "claude", result.Data.Targets[0].Agent)
	assert.Equal(t, skillDirectory(home, ".claude"), result.Data.Targets[0].Path)
	assert.Equal(t, outcomeWritten, result.Data.Targets[0].Outcome)
	assertInstalled(t, result.Data.Targets[0].Path)
	assert.NoDirExists(t, filepath.Join(home, ".codex"), "nothing is created for an agent that is not there")
}

func TestSkillInstallNamedAgentCreatesOnlyThatOne(t *testing.T) {
	home := cliHome(t)
	code, result := install(t, "--agent", "codex")
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, "codex", result.Data.Targets[0].Agent)
	assert.Equal(t, skillDirectory(home, ".codex"), result.Data.Targets[0].Path)
	assertInstalled(t, result.Data.Targets[0].Path)
	assert.NoDirExists(t, filepath.Join(home, ".claude"))
	// Repeating the flag names both, and naming one twice names it once.
	cliHome(t)
	code, result = install(t, "--agent", "claude", "--agent", "codex", "--agent", "claude")
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 2)
	assert.Equal(t, []string{"claude", "codex"},
		[]string{result.Data.Targets[0].Agent, result.Data.Targets[1].Agent})
}

func TestSkillInstallUpdatesItsOwnEarlierCopy(t *testing.T) {
	home := cliHome(t)
	path := skillDirectory(home, ".claude")
	seed(t, path, "---\nname: clavis\n"+skill.MarkerField+": 0.5\n---\nstale\n")
	code, result := install(t)
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, outcomeUpdated, result.Data.Targets[0].Outcome)
	assert.Equal(t, "0.5", result.Data.Targets[0].PreviousVersion)
	assertInstalled(t, path)
	// Reinstalling the same build writes nothing and says so, without a
	// previous version: nothing was replaced.
	code, result = install(t)
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeUnchanged, result.Data.Targets[0].Outcome)
	assert.Empty(t, result.Data.Targets[0].PreviousVersion)
	assertInstalled(t, path)
}

func TestSkillInstallLeavesFilesItDoesNotOwnAlone(t *testing.T) {
	home := cliHome(t)
	path := skillDirectory(home, ".claude")
	require.Equal(t, 0, mustInstall(t))
	extra := filepath.Join(path, "notes.md")
	require.NoError(t, os.WriteFile(extra, []byte("mine\n"), 0o644))
	code, result := install(t)
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeUnchanged, result.Data.Targets[0].Outcome)
	assert.Equal(t, "mine\n", string(readFile(t, extra)), "a file that is not ours is never removed")
}

func mustInstall(t *testing.T, args ...string) int {
	t.Helper()
	code, _ := install(t, args...)
	return code
}

func TestSkillInstallRefusesAForeignDirectoryUntilForced(t *testing.T) {
	home := cliHome(t)
	path := skillDirectory(home, ".claude")
	foreign := "---\nname: someone-else\n---\nnot ours\n"
	seed(t, path, foreign)
	code, result := install(t)
	require.Equal(t, 2, code)
	require.False(t, result.OK)
	require.NotNil(t, result.Error)
	assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
	assert.Equal(t, skillForceHint, result.Error.Hint)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, outcomeRefused, result.Data.Targets[0].Outcome)
	assert.Equal(t, path, result.Data.Targets[0].Path)
	assert.Equal(t, foreign, string(readFile(t, filepath.Join(path, skill.Entry))), "the directory is untouched")
	code, result = install(t, "--force")
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeWritten, result.Data.Targets[0].Outcome)
	assert.Empty(t, result.Data.Targets[0].PreviousVersion)
	assertInstalled(t, path)
}

func TestSkillInstallRefusesADirectoryHoldingSomethingElse(t *testing.T) {
	home := cliHome(t)
	path := skillDirectory(home, ".claude")
	require.NoError(t, os.MkdirAll(path, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(path, "other.md"), []byte("x"), 0o644))
	code, result := install(t)
	require.Equal(t, 2, code)
	assert.Equal(t, outcomeRefused, result.Data.Targets[0].Outcome)
	assert.NoFileExists(t, filepath.Join(path, skill.Entry))
}

func TestSkillInstallReportsEveryTargetWhenOneIsRefused(t *testing.T) {
	home := cliHome(t)
	claude, codex := skillDirectory(home, ".claude"), skillDirectory(home, ".codex")
	seed(t, claude, "---\nname: someone-else\n---\nnot ours\n")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".codex", "skills"), 0o755))
	code, result := install(t)
	require.Equal(t, 2, code)
	require.NotNil(t, result.Error)
	assert.Equal(t, skillForceHint, result.Error.Hint)
	require.Len(t, result.Data.Targets, 2, "a refusal never stops the other targets")
	assert.Equal(t, outcomeRefused, result.Data.Targets[0].Outcome)
	assert.Equal(t, outcomeWritten, result.Data.Targets[1].Outcome)
	assert.Equal(t, codex, result.Data.Targets[1].Path)
	assertInstalled(t, codex)
}

func TestSkillInstallProjectScopeStaysInTheWorkingDirectory(t *testing.T) {
	home := cliHome(t)
	project := resolvedTempDir(t)
	t.Chdir(project)
	// With no agent directory in the project nothing is guessed.
	code, result := install(t, "--scope", "project")
	require.Equal(t, 2, code)
	require.NotNil(t, result.Error)
	assert.Equal(t, skillProjectHint, result.Error.Hint)
	assert.Empty(t, result.Data.Targets)
	require.NoError(t, os.MkdirAll(filepath.Join(project, ".claude", "skills"), 0o755))
	code, result = install(t, "--scope", "project")
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, skillDirectory(project, ".claude"), result.Data.Targets[0].Path)
	assertInstalled(t, result.Data.Targets[0].Path)
	assert.NoDirExists(t, filepath.Join(home, ".claude"), "nothing is written under the home directory")
	// A named agent creates the project directory it was told to.
	code, result = install(t, "--scope", "project", "--agent", "codex")
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, skillDirectory(project, ".codex"), result.Data.Targets[0].Path)
	assert.NoDirExists(t, filepath.Join(home, ".codex"))
}

func TestSkillInstallExplicitDirectory(t *testing.T) {
	home := cliHome(t)
	target := resolvedTempDir(t)
	code, result := install(t, "--dir", target)
	require.Equal(t, 0, code)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, dirAgent, result.Data.Targets[0].Agent)
	assert.Equal(t, filepath.Join(target, skill.Directory), result.Data.Targets[0].Path)
	assertInstalled(t, result.Data.Targets[0].Path)
	assert.NoDirExists(t, filepath.Join(home, ".claude"))
	// A directory that does not exist yet is created along the way.
	nested := filepath.Join(target, "a", "b")
	code, result = install(t, "--dir", nested)
	require.Equal(t, 0, code)
	assert.Equal(t, filepath.Join(nested, skill.Directory), result.Data.Targets[0].Path)
	assertInstalled(t, result.Data.Targets[0].Path)
}

func TestSkillInstallDryRunWritesNothing(t *testing.T) {
	home := cliHome(t)
	code, result := install(t, "--dry-run")
	require.Equal(t, 0, code)
	assert.True(t, result.Data.DryRun)
	require.Len(t, result.Data.Targets, 1)
	assert.Equal(t, outcomeWritten, result.Data.Targets[0].Outcome)
	assert.NoDirExists(t, filepath.Join(home, ".claude"), "a dry run creates no directory either")
	// The same outcomes are reported over a real installation.
	require.Equal(t, 0, mustInstall(t))
	code, result = install(t, "--dry-run")
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeUnchanged, result.Data.Targets[0].Outcome)
	seed(t, skillDirectory(home, ".claude"), "---\nname: someone-else\n---\n")
	code, result = install(t, "--dry-run")
	require.Equal(t, 2, code)
	assert.Equal(t, outcomeRefused, result.Data.Targets[0].Outcome)
	code, result = install(t, "--dry-run", "--force")
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeWritten, result.Data.Targets[0].Outcome)
	assert.Equal(t, "---\nname: someone-else\n---\n",
		string(readFile(t, filepath.Join(skillDirectory(home, ".claude"), skill.Entry))))
}

func TestSkillInstallDryRunReportsAnUpdateWithoutWriting(t *testing.T) {
	home := cliHome(t)
	path := skillDirectory(home, ".claude")
	stale := "---\nname: clavis\n" + skill.MarkerField + ": 0.4\n---\nstale\n"
	seed(t, path, stale)
	code, result := install(t, "--dry-run")
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeUpdated, result.Data.Targets[0].Outcome)
	assert.Equal(t, "0.4", result.Data.Targets[0].PreviousVersion)
	assert.Equal(t, stale, string(readFile(t, filepath.Join(path, skill.Entry))))
	assert.NoFileExists(t, filepath.Join(path, "postgresql.md"))
}

func TestSkillInstallTextOutput(t *testing.T) {
	home := cliHome(t)
	path := skillDirectory(home, ".claude")
	seed(t, path, "---\nname: clavis\n"+skill.MarkerField+": 0.5\n---\nstale\n")
	code, out := invoke(t, "--output", "text", "skill", "install")
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeUpdated+"\t"+path+" (was 0.5)\nVersion: "+skill.Version()+"\n", out)
	code, out = invoke(t, "--output", "text", "skill", "install", "--dry-run")
	require.Equal(t, 0, code)
	assert.Equal(t, outcomeUnchanged+"\t"+path+"\nDry run: true\nVersion: "+skill.Version()+"\n", out)
}

func TestSkillInstallRefusesArgumentsItCannotMean(t *testing.T) {
	home := cliHome(t)
	for name, tc := range map[string]struct {
		args []string
		hint string
	}{
		"unknown agent":   {[]string{"--agent", "cursor"}, skillAgentHint},
		"empty agent":     {[]string{"--agent", ""}, skillAgentHint},
		"unknown scope":   {[]string{"--scope", "machine"}, skillScopeHint},
		"relative dir":    {[]string{"--dir", "skills"}, skillDirHint},
		"dir with agent":  {[]string{"--dir", "/tmp/x", "--agent", "claude"}, skillDirHint},
		"dir with scope":  {[]string{"--dir", "/tmp/x", "--scope", "user"}, skillDirHint},
		"positional":      {[]string{"claude"}, ""},
		"unknown flag":    {[]string{"--everywhere"}, ""},
		"unknown subverb": {[]string{"--agent", "claude", "--uninstall"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, result := install(t, tc.args...)
			assert.Equal(t, 2, code)
			assert.False(t, result.OK)
			require.NotNil(t, result.Error)
			assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
			if tc.hint != "" {
				assert.Equal(t, tc.hint, result.Error.Hint)
			}
			assert.Empty(t, result.Data.Targets)
		})
	}
	assert.NoDirExists(t, filepath.Join(home, ".claude"), "a refused invocation writes nothing")
}

func TestSkillInstallReportsAnUnwritableDirectoryWithoutItsContents(t *testing.T) {
	cliHome(t)
	root := resolvedTempDir(t)
	closed := filepath.Join(root, "closed")
	require.NoError(t, os.Mkdir(closed, 0o500))
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	code, result := install(t, "--dir", closed)
	require.Equal(t, 2, code)
	require.NotNil(t, result.Error)
	assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
	assert.Contains(t, result.Error.Hint, filepath.Join(closed, skill.Directory))
	assert.NotContains(t, result.Error.Message, "clavis skill")
}

func TestSkillInstallNeedsNoSessionOrServer(t *testing.T) {
	home := cliHome(t)
	t.Setenv("CLAVIS_SERVER_URL", "http://SECRET.invalid")
	code, result := install(t)
	require.Equal(t, 0, code)
	require.True(t, result.OK)
	config, err := os.UserConfigDir()
	require.NoError(t, err)
	assert.NoDirExists(t, filepath.Join(config, "clavis"), "no session storage is opened")
	assert.NoDirExists(t, filepath.Join(home, ".config", "clavis"))
	// The offline commands take neither of the two networked flags.
	for _, args := range [][]string{
		{"skill", "install", "--server", "http://127.0.0.1:8080"},
		{"skill", "install", "--timeout", "5s"},
		{"skill", "show", "--server", "http://127.0.0.1:8080"},
	} {
		code, out := invoke(t, args...)
		assert.Equal(t, 2, code, strings.Join(args, " "))
		assert.NotContains(t, out, "SECRET")
	}
}

func TestSkillShowPrintsTheDocumentAndNothingElse(t *testing.T) {
	cliHome(t)
	entry, err := skill.Render(skill.Entry)
	require.NoError(t, err)
	for _, args := range [][]string{
		{"skill", "show"}, {"skill", "show", "--file", skill.Entry},
		{"--output", "text", "skill", "show"}, {"--output", "json", "skill", "show"},
	} {
		code, out := invoke(t, args...)
		assert.Equal(t, 0, code, strings.Join(args, " "))
		assert.Equal(t, string(entry), out, "no envelope is wrapped around the document")
	}
	for _, name := range []string{"postgresql.md", "victoriametrics.md", "victorialogs.md"} {
		body, err := skill.Render(name)
		require.NoError(t, err)
		code, out := invoke(t, "skill", "show", "--file", name)
		assert.Equal(t, 0, code)
		assert.Equal(t, string(body), out)
	}
}

func TestSkillShowRefusesAnUnknownFile(t *testing.T) {
	cliHome(t)
	for _, name := range []string{"mysql.md", "", "../skill_commands.go", "SKILL.MD"} {
		code, out := invoke(t, "skill", "show", "--file", name)
		assert.Equal(t, 2, code, name)
		result := decode(t, out)
		require.NotNil(t, result.Error)
		assert.Equal(t, "INVALID_ARGUMENT", result.Error.Code)
		assert.Equal(t, skillFileHint(), result.Error.Hint)
		for _, embedded := range skill.Names() {
			assert.Contains(t, result.Error.Hint, embedded)
		}
	}
}

func TestSkillGroupShowsItsOwnHelp(t *testing.T) {
	cliHome(t)
	code, out := invoke(t, "skill")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "install")
	assert.Contains(t, out, "show")
}
