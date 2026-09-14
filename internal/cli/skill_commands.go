package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/skill"
	urfave "github.com/urfave/cli/v3"
)

// The skill group is offline: neither command reads the stored session, takes
// a --server or a --timeout, or makes a request. The document is embedded in
// this binary, so installing it and printing it are file operations.

// skillAgents are the agents whose skill directories the installer knows, in
// the order a report lists them. The base is the agent's own directory under
// the scope root, and both agents read the same directory format, so one
// rendering serves both.
var skillAgents = []struct{ name, base string }{{"claude", ".claude"}, {"codex", ".codex"}}

// skillsComponent is the directory each agent keeps its skills in.
const skillsComponent = "skills"

// dirAgent labels the target an explicit --dir produced, which belongs to no
// agent: the caller named the directory, so the report names the caller's word
// for it rather than inventing an owner.
const dirAgent = "dir"

// The four outcomes one target can have. They are the whole vocabulary of the
// report: nothing is ever deleted, so there is no outcome for a removal.
const (
	outcomeWritten   = "written"
	outcomeUpdated   = "updated"
	outcomeUnchanged = "unchanged"
	outcomeRefused   = "refused"
)

// skillForceHint names the one flag that replaces a skill directory clavis did
// not install. It is quoted in the refusal of every such target.
const skillForceHint = "Use --force to replace a skill directory that clavis did not install"

// skillAgentHint names the agents the installer knows.
const skillAgentHint = "--agent accepts claude or codex; repeat it to install for both"

// skillScopeHint names the two roots a scope chooses between.
const skillScopeHint = "--scope accepts user for the home directory or project for the working directory"

// skillDirHint states what --dir is: one absolute directory that receives the
// clavis directory, chosen instead of an agent and a scope rather than beside
// them.
const skillDirHint = "--dir takes one absolute directory path and replaces --agent and --scope"

// skillProjectHint states the one case the installer refuses to guess: a
// repository is not the installer's to shape, so a project directory is
// created only for an agent the caller named.
const skillProjectHint = "Pass --agent claude or --agent codex to create a project skill directory"

// skillOutputHint covers the one failure printing a document can have.
const skillOutputHint = "Redirect stdout to a writable destination"

// SkillTarget is one directory the installer considered and what became of it.
// The path is the clavis directory itself, absolute, so a reader can go
// straight to what was written.
type SkillTarget struct {
	Agent           string `json:"agent"`
	Path            string `json:"path"`
	Outcome         string `json:"outcome"`
	PreviousVersion string `json:"previousVersion,omitempty"`
}

// SkillInstall is the install report. Every target is listed whatever happened
// to it, including on a refusal, so one run says what the machine now holds.
type SkillInstall struct {
	Version string        `json:"version"`
	Targets []SkillTarget `json:"targets"`
	DryRun  bool          `json:"dryRun,omitempty"`
}

// skillDocument is one rendered file on its way to a target.
type skillDocument struct {
	name string
	body []byte
}

// skillCommands builds the offline group. It takes no server flag and no
// timeout: there is nothing to wait for but the file system.
func skillCommands(streams IO, check func(*urfave.Command) error, set func(Result)) *urfave.Command {
	return &urfave.Command{
		Name: "skill", Usage: "Install or print the agent skill embedded in this binary",
		Action: func(ctx context.Context, command *urfave.Command) error {
			if err := check(command); err != nil {
				return err
			}
			return urfave.ShowSubcommandHelp(command)
		},
		Commands: []*urfave.Command{
			{Name: "install", Usage: "Write the skill into the agent skill directories on this machine", Flags: []urfave.Flag{
				&urfave.StringSliceFlag{Name: "agent", Usage: "Agent to install for: claude or codex; repeat to name both"},
				&urfave.StringFlag{Name: "scope", Value: "user", Usage: "Install root: user for the home directory or project for the working directory"},
				&urfave.StringFlag{Name: "dir", Usage: "Absolute directory that receives the clavis directory, instead of an agent and a scope"},
				&urfave.BoolFlag{Name: "force", Usage: "Replace a clavis directory that carries no clavis marker"},
				&urfave.BoolFlag{Name: "dry-run", Usage: "Report what would be written without writing anything"},
			}, Action: func(ctx context.Context, command *urfave.Command) error {
				if err := check(command); err != nil {
					return err
				}
				set(runSkillInstall(command))
				return nil
			}},
			{Name: "show", Usage: "Print one embedded skill file to stdout", Flags: []urfave.Flag{
				&urfave.StringFlag{Name: "file", Value: skill.Entry, Usage: "Embedded file to print"},
			}, Action: func(ctx context.Context, command *urfave.Command) error {
				if err := check(command); err != nil {
					return err
				}
				return showSkill(streams, command.String("file"), set)
			}},
		},
	}
}

// showSkill writes the document and nothing else, whatever --output says: the
// document is the output, and an envelope around it would have to be stripped
// before anything could read it. Only a refusal produces one.
func showSkill(streams IO, name string, set func(Result)) error {
	body, err := skill.Render(name)
	if err != nil {
		set(failureWithHint(auth.InvalidArgument, "Provide an embedded skill file name", skillFileHint()))
		return nil
	}
	if _, err := streams.Stdout.Write(body); err != nil {
		set(failureWithHint(auth.InvalidArgument, "Could not write the skill file to the output stream", skillOutputHint))
	}
	return nil
}

// skillFileHint lists what --file accepts, built from the embedded names so it
// cannot name a file the binary lacks.
func skillFileHint() string {
	return "--file accepts " + strings.Join(skill.Names(), ", ")
}

// runSkillInstall resolves the targets, then handles each one in turn. Every
// target is handled before a refusal decides the exit code, so one foreign
// directory never stops the others from being installed.
func runSkillInstall(command *urfave.Command) Result {
	agents, failed := skillAgentSelection(command)
	if failed != nil {
		return *failed
	}
	targets, failed := skillTargets(command, agents)
	if failed != nil {
		return *failed
	}
	documents, err := skillDocuments()
	if err != nil {
		return failureWithHint(auth.InvalidArgument, "The embedded skill could not be rendered", skillFileHint())
	}
	report := SkillInstall{Version: skill.Version(), Targets: make([]SkillTarget, 0, len(targets)), DryRun: command.Bool("dry-run")}
	refused := false
	for _, target := range targets {
		handled, failed := installSkill(target, documents, command.Bool("force"), command.Bool("dry-run"))
		if failed != nil {
			return *failed
		}
		refused = refused || handled.Outcome == outcomeRefused
		report.Targets = append(report.Targets, handled)
	}
	if refused {
		// The report travels with the refusal: the caller needs to know which
		// targets were installed as much as which one was not.
		result := failure(auth.InvalidArgument, "Refused a skill directory clavis did not install", report)
		result.Error.Hint = skillForceHint
		return result
	}
	return success(report)
}

// skillAgentSelection reads --agent, refusing an agent the installer does not
// know and the combination --dir excludes. An empty selection means detect.
func skillAgentSelection(command *urfave.Command) ([]string, *Result) {
	if command.IsSet("dir") && (command.IsSet("agent") || command.IsSet("scope")) {
		return nil, argumentFailure("Provide --dir instead of --agent or --scope", skillDirHint)
	}
	names := make([]string, 0, len(skillAgents))
	for _, value := range command.StringSlice("agent") {
		if !slices.ContainsFunc(skillAgents, func(agent struct{ name, base string }) bool { return agent.name == value }) {
			return nil, argumentFailure("Provide a supported agent", skillAgentHint)
		}
		if !slices.Contains(names, value) {
			names = append(names, value)
		}
	}
	return names, nil
}

// skillTargets resolves the directories one run writes into. An explicit --dir
// is the whole answer; otherwise the scope names a root and the agents are
// either the ones named or the ones already present there.
func skillTargets(command *urfave.Command, agents []string) ([]SkillTarget, *Result) {
	if command.IsSet("dir") {
		path := command.String("dir")
		if !filepath.IsAbs(path) {
			return nil, argumentFailure("Provide an absolute --dir path", skillDirHint)
		}
		return []SkillTarget{{Agent: dirAgent, Path: filepath.Join(filepath.Clean(path), skill.Directory)}}, nil
	}
	root, failed := skillScopeRoot(command)
	if failed != nil {
		return nil, failed
	}
	named := len(agents) > 0
	targets := make([]SkillTarget, 0, len(skillAgents))
	for _, agent := range skillAgents {
		if named && !slices.Contains(agents, agent.name) {
			continue
		}
		base := filepath.Join(root, agent.base, skillsComponent)
		// A named agent gets its directory created; an unnamed one is a target
		// only because it is already there, which is what detection means.
		if !named {
			info, err := os.Stat(base)
			if err != nil || !info.IsDir() {
				continue
			}
		}
		targets = append(targets, SkillTarget{Agent: agent.name, Path: filepath.Join(base, skill.Directory)})
	}
	if len(targets) > 0 {
		return targets, nil
	}
	// Nothing to detect. At user scope the agent most likely to read the skill
	// gets the directory, because a machine with no agent directory is a
	// machine being set up; in a project nothing is created without being
	// named, because a repository is not the installer's to shape.
	if command.String("scope") == "project" {
		return nil, argumentFailure("No agent skill directory exists in this project", skillProjectHint)
	}
	fallback := skillAgents[0]
	return []SkillTarget{{Agent: fallback.name,
		Path: filepath.Join(root, fallback.base, skillsComponent, skill.Directory)}}, nil
}

// skillScopeRoot names the directory the agent bases hang under.
func skillScopeRoot(command *urfave.Command) (string, *Result) {
	switch command.String("scope") {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", argumentFailure("Could not resolve the home directory", skillDirHint)
		}
		return home, nil
	case "project":
		working, err := os.Getwd()
		if err != nil || !filepath.IsAbs(working) {
			return "", argumentFailure("Could not resolve the working directory", skillDirHint)
		}
		return working, nil
	}
	return "", argumentFailure("Provide a scope of user or project", skillScopeHint)
}

// skillDocuments renders every embedded file once, in the order they are
// written in, so one run writes one consistent set of documents.
func skillDocuments() ([]skillDocument, error) {
	names := skill.Names()
	if len(names) == 0 {
		return nil, skill.ErrUnknownFile
	}
	documents := make([]skillDocument, 0, len(names))
	for _, name := range names {
		body, err := skill.Render(name)
		if err != nil {
			return nil, err
		}
		documents = append(documents, skillDocument{name: name, body: body})
	}
	return documents, nil
}

// skillOwner is what the installer can tell about a target directory before it
// writes anything: whether it exists at all, and whether the entry in it
// carries the marker that makes it ours to replace.
type skillOwner struct {
	version string
	owned   bool
	present bool
}

// installSkill handles one target: refuse a directory that is not ours, then
// write the documents that are absent or different and report which of the
// four outcomes that was. Files in the directory that are not ours are left
// exactly as they are; nothing is ever removed.
func installSkill(target SkillTarget, documents []skillDocument, force, dryRun bool) (SkillTarget, *Result) {
	owner, err := skillOwnership(target.Path)
	if err != nil {
		return target, skillIOFailure(target.Path)
	}
	if owner.present && !owner.owned && !force {
		target.Outcome = outcomeRefused
		return target, nil
	}
	pending, err := skillPending(target.Path, documents)
	if err != nil {
		return target, skillIOFailure(target.Path)
	}
	switch {
	case len(pending) == 0:
		target.Outcome = outcomeUnchanged
	case owner.owned:
		target.Outcome, target.PreviousVersion = outcomeUpdated, owner.version
	default:
		target.Outcome = outcomeWritten
	}
	if dryRun || len(pending) == 0 {
		return target, nil
	}
	if err := writeSkill(target.Path, pending); err != nil {
		return target, skillIOFailure(target.Path)
	}
	return target, nil
}

// skillOwnership reads the marker out of the target's entry document. A
// directory holding no entry at all is as foreign as one holding a wrong
// marker: something else put it there, and only --force may replace it.
func skillOwnership(path string) (skillOwner, error) {
	entry, err := os.ReadFile(filepath.Join(path, skill.Entry))
	if err == nil {
		version, owned := skill.Marker(entry)
		return skillOwner{version: version, owned: owned, present: true}, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return skillOwner{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return skillOwner{present: true}, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return skillOwner{}, err
	}
	return skillOwner{}, nil
}

// skillPending keeps the documents a target does not already hold byte for
// byte, so reinstalling an unchanged skill writes nothing at all.
func skillPending(path string, documents []skillDocument) ([]skillDocument, error) {
	pending := make([]skillDocument, 0, len(documents))
	for _, document := range documents {
		current, err := os.ReadFile(filepath.Join(path, document.name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, err
		case bytes.Equal(current, document.body):
			continue
		}
		pending = append(pending, document)
	}
	return pending, nil
}

// writeSkill creates the directory and replaces each document atomically, so a
// reader either sees the previous file or the whole new one and an interrupted
// install never leaves a half-written document an agent would read as prose.
func writeSkill(path string, documents []skillDocument) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	for _, document := range documents {
		if err := writeSkillFile(path, document); err != nil {
			return err
		}
	}
	return nil
}

func writeSkillFile(path string, document skillDocument) error {
	file, err := os.CreateTemp(path, ".clavis-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	// The temporary file is removed on every path but the rename, which has
	// already moved it away by the time this runs.
	defer func() { _ = os.Remove(temporary) }()
	_, err = file.Write(document.body)
	if err == nil {
		// A skill is prose an agent reads, not a secret: the mode is the
		// ordinary one for a document, set before the file is in place.
		err = file.Chmod(0o644)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(path, document.name))
}

// skillIOFailure reports a file system refusal as the local argument failure
// it is in practice: the path is named so the caller can fix the permission or
// the mount, and nothing that was read from the directory is echoed.
func skillIOFailure(path string) *Result {
	return argumentFailure("Could not read or write the skill directory", "Check the permissions on "+path)
}
