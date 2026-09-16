package cli

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// The profiles group is local, like kubectl's config commands: it reads and
// writes config.toml and reads stored sessions, and never contacts a server,
// so no result carries the envelope's server and profile.

// ProfileSession is what the locally stored session says, not a verification.
type ProfileSession struct {
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ProfileEntry is one configured profile. Current is the file's current
// profile, whatever CLAVIS_PROFILE selects.
type ProfileEntry struct {
	Name    string          `json:"name"`
	Server  string          `json:"server"`
	Current bool            `json:"current"`
	Session *ProfileSession `json:"session"`
}

type ProfileSet struct {
	Name        string `json:"name"`
	Server      string `json:"server"`
	Created     bool   `json:"created"`
	MadeCurrent bool   `json:"madeCurrent"`
}

// ProfileUse and ProfileList report CLAVIS_PROFILE as override; overrideKnown
// only chooses the text note.
type ProfileUse struct {
	Profile       ProfileEntry `json:"profile"`
	Override      string       `json:"override"`
	overrideKnown bool
}

type ProfileCurrent struct {
	Profile ProfileEntry `json:"profile"`
	Source  string       `json:"source"`
}

type ProfileList struct {
	Current       string         `json:"current"`
	Override      string         `json:"override"`
	Profiles      []ProfileEntry `json:"profiles"`
	overrideKnown bool
}

type ProfileRemoval struct {
	Name           string `json:"name"`
	CurrentCleared bool   `json:"currentCleared"`
}

// profileUsages is each profiles command's usage, keyed on the whole lineage.
// Only the ones naming <name> take a positional argument, exactly one, so no
// other command named set, use or remove accepts one.
var profileUsages = map[string]struct {
	arguments int
	usage     string
}{
	"clavis profiles set":     {1, "Usage: clavis profiles set <name> --server <url>"},
	"clavis profiles use":     {1, "Usage: clavis profiles use <name>"},
	"clavis profiles remove":  {1, "Usage: clavis profiles remove <name>"},
	"clavis profiles current": {0, "Usage: clavis profiles current, which takes no arguments"},
	"clavis profiles list":    {0, "Usage: clavis profiles list, which takes no arguments"},
}

func lineageName(command *urfave.Command) string {
	lineage := command.Lineage()
	names := make([]string, len(lineage))
	for i, ancestor := range lineage {
		names[len(lineage)-1-i] = ancestor.Name
	}
	return strings.Join(names, " ")
}

// positionalArguments is how many positional arguments a command takes.
func positionalArguments(command *urfave.Command) int {
	return profileUsages[lineageName(command)].arguments
}

// profileUsage is the hint for a profiles command given the wrong arguments,
// and empty for every other command.
func profileUsage(command *urfave.Command) string {
	return profileUsages[lineageName(command)].usage
}

func profilesCommands(check func(*urfave.Command) error, set func(Result)) *urfave.Command {
	command := func(name, usage string, run func(context.Context, *urfave.Command, string) Result, flags ...urfave.Flag) *urfave.Command {
		return &urfave.Command{Name: name, Usage: usage, Flags: flags, Action: func(ctx context.Context, command *urfave.Command) error {
			if err := check(command); err != nil {
				return err
			}
			home, err := clavisHome()
			if err != nil {
				set(failure("INVALID_ARGUMENT", err.Error(), nil))
				return nil
			}
			if positionalArguments(command) == 1 && !auth.ValidUsername(command.Args().First()) {
				set(failureWithHint("INVALID_ARGUMENT", "Provide a valid profile name", profileNameHint))
				return nil
			}
			set(run(ctx, command, home))
			return nil
		}}
	}
	return &urfave.Command{Name: "profiles", Usage: "Manage the named servers this machine uses (local, no server contact)", Action: func(ctx context.Context, command *urfave.Command) error {
		if err := check(command); err != nil {
			return err
		}
		return urfave.ShowSubcommandHelp(command)
	}, Commands: []*urfave.Command{
		command("set", "Create a profile or change its server; the first one becomes current", profileSet,
			&urfave.StringFlag{Name: "server", Usage: "Server root origin to store"}),
		command("use", "Make a profile current", profileUse),
		command("current", "Show the profile in effect", profileCurrent),
		command("list", "List profiles and their stored sessions", profileList),
		command("remove", "Remove a profile; stored sessions are kept", profileRemove),
	}}
}

func profileSet(ctx context.Context, command *urfave.Command, home string) Result {
	name := command.Args().First()
	if command.String("server") == "" {
		return failureWithHint("INVALID_ARGUMENT", "Provide --server with the server's root origin", profileSetupHint)
	}
	origin, err := auth.CanonicalOrigin(command.String("server"))
	if err != nil {
		return failureWithHint("INVALID_ARGUMENT", "Use an HTTPS root origin (literal loopback HTTP is allowed) for --server", profileSetupHint)
	}
	data := ProfileSet{Name: name, Server: origin}
	if failed := saveConfig(ctx, home, func(config *clientConfig) *Result {
		_, exists := config.Profiles[name]
		data.Created = !exists
		if config.Profiles == nil {
			config.Profiles = map[string]clientProfile{}
		}
		config.Profiles[name] = clientProfile{Server: origin}
		if config.Current == "" {
			config.Current, data.MadeCurrent = name, true
		}
		return nil
	}); failed != nil {
		return *failed
	}
	return success(data)
}

func profileUse(ctx context.Context, command *urfave.Command, home string) Result {
	name := command.Args().First()
	override, failed := profileOverride()
	if failed != nil {
		return *failed
	}
	if failed := requireProfile(home, name); failed != nil {
		return *failed
	}
	var data ProfileUse
	// The session is read under the configuration lock and before the write,
	// so a storage failure leaves the file unchanged.
	if failed := saveConfig(ctx, home, func(config *clientConfig) *Result {
		if _, ok := config.Profiles[name]; !ok {
			return unknownProfile(name)
		}
		config.Current = name
		entry, failed := profileEntry(home, *config, name)
		if failed != nil {
			return failed
		}
		_, known := config.Profiles[override]
		data = ProfileUse{Profile: entry, Override: override, overrideKnown: known}
		return nil
	}); failed != nil {
		return *failed
	}
	return success(data)
}

func profileCurrent(_ context.Context, _ *urfave.Command, home string) Result {
	override, failed := profileOverride()
	if failed != nil {
		return *failed
	}
	config, failed := loadConfig(home)
	if failed != nil {
		return *failed
	}
	name, source := override, "environment"
	if name == "" {
		name, source = config.Current, "config"
	}
	if name == "" {
		return failureWithHint("INVALID_ARGUMENT", "No profile is current and CLAVIS_PROFILE is not set", profileSetupHint)
	}
	if _, ok := config.Profiles[name]; !ok {
		return *unknownProfile(name)
	}
	entry, failed := profileEntry(home, config, name)
	if failed != nil {
		return *failed
	}
	return success(ProfileCurrent{Profile: entry, Source: source})
}

func profileList(_ context.Context, _ *urfave.Command, home string) Result {
	override, failed := profileOverride()
	if failed != nil {
		return *failed
	}
	config, failed := loadConfig(home)
	if failed != nil {
		return *failed
	}
	_, known := config.Profiles[override]
	data := ProfileList{Current: config.Current, Override: override, Profiles: []ProfileEntry{}, overrideKnown: known}
	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, failed := profileEntry(home, config, name)
		if failed != nil {
			return *failed
		}
		data.Profiles = append(data.Profiles, entry)
	}
	return success(data)
}

func profileRemove(ctx context.Context, command *urfave.Command, home string) Result {
	name := command.Args().First()
	if failed := requireProfile(home, name); failed != nil {
		return *failed
	}
	data := ProfileRemoval{Name: name}
	if failed := saveConfig(ctx, home, func(config *clientConfig) *Result {
		if _, ok := config.Profiles[name]; !ok {
			return unknownProfile(name)
		}
		delete(config.Profiles, name)
		if config.Current == name {
			config.Current, data.CurrentCleared = "", true
		}
		return nil
	}); failed != nil {
		return *failed
	}
	return success(data)
}

// profileOverride reads CLAVIS_PROFILE for the commands that report it. A value
// that is not a profile name is refused without being echoed.
func profileOverride() (string, *Result) {
	override := os.Getenv("CLAVIS_PROFILE")
	if override != "" && !auth.ValidUsername(override) {
		return "", argumentFailure("CLAVIS_PROFILE is not a valid profile name", profileNameHint)
	}
	return override, nil
}

// requireProfile refuses an unknown name before anything is created; the
// writer checks again under the lock.
func requireProfile(home, name string) *Result {
	config, failed := loadConfig(home)
	if failed != nil {
		return failed
	}
	if _, ok := config.Profiles[name]; !ok {
		return unknownProfile(name)
	}
	return nil
}

func unknownProfile(name string) *Result {
	return argumentFailure("No profile named "+name+" is configured", profileListHint)
}

// profileEntry describes a configured profile with its locally stored session,
// read without creating the home or the sessions directory.
func profileEntry(home string, config clientConfig, name string) (ProfileEntry, *Result) {
	// loadConfig already checked the server; this only canonicalizes it.
	origin, _ := auth.CanonicalOrigin(config.Profiles[name].Server)
	entry := ProfileEntry{Name: name, Server: origin, Current: config.Current == name}
	stored, err := readStoredSession(home, origin)
	if err != nil {
		r := storageFailure(err)
		return ProfileEntry{}, &r
	}
	if stored != nil {
		entry.Session = &ProfileSession{Username: stored.User.Username, ExpiresAt: stored.ExpiresAt}
	}
	return entry, nil
}
