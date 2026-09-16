package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/heurema/clavis/internal/auth"
	"github.com/pelletier/go-toml/v2"
)

// maxConfigBytes bounds config.toml: it holds names and origins only.
const maxConfigBytes = 64 << 10

// profileSetupHint is the one next step when no server was resolved: the
// person names a server once, and every later command finds it.
const profileSetupHint = "clavis profiles set <name> --server <url>"

const profileListHint = "Run clavis profiles list to see the configured profiles"

// profileNameHint states the profile-name rule, which is the username grammar.
const profileNameHint = "Profile names are 3 to 64 characters: a lowercase letter followed by lowercase letters, digits, '.', '_' or '-', and never UUID-shaped"

// clientConfig is config.toml in the Clavis home. It never holds a secret.
type clientConfig struct {
	Current  string                   `toml:"current,omitempty"`
	Profiles map[string]clientProfile `toml:"profiles,omitempty"`
}

type clientProfile struct {
	Server string `toml:"server"`
}

// target is the server a networked command talks to and where its sessions
// live. Profile is empty when the server was given with --server.
type target struct {
	Origin, Profile, Home string
}

// resolveTarget picks exactly one server before any input, storage or network
// access: --server or --profile, then CLAVIS_PROFILE, then the configuration's
// current profile. The file is read only once a profile name is needed, so a
// direct --server never depends on it.
func resolveTarget(server, profile string) (target, *Result) {
	home, err := clavisHome()
	if err != nil {
		r := failure("INVALID_ARGUMENT", err.Error(), nil)
		return target{}, &r
	}
	if server != "" && profile != "" {
		r := failureWithHint("INVALID_ARGUMENT", "Use either --server or --profile, not both", profileListHint)
		return target{}, &r
	}
	if server != "" {
		origin, err := auth.CanonicalOrigin(server)
		if err != nil {
			r := failure("INVALID_ARGUMENT", "Use an HTTPS root origin (literal loopback HTTP is allowed) for --server", nil)
			return target{}, &r
		}
		return target{Origin: origin, Home: home}, nil
	}
	source := "--profile"
	if profile == "" {
		source, profile = "CLAVIS_PROFILE", os.Getenv("CLAVIS_PROFILE")
	}
	// A name from the command line or the environment is checked before the
	// file is read and never echoed unless it is a well-formed name.
	if profile != "" && !auth.ValidUsername(profile) {
		r := failureWithHint("INVALID_ARGUMENT", source+" is not a valid profile name", profileListHint)
		return target{}, &r
	}
	config, failed := loadConfig(home)
	if failed != nil {
		return target{}, failed
	}
	if profile == "" {
		profile = config.Current
	}
	if profile == "" {
		r := failureWithHint("INVALID_ARGUMENT", "No server is configured: no --server, --profile, CLAVIS_PROFILE or current profile", profileSetupHint)
		return target{}, &r
	}
	entry, ok := config.Profiles[profile]
	if !ok {
		r := failureWithHint("INVALID_ARGUMENT", "No profile named "+profile+" is configured", profileListHint)
		return target{}, &r
	}
	// loadConfig already checked the server; this only canonicalizes it.
	origin, _ := auth.CanonicalOrigin(entry.Server)
	return target{Origin: origin, Profile: profile, Home: home}, nil
}

// loadConfig reads config.toml whole or not at all. An absent file is an empty
// configuration; anything else that is not a valid file is INVALID_ARGUMENT
// naming the path and, where there is one, the offending key.
func loadConfig(home string) (clientConfig, *Result) {
	path := filepath.Join(home, "config.toml")
	invalid := func(message, hint string) (clientConfig, *Result) {
		r := failureWithHint("INVALID_ARGUMENT", path+": "+message, hint)
		return clientConfig{}, &r
	}
	// O_NONBLOCK keeps a FIFO from blocking the open; the type check refuses it.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return clientConfig{}, nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return invalid("must be a regular file, not a symlink", "")
	}
	if err != nil {
		return invalid("could not be read", "")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return invalid("must be a regular file, not a symlink", "")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return invalid("could not be read", "")
	}
	if len(body) > maxConfigBytes {
		return invalid("is larger than 64 KiB", "")
	}
	var config clientConfig
	decoder := toml.NewDecoder(bytes.NewReader(body)).DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		var strict *toml.StrictMissingError
		var decode *toml.DecodeError
		switch {
		case errors.As(err, &strict) && len(strict.Errors) > 0:
			return invalid(configKey(strict.Errors[0].Key())+" is not a known key", "")
		case errors.As(err, &decode):
			// The parser's own message may quote the document, so only the
			// position and key are reported.
			row, _ := decode.Position()
			if key := decode.Key(); len(key) > 0 {
				return invalid(fmt.Sprintf("line %d: %s is not valid", row, configKey(key)), "")
			}
			return invalid(fmt.Sprintf("line %d is not valid TOML", row), "")
		default:
			return invalid("is not a valid configuration file", "")
		}
	}
	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := configKey(toml.Key{"profiles", name})
		if !auth.ValidUsername(name) {
			return invalid(key+" is not a valid profile name", profileNameHint)
		}
		if _, err := auth.CanonicalOrigin(config.Profiles[name].Server); err != nil {
			return invalid(key+".server must be an HTTPS root origin (literal loopback HTTP is allowed)", "")
		}
	}
	if config.Current != "" {
		if _, ok := config.Profiles[config.Current]; !ok {
			return invalid("current names no configured profile", "")
		}
	}
	return config, nil
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// configKey spells a key path the way TOML would, quoting parts that are not
// bare keys so a hand-written name cannot break the message apart.
func configKey(key toml.Key) string {
	parts := make([]string, len(key))
	for i, part := range key {
		parts[i] = part
		if !bareKey.MatchString(part) {
			parts[i] = fmt.Sprintf("%q", part)
		}
	}
	return strings.Join(parts, ".")
}
