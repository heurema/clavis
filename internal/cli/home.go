package cli

import (
	"os"
	"path/filepath"
)

// storageError names the local path that failed a storage check and what it
// must be. The path comes from the check, never from server data, so the
// message is safe to display.
type storageError struct {
	path        string
	requirement string
}

func (e storageError) Error() string {
	return e.path + " must be " + e.requirement
}

// clavisHome is the directory holding the CLI's sessions: CLAVIS_HOME when set,
// otherwise .clavis in the user's home directory. It touches no file.
func clavisHome() (string, error) {
	if home := os.Getenv("CLAVIS_HOME"); home != "" {
		if !filepath.IsAbs(home) {
			return "", storageError{path: "CLAVIS_HOME", requirement: "an absolute path"}
		}
		return filepath.Clean(home), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", storageError{path: "HOME", requirement: "set to an absolute path"}
	}
	return filepath.Join(home, ".clavis"), nil
}
