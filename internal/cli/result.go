package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/buildinfo"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Result struct {
	SchemaVersion int    `json:"schemaVersion"`
	OK            bool   `json:"ok"`
	Data          any    `json:"data"`
	Error         *Error `json:"error"`
}

type Diagnosis struct {
	API      string `json:"api"`
	Database string `json:"database"`
}

func success(data any) Result { return Result{SchemaVersion: 1, OK: true, Data: data} }
func failure(code, message string, data any) Result {
	return Result{SchemaVersion: 1, Data: data, Error: &Error{code, message}}
}

func render(w io.Writer, result Result, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(result)
	}
	if result.Error != nil {
		if _, err := fmt.Fprintf(w, "%s: %s\n", result.Error.Code, result.Error.Message); err != nil {
			return err
		}
	}
	switch data := result.Data.(type) {
	case auth.Identity:
		_, err := fmt.Fprintf(w, "User: %s (%s)\nRole: %s\nExpires: %s\n", data.User.Username, data.User.ID, data.User.Role, data.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
		return err
	case auth.Revocation:
		_, err := fmt.Fprintf(w, "Revoked: %t\n", data.Revoked)
		return err
	case auth.UserRecord:
		return renderUser(w, data)
	case auth.UserMutation:
		if err := renderUser(w, data.User); err != nil {
			return err
		}
		_, err := fmt.Fprintf(w, "Sessions revoked: %t\n", data.SessionsRevoked)
		return err
	case auth.UserList:
		for _, user := range data.Users {
			if _, err := fmt.Fprintf(w, "%s %s %s %s\n", user.ID, user.Username, user.Role, userStatus(user)); err != nil {
				return err
			}
		}
		if data.Truncated {
			_, err := fmt.Fprintf(w, "Truncated: list is limited to %d users\n", auth.MaxUserListing)
			return err
		}
		return nil
	case Diagnosis:
		_, err := fmt.Fprintf(w, "API: %s\nDatabase: %s\n", data.API, data.Database)
		return err
	case buildinfo.Info:
		_, err := fmt.Fprintf(w, "clavis %s (commit %s, built %s)\n", data.Version, data.Commit, data.Date)
		return err
	}
	return nil
}

func userStatus(user auth.UserRecord) string {
	if user.Disabled {
		return "blocked"
	}
	return "enabled"
}

// renderUser prints the safe record projection only; a password never reaches
// a result type.
func renderUser(w io.Writer, user auth.UserRecord) error {
	_, err := fmt.Fprintf(w, "User: %s (%s)\nRole: %s\nStatus: %s\nCreated: %s\n",
		user.Username, user.ID, user.Role, userStatus(user), user.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	return err
}
