package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/buildinfo"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
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
	return Result{SchemaVersion: 1, Data: data, Error: &Error{Code: code, Message: message}}
}

// failureWithHint adds optional next-step guidance. The hint is additive to the
// envelope, so schemaVersion stays 1, and it never carries a submitted value.
func failureWithHint(code, message, hint string) Result {
	result := failure(code, message, nil)
	result.Error.Hint = hint
	return result
}

func render(w io.Writer, result Result, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(result)
	}
	if result.Error != nil {
		if _, err := fmt.Fprintf(w, "%s: %s\n", result.Error.Code, result.Error.Message); err != nil {
			return err
		}
		if result.Error.Hint != "" {
			if _, err := fmt.Fprintf(w, "Hint: %s\n", result.Error.Hint); err != nil {
				return err
			}
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
	case auth.Connection:
		return renderConnection(w, data)
	case auth.ConnectionList:
		for _, connection := range data.Connections {
			if _, err := fmt.Fprintf(w, "%s %s %s %s %s\n", connection.ID, connection.Name,
				connection.Provider, connectionStatus(connection), lastCheckOutcome(connection.LastCheck)); err != nil {
				return err
			}
		}
		if data.Truncated {
			_, err := fmt.Fprintf(w, "Truncated: list is limited to %d connections\n", auth.MaxConnectionListing)
			return err
		}
		return nil
	case auth.ConnectionMutation:
		if err := renderConnection(w, data.Connection); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.ConnectionDeletion:
		if _, err := fmt.Fprintf(w, "Deleted: %s (%s)\n", data.Name, data.ID); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.ConnectionCheck:
		if err := renderConnection(w, data.Connection); err != nil {
			return err
		}
		_, err := fmt.Fprintf(w, "Check: %s at %s\n", data.Check.Outcome, timestamp(data.Check.CheckedAt))
		return err
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

func timestamp(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05Z") }

func connectionStatus(connection auth.Connection) string {
	if connection.Enabled {
		return "enabled"
	}
	return "disabled"
}

func lastCheckOutcome(check *auth.CheckResult) string {
	if check == nil {
		return "unchecked"
	}
	return string(check.Outcome)
}

// settingPairs renders a flat string map in a stable order, so two runs of the
// same command produce identical text.
func settingPairs(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+values[key])
	}
	return strings.Join(pairs, " ")
}

func renderDryRun(w io.Writer, dryRun bool) error {
	if !dryRun {
		return nil
	}
	_, err := fmt.Fprint(w, "Dry run: true\n")
	return err
}

// renderConnection prints the safe record projection only; a credential never
// reaches a result type.
func renderConnection(w io.Writer, connection auth.Connection) error {
	lastCheck := "never"
	if connection.LastCheck != nil {
		lastCheck = string(connection.LastCheck.Outcome) + " at " + timestamp(connection.LastCheck.CheckedAt)
	}
	_, err := fmt.Fprintf(w,
		"Connection: %s\nID: %s\nTitle: %s\nProvider: %s\nTarget: %s\nLabels: %s\nStatus: %s\n"+
			"Timeout: %s\nMax rows: %d\nMax bytes: %d\nLast check: %s\nCreated: %s\nUpdated: %s\n",
		connection.Name, connection.ID, connection.Title, connection.Provider,
		settingPairs(connection.Target), settingPairs(connection.Labels), connectionStatus(connection),
		(time.Duration(connection.StatementTimeoutMS) * time.Millisecond).String(),
		connection.MaxRows, connection.MaxBytes, lastCheck,
		timestamp(connection.CreatedAt), timestamp(connection.UpdatedAt))
	return err
}

// renderUser prints the safe record projection only; a password never reaches
// a result type.
func renderUser(w io.Writer, user auth.UserRecord) error {
	_, err := fmt.Fprintf(w, "User: %s (%s)\nRole: %s\nStatus: %s\nCreated: %s\n",
		user.Username, user.ID, user.Role, userStatus(user), user.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	return err
}
