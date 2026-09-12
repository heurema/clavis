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
		if _, err := fmt.Fprintf(w, "User: %s (%s)\nRole: %s\nExpires: %s\n", data.User.Username, data.User.ID, data.User.Role, timestamp(data.ExpiresAt)); err != nil {
			return err
		}
		// Only whoami fills the names, and only for a member: an administrator
		// needs no grant, so the line is absent rather than listing everything.
		if len(data.Connections) == 0 {
			return nil
		}
		if _, err := fmt.Fprintf(w, "Connections: %s\n", strings.Join(data.Connections, ", ")); err != nil {
			return err
		}
		return renderTruncation(w, data.ConnectionsTruncated, auth.MaxConnectionListing, "connections")
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
		return renderTruncation(w, data.Truncated, auth.MaxUserListing, "users")
	case auth.Connection:
		return renderConnection(w, data)
	case auth.ConnectionSummary:
		return renderConnectionSummary(w, data)
	case auth.ConnectionList:
		for _, connection := range data.Connections {
			if err := renderConnectionLine(w, connection.Summary()); err != nil {
				return err
			}
		}
		return renderTruncation(w, data.Truncated, auth.MaxConnectionListing, "connections")
	case auth.ConnectionSummaryList:
		for _, connection := range data.Connections {
			if err := renderConnectionLine(w, connection); err != nil {
				return err
			}
		}
		return renderTruncation(w, data.Truncated, auth.MaxConnectionListing, "connections")
	case auth.GrantList:
		for _, grant := range data.Grants {
			if _, err := fmt.Fprintf(w, "%s %s %s\n", grant.User.Name, grant.Connection.Name, timestamp(grant.CreatedAt)); err != nil {
				return err
			}
		}
		return renderTruncation(w, data.Truncated, auth.MaxGrantListing, "grants")
	case auth.GrantMutation:
		if _, err := fmt.Fprintf(w, "Grant: %s → %s\nGranted: %s by %s\nCreated: %t\n",
			data.Grant.User.Name, data.Grant.Connection.Name, timestamp(data.Grant.CreatedAt),
			data.Grant.CreatedBy.Name, data.Created); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.GrantRevocation:
		if _, err := fmt.Fprintf(w, "Revoked: %t\n", data.Revoked); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
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

// renderTruncation prints the one bounded-listing notice every group shares,
// and only when the server actually reported truncation.
func renderTruncation(w io.Writer, truncated bool, limit int, noun string) error {
	if !truncated {
		return nil
	}
	_, err := fmt.Fprintf(w, "Truncated: list is limited to %d %s\n", limit, noun)
	return err
}

func connectionStatus(enabled bool) string {
	if enabled {
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

// renderConnectionLine prints one listing row. Both listings share it: the
// columns a member sees are exactly the ones an administrator's row leads with.
func renderConnectionLine(w io.Writer, connection auth.ConnectionSummary) error {
	_, err := fmt.Fprintf(w, "%s %s %s %s %s\n", connection.ID, connection.Name,
		connection.Provider, connectionStatus(connection.Enabled), lastCheckOutcome(connection.LastCheck))
	return err
}

func lastCheckDetail(check *auth.CheckResult) string {
	if check == nil {
		return "never"
	}
	return string(check.Outcome) + " at " + timestamp(check.CheckedAt)
}

// renderConnectionSummary prints the member projection: identity, descriptive
// text, labels, state and the last check. It has no target or bound line
// because the shape carries neither.
func renderConnectionSummary(w io.Writer, connection auth.ConnectionSummary) error {
	_, err := fmt.Fprintf(w,
		"Connection: %s\nID: %s\nTitle: %s\nProvider: %s\nLabels: %s\nStatus: %s\nLast check: %s\n",
		connection.Name, connection.ID, connection.Title, connection.Provider,
		settingPairs(connection.Labels), connectionStatus(connection.Enabled), lastCheckDetail(connection.LastCheck))
	return err
}

// renderConnection prints the safe record projection only; a credential never
// reaches a result type.
func renderConnection(w io.Writer, connection auth.Connection) error {
	_, err := fmt.Fprintf(w,
		"Connection: %s\nID: %s\nTitle: %s\nProvider: %s\nTarget: %s\nLabels: %s\nStatus: %s\n"+
			"Timeout: %s\nMax rows: %d\nMax bytes: %d\nLast check: %s\nCreated: %s\nUpdated: %s\n",
		connection.Name, connection.ID, connection.Title, connection.Provider,
		settingPairs(connection.Target), settingPairs(connection.Labels), connectionStatus(connection.Enabled),
		(time.Duration(connection.StatementTimeoutMS) * time.Millisecond).String(),
		connection.MaxRows, connection.MaxBytes, lastCheckDetail(connection.LastCheck),
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
