package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/buildinfo"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	// Source is the external source's own rejection, carried through from the
	// server's envelope unchanged. Only an execution the source refused has
	// one, and its message may quote values from the caller's own SQL, so it
	// reaches the caller and nothing else.
	Source *auth.SourceFailure `json:"source,omitempty"`
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
		if err := renderSourceFailure(w, result.Error.Source); err != nil {
			return err
		}
	}
	switch data := result.Data.(type) {
	case auth.QueryResponse:
		return renderQueryResponse(w, data)
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

// nullMark distinguishes SQL NULL from an empty string in text output, which
// no rendering of the value itself could do.
const nullMark = "∅"

// emptyStatementLabel names the result a comment-only string produces: the
// source reports no command tag at all, and a bare count would read as a
// missing result rather than a real one.
const emptyStatementLabel = "(empty statement)"

// renderQueryResponse prints one aligned table per row-producing result, the
// command tag and affected count for the others, then the truncation notice
// and the duration. The values are printed exactly as the source rendered
// them; only NULL is marked, because nothing in the value itself could be.
func renderQueryResponse(w io.Writer, response auth.QueryResponse) error {
	for _, result := range response.Results {
		if err := renderQueryResult(w, result); err != nil {
			return err
		}
	}
	if response.Truncated {
		if _, err := fmt.Fprint(w, "Truncated: true\n"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "Duration: %d ms\n", response.DurationMS)
	return err
}

func renderQueryResult(w io.Writer, result auth.QueryResult) error {
	if len(result.Columns) == 0 {
		command := result.Command
		if command == "" {
			command = emptyStatementLabel
		}
		_, err := fmt.Fprintf(w, "%s %d\n", command, result.RowCount)
		return err
	}
	rows := make([][]string, 0, len(result.Rows)+1)
	header := make([]string, len(result.Columns))
	for index, column := range result.Columns {
		header[index] = column.Name
	}
	rows = append(rows, header)
	for _, row := range result.Rows {
		values := make([]string, len(row))
		for index, value := range row {
			values[index] = nullMark
			if value != nil {
				values[index] = *value
			}
		}
		rows = append(rows, values)
	}
	// The widths come from the kept rows and the header, so a truncated table
	// is aligned on what it actually shows.
	widths := make([]int, len(result.Columns))
	for _, row := range rows {
		for index, value := range row {
			if index < len(widths) {
				widths[index] = max(widths[index], utf8.RuneCountInString(value))
			}
		}
	}
	for _, row := range rows {
		if err := renderQueryRow(w, row, widths); err != nil {
			return err
		}
	}
	// The count is what the table shows: a truncated result reports the kept
	// rows, and the truncation notice says the rest was dropped.
	_, err := fmt.Fprintf(w, "(%d rows)\n", len(result.Rows))
	return err
}

func renderQueryRow(w io.Writer, row []string, widths []int) error {
	var line strings.Builder
	for index, value := range row {
		if index > 0 {
			line.WriteString("  ")
		}
		line.WriteString(value)
		// The last column is never padded, so no line carries trailing blanks.
		if index < len(row)-1 && index < len(widths) {
			line.WriteString(strings.Repeat(" ", max(0, widths[index]-utf8.RuneCountInString(value))))
		}
	}
	_, err := fmt.Fprintln(w, line.String())
	return err
}

// renderSourceFailure prints the source's own rejection under the platform's
// failure line. The upper-case labels are the source's own words; the mixed
// case ones are the platform's, so the two are never confused.
func renderSourceFailure(w io.Writer, source *auth.SourceFailure) error {
	if source == nil {
		return nil
	}
	headline := source.Message
	if source.SQLState != "" {
		headline = source.SQLState + " " + source.Message
	}
	if _, err := fmt.Fprintf(w, "ERROR: %s\n", headline); err != nil {
		return err
	}
	for _, line := range []struct{ label, value string }{{"DETAIL", source.Detail}, {"HINT", source.Hint}} {
		if line.value == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s: %s\n", line.label, line.value); err != nil {
			return err
		}
	}
	if source.Position > 0 {
		if _, err := fmt.Fprintf(w, "Position: %d\n", source.Position); err != nil {
			return err
		}
	}
	// Zero is meaningful: the whole string was rejected before anything ran.
	_, err := fmt.Fprintf(w, "Statement: %d\n", source.Statement)
	return err
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
