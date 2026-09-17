package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	SchemaVersion int  `json:"schemaVersion"`
	OK            bool `json:"ok"`
	// Server and Profile name the resolved target. Only a command that
	// resolved one sets them, so a pointer tells an absent profile from the
	// empty one a --server command reports.
	Server  *string `json:"server,omitempty"`
	Profile *string `json:"profile,omitempty"`
	Data    any     `json:"data"`
	Error   *Error  `json:"error"`
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

// named records the resolved target on a result produced after resolution. A
// --server target reports its empty profile rather than omitting it.
func (t target) named(result Result) Result {
	result.Server, result.Profile = &t.Origin, &t.Profile
	return result
}

func render(w io.Writer, result Result, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(result)
	}
	if err := renderServer(w, result); err != nil {
		return err
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
		if _, err := fmt.Fprintf(w, "User: %s (%s)\nRole: %s\nExpires: %s\nIdle until: %s\n",
			data.User.Username, data.User.ID, data.User.Role, timestamp(data.ExpiresAt), timestamp(data.IdleExpiresAt)); err != nil {
			return err
		}
		return renderIdentityNames(w, data)
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
	case auth.AccessList:
		return renderAccessList(w, data)
	case auth.Group:
		return renderGroup(w, data)
	case auth.GroupList:
		for _, group := range data.Groups {
			if _, err := fmt.Fprintf(w, "%s %s %d %d\n", group.ID, group.Name, group.Members, group.Grants); err != nil {
				return err
			}
		}
		return renderTruncation(w, data.Truncated, auth.MaxGroupListing, "groups")
	case auth.GroupMutation:
		if err := renderGroup(w, data.Group); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.GroupDeletion:
		if _, err := fmt.Fprintf(w, "Deleted: %s (%s)\n", data.Group.Name, data.Group.ID); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.MemberList:
		for _, member := range data.Members {
			if _, err := fmt.Fprintf(w, "%s %s %s %s\n", member.ID, member.Username,
				userStatus(member.UserRecord), timestamp(member.AddedAt)); err != nil {
				return err
			}
		}
		return renderTruncation(w, data.Truncated, auth.MaxMemberListing, "members")
	case auth.MembershipMutation:
		if _, err := fmt.Fprintf(w, "Member: %s → %s\nAdded: %t\n",
			data.Membership.User.Name, data.Membership.Group.Name, data.Added); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.MembershipRemoval:
		if _, err := fmt.Fprintf(w, "Member: %s → %s\nRemoved: %t\n",
			data.User.Name, data.Group.Name, data.Removed); err != nil {
			return err
		}
		return renderDryRun(w, data.DryRun)
	case auth.GrantList:
		for _, grant := range data.Grants {
			if _, err := fmt.Fprintf(w, "%s %s %s\n", recipientLabel(grant.Recipient),
				grant.Connection.Name, timestamp(grant.CreatedAt)); err != nil {
				return err
			}
		}
		return renderTruncation(w, data.Truncated, auth.MaxGrantListing, "grants")
	case auth.GrantMutation:
		if _, err := fmt.Fprintf(w, "Grant: %s → %s\nGranted: %s by %s\nCreated: %t\n",
			recipientLabel(data.Grant.Recipient), data.Grant.Connection.Name, timestamp(data.Grant.CreatedAt),
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
	case SkillInstall:
		return renderSkillInstall(w, data)
	case Diagnosis:
		_, err := fmt.Fprintf(w, "API: %s\nDatabase: %s\n", data.API, data.Database)
		return err
	case ProfileSet:
		line := "Profile " + data.Name + " set to " + data.Server
		if data.MadeCurrent {
			line += ", now current"
		}
		_, err := fmt.Fprintln(w, line)
		return err
	case ProfileUse:
		if err := renderProfile(w, data.Profile); err != nil {
			return err
		}
		return renderOverride(w, data.Override, data.overrideKnown, data.Profile.Name)
	case ProfileCurrent:
		if err := renderProfile(w, data.Profile); err != nil {
			return err
		}
		_, err := fmt.Fprintf(w, "Source: %s\n", data.Source)
		return err
	case ProfileList:
		for _, entry := range data.Profiles {
			mark := " "
			if entry.Current {
				mark = "*"
			}
			if _, err := fmt.Fprintf(w, "%s %s %s %s\n", mark, entry.Name, entry.Server, profileSessionText(entry.Session)); err != nil {
				return err
			}
		}
		return renderOverride(w, data.Override, data.overrideKnown, data.Current)
	case ProfileRemoval:
		line := "Removed " + data.Name
		if data.CurrentCleared {
			line += "; no profile is current now"
		}
		_, err := fmt.Fprintln(w, line)
		return err
	case buildinfo.Info:
		_, err := fmt.Fprintf(w, "clavis %s (commit %s, built %s)\n", data.Version, data.Commit, data.Date)
		return err
	}
	return nil
}

// renderServer names the target first, so a reader knows which server the
// rest of the output, a failure included, came from.
func renderServer(w io.Writer, result Result) error {
	if result.Server == nil {
		return nil
	}
	line := "Server: " + *result.Server
	if result.Profile != nil && *result.Profile != "" {
		line += " (profile " + *result.Profile + ")"
	}
	_, err := fmt.Fprintln(w, line)
	return err
}

// renderProfile prints one profile with what the local session store holds for
// its server, which is never a verification: whoami is.
func renderProfile(w io.Writer, entry ProfileEntry) error {
	session := "none (not signed in)"
	if entry.Session != nil {
		session = entry.Session.Username + " until " + timestamp(entry.Session.ExpiresAt)
	}
	_, err := fmt.Fprintf(w, "Profile: %s\nServer: %s\nStored session: %s\n", entry.Name, entry.Server, session)
	return err
}

func profileSessionText(session *ProfileSession) string {
	if session == nil {
		return "not signed in"
	}
	return "stored session: " + session.Username + " until " + timestamp(session.ExpiresAt)
}

// renderOverride notes a CLAVIS_PROFILE that makes networked commands in this
// environment use something other than the file's current profile.
func renderOverride(w io.Writer, override string, known bool, current string) error {
	switch {
	case override == "" || override == current:
		return nil
	case !known:
		_, err := fmt.Fprintf(w, "Note: CLAVIS_PROFILE=%s names no profile; networked commands in this environment exit 2\n", override)
		return err
	default:
		_, err := fmt.Fprintf(w, "Note: CLAVIS_PROFILE=%s selects %s in this environment\n", override, override)
		return err
	}
}

// nullMark distinguishes SQL NULL from an empty string in text output, which
// no rendering of the value itself could do.
const nullMark = "∅"

// emptyStatementLabel names the result a comment-only string produces: the
// source reports no command tag at all, and a bare count would read as a
// missing result rather than a real one.
const emptyStatementLabel = "(empty statement)"

// renderQueryResponse prints the shape the provider named: for a SQL source
// one aligned table per row-producing result and the command tag and affected
// count for the others; for a metrics source the source's own samples; for a
// log source one line per row. The source's warnings come first and the
// platform's own notices last. The values are printed exactly as the source
// rendered them; only NULL is marked, because nothing in the value itself
// could be.
func renderQueryResponse(w io.Writer, response auth.QueryResponse) error {
	// The source's warnings come before the data they are about, so a reader
	// knows what the answer is qualified by before reading it.
	for _, warning := range response.Warnings {
		if _, err := fmt.Fprintf(w, "Warning: %s\n", warning); err != nil {
			return err
		}
	}
	switch response.Provider {
	case auth.ProviderVictoriaMetrics:
		if err := renderMetricsResult(w, response.ResultType, response.Result); err != nil {
			return err
		}
	case auth.ProviderVictoriaLogs:
		if err := renderLogsResult(w, response.ResultType, response.Result); err != nil {
			return err
		}
	}
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
	// The source's own word about its data, never folded into the platform's
	// word about the bounds it applied.
	if response.IsPartial {
		if _, err := fmt.Fprint(w, "Partial: true\n"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "Duration: %d ms\n", response.DurationMS)
	return err
}

// The fields a log row leads and trails with. A row is a query result rather
// than a log line, so none of them is required: an aggregate row has neither
// time nor message, and the platform prints whatever fields exist.
const (
	logTimeField     = "_time"
	logMessageField  = "_msg"
	logStreamField   = "_stream"
	logStreamIDField = "_stream_id"
)

// renderLogsResult prints the source's own rows, one physical line each, so a
// multi-line message stays one line and a reader can pipe the output. The time
// leads, the message follows it, the remaining fields come as key=value in
// name order because a JSON object's order is not the source's statement about
// them, and the two stream fields close the line. Discovery is the source's
// value and its hit count, one pair per line.
func renderLogsResult(w io.Writer, resultType string, result json.RawMessage) error {
	if resultType != "logs" {
		var values []struct {
			Value string      `json:"value"`
			Hits  json.Number `json:"hits"`
		}
		if err := json.Unmarshal(result, &values); err != nil {
			return nil
		}
		for _, item := range values {
			if _, err := fmt.Fprintf(w, "%s\t%s\n", logsText(item.Value), item.Hits.String()); err != nil {
				return err
			}
		}
		return nil
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(result, &rows); err != nil {
		return nil
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(w, logRow(row)); err != nil {
			return err
		}
	}
	return nil
}

// logRow renders one row as the documented line.
func logRow(row map[string]json.RawMessage) string {
	parts := make([]string, 0, len(row))
	for _, field := range []string{logTimeField, logMessageField} {
		if value, present := row[field]; present {
			parts = append(parts, logsValueText(value))
		}
	}
	middle := make([]string, 0, len(row))
	for name := range row {
		switch name {
		case logTimeField, logMessageField, logStreamField, logStreamIDField:
		default:
			middle = append(middle, name)
		}
	}
	sort.Strings(middle)
	for _, name := range middle {
		parts = append(parts, logsText(name)+"="+logsValueText(row[name]))
	}
	// The stream fields close the line: they identify the row's origin rather
	// than say anything about it, so they never separate the fields that do.
	for _, field := range []string{logStreamField, logStreamIDField} {
		if value, present := row[field]; present {
			parts = append(parts, logsText(field)+"="+logsValueText(value))
		}
	}
	return strings.Join(parts, " ")
}

// logsValueText renders one JSON value: the text a string holds, or the
// compact JSON the source wrote for anything else, so a number, a boolean, an
// object or a list survives as what it was. Either way the quoting rule below
// decides whether it is printed as it is.
func logsValueText(raw json.RawMessage) string {
	// The leading quote decides it: JSON null also decodes into a string, and
	// printing a null as an empty value would say something the source did not.
	trimmed := bytes.TrimSpace(raw)
	var text string
	if len(trimmed) > 0 && trimmed[0] == '"' && json.Unmarshal(trimmed, &text) == nil {
		return logsText(text)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return logsText(string(raw))
	}
	return logsText(compact.String())
}

// logsText quotes a field name or a value when printing it bare would make the
// line ambiguous or would let the source's own text rewrite the terminal: an
// empty string, whitespace, a quote, a backslash, a control character or the
// separator itself. Go's own quoting is used, so the escape is one a reader
// and a parser both know.
func logsText(value string) string {
	if value == "" || strings.ContainsFunc(value, logsQuoted) {
		return strconv.Quote(value)
	}
	return value
}

func logsQuoted(r rune) bool {
	switch r {
	case '"', '\\', '=':
		return true
	}
	return unicode.IsSpace(r) || unicode.IsControl(r)
}

// renderMetricsResult prints the source's own answer: one line per vector
// sample, a labelled block per matrix series, one line for a scalar or a
// string and one item per line for discovery. The values are printed exactly
// as the source rendered them; only the label sets are ordered, because a map
// has no order of its own to print.
func renderMetricsResult(w io.Writer, resultType string, result json.RawMessage) error {
	switch resultType {
	case "vector":
		var series []metricsSeries
		if err := json.Unmarshal(result, &series); err != nil {
			return nil
		}
		for _, entry := range series {
			if err := renderMetricsSample(w, labelSet(entry.Metric)+" ", entry.Value); err != nil {
				return err
			}
		}
	case "matrix":
		var series []metricsSeries
		if err := json.Unmarshal(result, &series); err != nil {
			return nil
		}
		for _, entry := range series {
			if _, err := fmt.Fprintln(w, labelSet(entry.Metric)); err != nil {
				return err
			}
			for _, sample := range entry.Values {
				if len(sample) != 2 {
					continue
				}
				if _, err := fmt.Fprintf(w, "%s %s\n", rawText(sample[0]), rawText(sample[1])); err != nil {
					return err
				}
			}
		}
	case "scalar", "string":
		var sample []json.RawMessage
		if err := json.Unmarshal(result, &sample); err != nil {
			return nil
		}
		return renderMetricsSample(w, "", sample)
	case "labels", "labelValues":
		var names []string
		if err := json.Unmarshal(result, &names); err != nil {
			return nil
		}
		for _, name := range names {
			if _, err := fmt.Fprintln(w, name); err != nil {
				return err
			}
		}
	default:
		var sets []map[string]string
		if err := json.Unmarshal(result, &sets); err != nil {
			return nil
		}
		for _, set := range sets {
			if _, err := fmt.Fprintln(w, labelSet(set)); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderMetricsSample prints one sample as its value at its timestamp, which
// is the order a reader wants it in: the value first, the time it belongs to
// after it.
func renderMetricsSample(w io.Writer, prefix string, sample []json.RawMessage) error {
	if len(sample) != 2 {
		return nil
	}
	_, err := fmt.Fprintf(w, "%s%s @%s\n", prefix, rawText(sample[1]), rawText(sample[0]))
	return err
}

// rawText renders one JSON value as the text it holds: a quoted string without
// its quotes, anything else as it was encoded.
func rawText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return string(raw)
}

// labelSet renders a label set the way the source's own query language writes
// one: the metric name, then the remaining labels in name order. The order is
// the platform's because a map has none, which is the one thing here that is
// not the source's own rendering.
func labelSet(labels map[string]string) string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		if name != metricNameLabel {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+strconv.Quote(labels[name]))
	}
	return labels[metricNameLabel] + "{" + strings.Join(pairs, ",") + "}"
}

// metricNameLabel is the label a metric's own name travels in.
const metricNameLabel = "__name__"

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
	// The source's own classification leads the line: a SQLSTATE from a SQL
	// source, an errorType from an HTTP one, and neither from a source that
	// reported only a message.
	headline := source.Message
	switch {
	case source.SQLState != "":
		headline = source.SQLState + " " + source.Message
	case source.ErrorType != "":
		headline = source.ErrorType + " " + source.Message
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
	// A source without statements reports none, and the line is left out.
	if source.Statement == nil {
		return nil
	}
	_, err := fmt.Fprintf(w, "Statement: %d\n", *source.Statement)
	return err
}

func userStatus(user auth.UserRecord) string {
	if user.Disabled {
		return "blocked"
	}
	return "enabled"
}

// renderIdentityNames prints what whoami adds to the identity: the groups the
// caller belongs to, whatever their role, and the connections a member may
// use. An administrator needs no grant, so the connection line is absent
// rather than listing everything, and a caller in no group has no group line.
func renderIdentityNames(w io.Writer, identity auth.Identity) error {
	if len(identity.Groups) > 0 {
		if _, err := fmt.Fprintf(w, "Groups: %s\n", strings.Join(identity.Groups, ", ")); err != nil {
			return err
		}
		if err := renderTruncation(w, identity.GroupsTruncated, auth.MaxGroupListing, "groups"); err != nil {
			return err
		}
	}
	if len(identity.Connections) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "Connections: %s\n", strings.Join(identity.Connections, ", ")); err != nil {
		return err
	}
	return renderTruncation(w, identity.ConnectionsTruncated, auth.MaxConnectionListing, "connections")
}

// renderGroup prints the safe group projection: the name and UUID an agent
// addresses it by, what it is for, and the two counts that decide whether it
// can be deleted.
func renderGroup(w io.Writer, group auth.Group) error {
	_, err := fmt.Fprintf(w, "Group: %s (%s)\nDescription: %s\nMembers: %d\nGrants: %d\n",
		group.Name, group.ID, group.Description, group.Members, group.Grants)
	return err
}

// renderAccessList prints the subject first, because their role and status are
// what explain the paths, then one line per configured path: the connection,
// where the access comes from and when that path was created. It is a
// description of the configuration, never a claim that the connection can be
// used now.
func renderAccessList(w io.Writer, access auth.AccessList) error {
	if _, err := fmt.Fprintf(w, "User: %s (%s)\nRole: %s\nStatus: %s\n", access.User.Username,
		access.User.ID, access.User.Role, userStatus(access.User)); err != nil {
		return err
	}
	for _, entry := range access.Entries {
		source := auth.AccessDirect
		if entry.Source == auth.AccessGroup && entry.Group != nil {
			source = "via " + entry.Group.Name
		}
		if _, err := fmt.Fprintf(w, "%s %s %s\n", entry.Connection.Name, source, timestamp(entry.CreatedAt)); err != nil {
			return err
		}
	}
	return renderTruncation(w, access.Truncated, auth.MaxAccessListing, "entries")
}

// recipientLabel renders the one recipient a grant names. A group is prefixed
// so a group and a user of the same name stay distinguishable in text output,
// where the kind has no field of its own.
func recipientLabel(recipient auth.Recipient) string {
	if recipient.Kind == auth.RecipientGroup {
		return "group " + recipient.Name
	}
	return recipient.Name
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

// renderSkillInstall prints what happened where, one target per line, and
// closes with the version the files now carry: the outcome and the path are
// what a reader acts on, and the version is what the whole run installed.
func renderSkillInstall(w io.Writer, install SkillInstall) error {
	for _, target := range install.Targets {
		line := target.Outcome + "\t" + target.Path
		// Only an update has a previous version; a fresh directory replaced
		// nothing and an unchanged one is already at this version.
		if target.PreviousVersion != "" {
			line += " (was " + target.PreviousVersion + ")"
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	if err := renderDryRun(w, install.DryRun); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Version: %s\n", install.Version)
	return err
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
