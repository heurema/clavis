package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
)

// strictJSON rejects ambiguous duplicate keys as well as unknown fields and
// trailing values. Never expose the decoder's error (it may contain a secret).
func strictJSON(body []byte, value any) bool {
	if !json.Valid(body) || !uniqueJSONKeys(json.NewDecoder(bytes.NewReader(body))) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	// encoding/json otherwise accepts case-insensitive aliases for struct tags.
	// Compare the wire keys with the DTO's actual JSON projection.
	canonical, err := json.Marshal(value)
	var wire, projected any
	if err != nil || json.Unmarshal(body, &wire) != nil || json.Unmarshal(canonical, &projected) != nil {
		return false
	}
	return exactJSONKeys(wire, projected)
}

func exactJSONKeys(wire, projected any) bool {
	if items, ok := wire.([]any); ok {
		expected, ok := projected.([]any)
		if !ok || len(items) != len(expected) {
			return false
		}
		for i := range items {
			if !exactJSONKeys(items[i], expected[i]) {
				return false
			}
		}
		return true
	}
	object, ok := wire.(map[string]any)
	if !ok {
		return true
	}
	expected, ok := projected.(map[string]any)
	if !ok {
		return false
	}
	for key, value := range object {
		target, exists := expected[key]
		if !exists || !exactJSONKeys(value, target) {
			return false
		}
	}
	return true
}

func uniqueJSONKeys(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return true
	}
	keys := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || keys[name] {
				return false
			}
			keys[name] = true
		}
		if !uniqueJSONKeys(d) {
			return false
		}
	}
	_, err = d.Token()
	return err == nil
}

// validIdentity accepts the optional granted-connection names whoami adds for
// members: bounded, each a valid connection name. They are absent from every
// other identity response, which stays valid with an empty list.
func validIdentity(value auth.Identity) bool {
	_, offset := value.ExpiresAt.Zone()
	if len(value.Connections) > auth.MaxConnectionListing || len(value.Groups) > auth.MaxGroupListing {
		return false
	}
	for _, name := range value.Connections {
		if !auth.ValidConnectionName(name) {
			return false
		}
	}
	// The group names whoami adds for every caller: bounded, each a valid
	// group name, and absent from every other identity response.
	for _, name := range value.Groups {
		if !auth.ValidGroupName(name) {
			return false
		}
	}
	return auth.ValidUserID(value.User.ID) && auth.ValidUsername(value.User.Username) &&
		validRole(value.User.Role) && !value.ExpiresAt.IsZero() && offset == 0
}

func validRole(role auth.Role) bool { return role == auth.Admin || role == auth.Member }

func validRecord(value auth.UserRecord) bool {
	_, offset := value.CreatedAt.Zone()
	return auth.ValidUserID(value.ID) && auth.ValidUsername(value.Username) &&
		validRole(value.Role) && !value.CreatedAt.IsZero() && offset == 0
}

func validList(value auth.UserList) bool {
	if len(value.Users) > auth.MaxUserListing {
		return false
	}
	for _, user := range value.Users {
		if !validRecord(user) {
			return false
		}
	}
	return true
}

func validTimestamp(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0
}

func validOutcome(outcome auth.CheckOutcome) bool {
	switch outcome {
	case auth.CheckReachable, auth.CheckAuthRejected, auth.CheckUnreachable, auth.CheckCredentialsUnavailable:
		return true
	}
	return false
}

func validCheck(value auth.CheckResult) bool {
	return validOutcome(value.Outcome) && validTimestamp(value.CheckedAt)
}

// maxTargetSettings bounds the non-secret provider settings a record may carry,
// and maxSettingKeyBytes one setting's name.
const (
	maxTargetSettings  = 8
	maxSettingKeyBytes = 63
)

// validSettingKey accepts a provider setting name: a lower-case letter followed
// by letters and digits, which is how every provider spells one, camel case
// included. A label has a grammar of its own and is validated with it; a target
// setting is the provider's own vocabulary and is only bounded and framed here.
func validSettingKey(key string) bool {
	if key == "" || len(key) > maxSettingKeyBytes || key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for index := 1; index < len(key); index++ {
		c := key[index]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

func validTarget(target map[string]string) bool {
	if len(target) == 0 || len(target) > maxTargetSettings {
		return false
	}
	for key, value := range target {
		if !validSettingKey(key) || !printableSetting(value) {
			return false
		}
	}
	return true
}

// validConnectionSummary accepts the member projection: identifiers, bounded
// text, valid labels and an optional last check. It has no target, bound or
// timestamp member at all, so a summary can never carry one.
func validConnectionSummary(value auth.ConnectionSummary) bool {
	if !auth.ValidUserID(value.ID) || !auth.ValidConnectionName(value.Name) || !auth.ValidProvider(value.Provider) {
		return false
	}
	if len(value.Title) > auth.MaxTitleLength || len(value.Description) > auth.MaxDescriptionLength ||
		len(value.Scope) > auth.MaxDescriptionLength {
		return false
	}
	// A hostile server must not be able to rewrite the terminal through text
	// fields that reach `--output text`.
	if (value.Title != "" && !printableSetting(value.Title)) || !printableText(value.Description) || !printableText(value.Scope) {
		return false
	}
	if !auth.ValidLabels(value.Labels) {
		return false
	}
	return value.LastCheck == nil || validCheck(*value.LastCheck)
}

func validConnectionSummaryList(value auth.ConnectionSummaryList) bool {
	if len(value.Connections) > auth.MaxConnectionListing {
		return false
	}
	for _, connection := range value.Connections {
		if !validConnectionSummary(connection) {
			return false
		}
	}
	return true
}

// validConnection accepts only the safe administrative projection: everything
// the summary carries plus a target, in-range resource bounds and UTC
// timestamps. A response carrying any extra field is already refused by strict
// decoding, and one missing any of these is not a full record.
func validConnection(value auth.Connection) bool {
	if !validConnectionSummary(value.Summary()) || !validTarget(value.Target) {
		return false
	}
	if value.StatementTimeoutMS < int(auth.MinStatementTimeout/time.Millisecond) ||
		value.StatementTimeoutMS > int(auth.MaxStatementTimeout/time.Millisecond) {
		return false
	}
	if value.MaxRows < 1 || value.MaxRows > auth.MaxMaxRows ||
		value.MaxBytes < auth.MinMaxBytes || value.MaxBytes > auth.MaxMaxBytes {
		return false
	}
	if !validTimestamp(value.CreatedAt) || !validTimestamp(value.UpdatedAt) {
		return false
	}
	return value.LastCheck == nil || validCheck(*value.LastCheck)
}

func validConnectionList(value auth.ConnectionList) bool {
	if len(value.Connections) > auth.MaxConnectionListing {
		return false
	}
	for _, connection := range value.Connections {
		if !validConnection(connection) {
			return false
		}
	}
	return true
}

// validGrantParty accepts one side of a grant: a stable UUID and the human
// name it resolved to, so a rendered grant never needs a second lookup.
func validGrantParty(value auth.GrantParty, name func(string) bool) bool {
	return auth.ValidUserID(value.ID) && name(value.Name)
}

// validRecipient accepts the one recipient a grant is keyed on. The kind says
// which namespace the name belongs to, and an unknown kind is an undocumented
// response rather than a grant to render.
func validRecipient(value auth.Recipient) bool {
	switch value.Kind {
	case auth.RecipientUser:
		return auth.ValidUserID(value.ID) && auth.ValidUsername(value.Name)
	case auth.RecipientGroup:
		return auth.ValidUserID(value.ID) && auth.ValidGroupName(value.Name)
	}
	return false
}

func validGrant(value auth.Grant) bool {
	return validRecipient(value.Recipient) &&
		validGrantParty(value.Connection, auth.ValidConnectionName) &&
		validGrantParty(value.CreatedBy, auth.ValidUsername) && validTimestamp(value.CreatedAt)
}

func validGrantList(value auth.GrantList) bool {
	if len(value.Grants) > auth.MaxGrantListing {
		return false
	}
	for _, grant := range value.Grants {
		if !validGrant(grant) {
			return false
		}
	}
	return true
}

// A revocation that removed nothing is a documented success, so Revoked is not
// required to be true; both parties must still be named.
func validGrantRevocation(value auth.GrantRevocation) bool {
	return validRecipient(value.Recipient) &&
		validGrantParty(value.Connection, auth.ValidConnectionName)
}

// validAccessEntry accepts one configured path to a connection. The source and
// the group member are checked together: a group path without a group, or a
// direct path carrying one, describes no path this contract defines and is an
// undocumented response rather than a line to render.
func validAccessEntry(value auth.AccessEntry) bool {
	if !validGrantParty(value.Connection, auth.ValidConnectionName) || !validTimestamp(value.CreatedAt) {
		return false
	}
	switch value.Source {
	case auth.AccessDirect:
		return value.Group == nil
	case auth.AccessGroup:
		return value.Group != nil && validGrantParty(*value.Group, auth.ValidGroupName)
	}
	return false
}

// validAccessList accepts the effective listing: the subject's safe record and
// one entry per configured path. A subject with no paths at all is a
// documented answer, so an empty list is valid.
func validAccessList(value auth.AccessList) bool {
	if !validRecord(value.User) || len(value.Entries) > auth.MaxAccessListing {
		return false
	}
	for _, entry := range value.Entries {
		if !validAccessEntry(entry) {
			return false
		}
	}
	return true
}

// validGroup accepts the safe group projection: identity, bounded description,
// UTC timestamps and two counts that can never be negative.
func validGroup(value auth.Group) bool {
	if !auth.ValidUserID(value.ID) || !auth.ValidGroupName(value.Name) {
		return false
	}
	if utf8.RuneCountInString(value.Description) > auth.MaxDescriptionLength || !printableText(value.Description) {
		return false
	}
	if value.Members < 0 || value.Grants < 0 {
		return false
	}
	return validTimestamp(value.CreatedAt) && validTimestamp(value.UpdatedAt)
}

func validGroupList(value auth.GroupList) bool {
	if len(value.Groups) > auth.MaxGroupListing {
		return false
	}
	for _, group := range value.Groups {
		if !validGroup(group) {
			return false
		}
	}
	return true
}

func validMemberList(value auth.MemberList) bool {
	if len(value.Members) > auth.MaxMemberListing {
		return false
	}
	for _, member := range value.Members {
		if !validRecord(member.UserRecord) || !validTimestamp(member.AddedAt) ||
			!validGrantParty(member.AddedBy, auth.ValidUsername) {
			return false
		}
	}
	return true
}

// A membership that was already in place is a documented success, so Added is
// not required to be true; every party must still be named.
func validMembership(value auth.Membership) bool {
	return validGrantParty(value.Group, auth.ValidGroupName) &&
		validGrantParty(value.User, auth.ValidUsername) &&
		validGrantParty(value.CreatedBy, auth.ValidUsername) && validTimestamp(value.CreatedAt)
}

func validMembershipRemoval(value auth.MembershipRemoval) bool {
	return validGrantParty(value.Group, auth.ValidGroupName) &&
		validGrantParty(value.User, auth.ValidUsername)
}

// maxQueryColumns is PostgreSQL's own hard column limit, which no result can
// exceed; maxCommandBytes bounds the command tag word, and maxSourceTextBytes
// each free-text member of a source failure.
const (
	maxQueryColumns    = 1664
	maxCommandBytes    = 64
	maxIdentifierBytes = 63
	maxSourceTextBytes = auth.QueryEnvelopeAllowance
)

// sqlState is the five-character SQLSTATE the source reports.
var sqlState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// validSourceFailure accepts the source's own rejection: a well-formed
// SQLSTATE, non-negative offsets and renderable text. The message is the
// source's, not the platform's, so it is bounded and checked for control
// characters rather than trusted onto a terminal.
func validSourceFailure(value auth.SourceFailure) bool {
	if value.SQLState != "" && !sqlState.MatchString(value.SQLState) {
		return false
	}
	// A source classifies its own failure either way, never both: a SQLSTATE is
	// PostgreSQL's word and an errorType is an HTTP source's, whether it wrote
	// the classification itself or the platform named the status.
	// Such a failure carries no statement index either: the source ran one
	// request, and the index belongs to a script.
	if value.ErrorType != "" && (value.SQLState != "" || value.Statement != nil || !printableSetting(value.ErrorType)) {
		return false
	}
	if value.Position < 0 || (value.Statement != nil && *value.Statement < 0) {
		return false
	}
	for _, text := range []string{value.Message, value.Detail, value.Hint} {
		if len(text) > maxSourceTextBytes || !printableText(text) {
			return false
		}
	}
	return value.Message != ""
}

// validCommandTag accepts the source's command tag word. A comment-only
// statement produces no tag at all, which is a documented result rather than a
// malformed one.
func validCommandTag(value string) bool {
	return len(value) <= maxCommandBytes && (value == "" || printableSetting(value))
}

// validQueryResult accepts one statement's outcome: a bounded column list, a
// row for every kept row with exactly one value per column, and non-negative
// counts. Row values themselves are the caller's own data and are accepted
// unchanged; only their shape is checked.
func validQueryResult(value auth.QueryResult) bool {
	if !validCommandTag(value.Command) || len(value.Columns) > maxQueryColumns {
		return false
	}
	for _, column := range value.Columns {
		// A column name is whatever the SQL aliased it to, tabs and line
		// breaks included, within PostgreSQL's identifier length; a type
		// name is a catalogue value.
		if column.Name == "" || len(column.Name) > maxIdentifierBytes || !printableText(column.Name) || !printableSetting(column.Type) {
			return false
		}
	}
	if value.RowCount < 0 || len(value.Rows) > auth.MaxMaxRows {
		return false
	}
	for _, row := range value.Rows {
		if len(row) != len(value.Columns) {
			return false
		}
	}
	// A zero-column result set (`select from t`) is legal and carries empty
	// rows, so columns and rows are only tied by width.
	return true
}

// The result types a metrics answer may name: the source's own word for an
// expression, and the platform's for each of the three discovery endpoints.
var metricsResultTypes = []string{"vector", "matrix", "scalar", "string", "labels", "labelValues", "series"}

// The result types a log answer may name. A log source writes no result type
// of its own, so each of these names the input the platform forwarded.
var logsResultTypes = []string{"logs", "fieldNames", "fieldValues", "streams",
	"streamFieldNames", "streamFieldValues"}

// validQueryResponse accepts the document the named provider defines, and only
// that one: a results list for PostgreSQL, a native metrics answer for
// VictoriaMetrics, the source's own rows for VictoriaLogs, and nothing that
// mixes them or names none of them.
func validQueryResponse(value auth.QueryResponse) bool {
	if value.DurationMS < 0 {
		return false
	}
	switch value.Provider {
	case auth.ProviderPostgreSQL:
		return validResultsDocument(value)
	case auth.ProviderVictoriaMetrics:
		return validMetricsDocument(value)
	case auth.ProviderVictoriaLogs:
		return validLogsDocument(value)
	}
	return false
}

// validLogsDocument accepts the log source's own answer: a known result type, a
// result whose shape matches it, and none of the members another provider's
// document carries. A log source writes no warnings, infos or partial flag, so
// a document carrying one is not the shape this provider produces.
func validLogsDocument(value auth.QueryResponse) bool {
	if value.Results != nil || value.Warnings != nil || value.Infos != nil || value.IsPartial {
		return false
	}
	if !slices.Contains(logsResultTypes, value.ResultType) {
		return false
	}
	return validLogsResult(value.ResultType, value.Result)
}

// logsValue is one discovery item as the platform re-encoded it: the source's
// own value text and its hit count, kept exact. Both are pointers because the
// pair is the whole shape: an item missing either is not the source's answer.
// The count is raw so that a quoted number is refused rather than accepted: a
// hit count the source wrote as text is not a count.
type logsValue struct {
	Value *string          `json:"value"`
	Hits  *json.RawMessage `json:"hits"`
}

// validLogsHits accepts a hit count the source wrote as a JSON number, with the
// digits it wrote, and nothing that only looks like one.
func validLogsHits(raw *json.RawMessage) bool {
	if raw == nil {
		return false
	}
	var hits json.Number
	if json.Unmarshal(*raw, &hits) != nil {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(*raw), []byte(hits.String()))
}

// validLogsResult checks that the result is the shape its type names. The rows
// inside are the source's own data and are accepted as they are, with any
// fields and any JSON value types it wrote; only the frame around them is
// judged, exactly as a SQL row's values are.
func validLogsResult(resultType string, raw json.RawMessage) bool {
	// An absent or null result is not an empty one: the platform always sends
	// the array its own result type promises, empty when nothing matched.
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	if resultType == "logs" {
		var rows []map[string]json.RawMessage
		if json.Unmarshal(raw, &rows) != nil || rows == nil {
			return false
		}
		for _, row := range rows {
			if row == nil {
				return false
			}
		}
		return true
	}
	var values []logsValue
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return false
	}
	for _, item := range values {
		if item.Value == nil || !validLogsHits(item.Hits) {
			return false
		}
	}
	return true
}

// validMetricsDocument accepts the source's own answer: a known result type, a
// result whose shape matches it, renderable notes and no results list, because
// a metrics connection never produces one.
func validMetricsDocument(value auth.QueryResponse) bool {
	if value.Results != nil || !slices.Contains(metricsResultTypes, value.ResultType) {
		return false
	}
	for _, note := range slices.Concat(value.Warnings, value.Infos) {
		if note == "" || len(note) > maxSourceTextBytes || !printableText(note) {
			return false
		}
	}
	return validMetricsResult(value.ResultType, value.Result)
}

// metricsSeries is one vector or matrix entry as the platform re-encoded it: a
// label set, one sample or a list of them, and the mark a cut series carries.
// Members the source added of its own travel with it unchanged, so unknown
// ones are accepted here rather than refused.
type metricsSeries struct {
	Metric    map[string]string   `json:"metric"`
	Value     []json.RawMessage   `json:"value"`
	Values    [][]json.RawMessage `json:"values"`
	Truncated bool                `json:"truncated"`
}

// validMetricsResult checks that the result is the shape its type names. The
// values inside are the source's own data and are accepted as they are; only
// the frame around them is judged, exactly as a SQL row's values are.
func validMetricsResult(resultType string, raw json.RawMessage) bool {
	// An absent or null result is not an empty one: the source always sends
	// the container its own result type promises.
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	switch resultType {
	case "vector", "matrix":
		var series []metricsSeries
		if json.Unmarshal(raw, &series) != nil {
			return false
		}
		for _, entry := range series {
			if entry.Metric == nil {
				return false
			}
			if resultType == "vector" {
				if entry.Values != nil || !validMetricsPair(entry.Value) {
					return false
				}
				continue
			}
			if entry.Value != nil || entry.Values == nil {
				return false
			}
			for _, sample := range entry.Values {
				if !validMetricsPair(sample) {
					return false
				}
			}
		}
		return true
	case "scalar", "string":
		var sample []json.RawMessage
		return json.Unmarshal(raw, &sample) == nil && validMetricsPair(sample)
	case "labels", "labelValues":
		var names []string
		return json.Unmarshal(raw, &names) == nil && names != nil
	default:
		var sets []map[string]string
		if json.Unmarshal(raw, &sets) != nil || sets == nil {
			return false
		}
		for _, set := range sets {
			if set == nil {
				return false
			}
		}
		return true
	}
}

// validMetricsPair accepts one sample: the timestamp the source rendered as a
// number and the value it rendered as a string, which is what keeps an exact
// value exact.
func validMetricsPair(pair []json.RawMessage) bool {
	if len(pair) != 2 {
		return false
	}
	var timestamp json.Number
	if json.Unmarshal(pair[0], &timestamp) != nil ||
		!bytes.Equal(bytes.TrimSpace(pair[0]), []byte(timestamp.String())) {
		return false
	}
	var value string
	return json.Unmarshal(pair[1], &value) == nil
}

// validResultsDocument accepts the documented results document. The number of
// results is bounded by the response body limit alone: one statement's outcome
// is a few dozen bytes, and the SQL that produced them was bounded before it
// was sent. None of the metrics members may be set: one provider's document is
// never readable as another's.
func validResultsDocument(value auth.QueryResponse) bool {
	if value.ResultType != "" || value.Result != nil || value.Warnings != nil ||
		value.Infos != nil || value.IsPartial {
		return false
	}
	truncated := false
	for _, result := range value.Results {
		if !validQueryResult(result) {
			return false
		}
		truncated = truncated || result.Truncated
	}
	// The top-level flag is the one an agent branches on, so it may not
	// understate what the results already say.
	return !truncated || value.Truncated
}

// responseDecoder is the seam for the two connection reads, the only routes
// whose success body has two documented shapes. Everything else decodes into
// one DTO and is validated by the type switch below.
type responseDecoder interface{ decode(body []byte) bool }

// connectionRecord holds whichever shape `connections get` received: the
// administrator's full record or the member's summary. Each is decoded
// strictly and validated on its own, so a response that mixes the two - a
// summary carrying a target, or a record missing its bounds - matches neither
// and is refused as an invalid response.
type connectionRecord struct {
	full    *auth.Connection
	summary *auth.ConnectionSummary
}

func (c *connectionRecord) decode(body []byte) bool {
	var full auth.Connection
	if strictJSON(body, &full) && validConnection(full) {
		c.full = &full
		return true
	}
	var summary auth.ConnectionSummary
	if strictJSON(body, &summary) && validConnectionSummary(summary) {
		c.summary = &summary
		return true
	}
	return false
}

// data returns the projection that arrived, so the result envelope carries the
// server's shape unchanged rather than a widened one.
func (c *connectionRecord) data() any {
	if c.full != nil {
		return *c.full
	}
	return *c.summary
}

// connectionListing is connectionRecord for `connections list`.
type connectionListing struct {
	full    *auth.ConnectionList
	summary *auth.ConnectionSummaryList
}

func (c *connectionListing) decode(body []byte) bool {
	var full auth.ConnectionList
	if strictJSON(body, &full) && validConnectionList(full) {
		c.full = &full
		return true
	}
	var summary auth.ConnectionSummaryList
	if strictJSON(body, &summary) && validConnectionSummaryList(summary) {
		c.summary = &summary
		return true
	}
	return false
}

func (c *connectionListing) data() any {
	if c.full != nil {
		if c.full.Connections == nil {
			c.full.Connections = []auth.Connection{}
		}
		return *c.full
	}
	if c.summary.Connections == nil {
		c.summary.Connections = []auth.ConnectionSummary{}
	}
	return *c.summary
}

// documentedFailure is the per-route error allowlist from the HTTP contract.
// Codes every bearer route may return (400, 401, 403, 503) pass; the rest are
// only accepted where routeFailures lists them for that method and path.
func documentedFailure(code, method, path string) bool {
	switch code {
	case auth.InvalidCredentials:
		return path == auth.LoginPath
	case auth.Unauthenticated:
		return path != auth.LoginPath
	case auth.UserNotFound, auth.UsernameTaken, auth.LastAdministrator, auth.SelfTarget, auth.RateLimited,
		auth.ConnectionExists, auth.ConnectionNotFound, auth.ConnectionInUse, auth.CredentialsUnavailable,
		auth.ConnectionDisabled, auth.GroupExists, auth.GroupNotFound, auth.GroupInUse,
		auth.SourceError, auth.SourceTimeout, auth.SourceUnreachable,
		auth.SourceAuthRejected, auth.ProviderUnsupported:
		return slices.Contains(routeFailures(method, path), code)
	}
	return true
}

// maxHintBytes bounds the optional server hint the CLI is willing to render.
const maxHintBytes = 512

// safeHint passes the server's optional next-step guidance through unchanged
// when it is plainly renderable. Anything longer, invalid or carrying control
// characters is dropped rather than printed: a hint is guidance, never data.
func safeHint(hint string) string {
	if hint == "" || len(hint) > maxHintBytes || !utf8.ValidString(hint) {
		return ""
	}
	if strings.ContainsFunc(hint, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	return hint
}

// routeFailures is the positive list of route-specific codes from the design's
// HTTP table. Administration routes are POST except the listing.
func routeFailures(method, path string) []string {
	target := strings.HasPrefix(path, auth.UsersPath+"/")
	connection := strings.HasPrefix(path, auth.ConnectionsPath+"/")
	group := strings.HasPrefix(path, auth.GroupsPath+"/")
	switch {
	// The effective listing resolves one subject, so the user is the only
	// reference it can fail to find; the role rule it applies is an argument
	// failure, which every bearer route may already return.
	case path == auth.GrantsEffectivePath:
		return []string{auth.UserNotFound}
	case path == auth.GroupsPath && method == http.MethodPost:
		return []string{auth.GroupExists}
	case path == auth.GroupsPath: // the bounded listing
		return nil
	case group && strings.HasSuffix(path, "/update"):
		return []string{auth.GroupNotFound, auth.GroupExists}
	case group && strings.HasSuffix(path, "/delete"):
		return []string{auth.GroupNotFound, auth.GroupInUse}
	case group && (strings.HasSuffix(path, "/members/add") || strings.HasSuffix(path, "/members/remove")):
		return []string{auth.GroupNotFound, auth.UserNotFound}
	case group: // the record and the bounded member listing
		return []string{auth.GroupNotFound}
	// Execution is the one route where the source itself can be the reason a
	// request failed, so the four source codes join the authorization ones.
	case path == auth.QueryPath:
		return []string{auth.SourceError, auth.SourceTimeout, auth.SourceUnreachable, auth.SourceAuthRejected,
			auth.CredentialsUnavailable, auth.ProviderUnsupported, auth.ConnectionNotFound, auth.ConnectionDisabled}
	case path == auth.GrantRevokePath || (path == auth.GrantsPath && method == http.MethodPost):
		return []string{auth.UserNotFound, auth.GroupNotFound, auth.ConnectionNotFound}
	case path == auth.GrantsPath: // the bounded listing
		return nil
	case path == auth.ConnectionsPath && method == http.MethodPost:
		return []string{auth.ConnectionExists}
	case path == auth.ConnectionsPath: // the bounded listing
		return nil
	case connection && strings.HasSuffix(path, "/update"):
		return []string{auth.ConnectionNotFound, auth.ConnectionExists}
	case connection && strings.HasSuffix(path, "/delete"):
		return []string{auth.ConnectionNotFound, auth.ConnectionInUse}
	case connection && strings.HasSuffix(path, "/check"):
		return []string{auth.ConnectionNotFound, auth.CredentialsUnavailable}
	case connection: // the record, credentials, enable and disable
		return []string{auth.ConnectionNotFound}
	case path == auth.UsersPath && method == http.MethodPost:
		return []string{auth.UsernameTaken, auth.RateLimited}
	case path == auth.UsersPath:
		return nil
	case target && (strings.HasSuffix(path, "/block") || strings.HasSuffix(path, "/role")):
		return []string{auth.UserNotFound, auth.LastAdministrator, auth.SelfTarget}
	case target && strings.HasSuffix(path, "/unblock"):
		return []string{auth.UserNotFound}
	case target: // password reset and session revocation
		return []string{auth.UserNotFound, auth.RateLimited}
	default: // login, whoami, logout
		return []string{auth.RateLimited}
	}
}

// queryBodyAllowance is what a query request may add on top of the SQL: the
// JSON framing, the connection reference and maxRows. The route bounds its own
// body with the same sum, so a body one side refuses is one the other never
// builds.
const queryBodyAllowance = 4096

// requestLimit is the per-route request bound. Every route carries a
// credential-sized body except execution, which carries the SQL.
func requestLimit(path string) int {
	if path == auth.QueryPath {
		return auth.MaxSQLBytes + queryBodyAllowance
	}
	return auth.MaxCredentialBody
}

// responseLimit is the per-route response bound: the general limit, the
// listing limit for the three bounded listings, and for execution the largest
// byte cap a connection may carry plus the envelope allowance, doubled for the
// escaping headroom. The CLI does not know the connection's own cap, so it
// reads under the ceiling; values are bounded by the server's drain, but JSON
// escaping can double a value the source rendered, so the ceiling alone would
// refuse a legitimate result.
func responseLimit(method, path string) int {
	switch {
	case path == auth.QueryPath:
		return 2*auth.MaxMaxBytes + auth.QueryEnvelopeAllowance
	// Every bounded listing is read under the listing limit, the group record
	// and member listing included: their paths carry the group reference, so
	// the whole group prefix is covered rather than one literal path.
	case method == http.MethodGet && (path == auth.UsersPath || path == auth.ConnectionsPath ||
		path == auth.GrantsPath || path == auth.GrantsEffectivePath || strings.HasPrefix(path, auth.GroupsPath)):
		return auth.MaxListingBody
	default:
		return auth.MaxResponseBody
	}
}

type authTransport struct {
	origin  string
	timeout time.Duration
}

// Each call uses a fresh transport, with no reusable connection on which net/http
// could retry a request. Redirect destinations never receive credentials.
func (a authTransport) request(ctx context.Context, path string, token auth.Secret, input *auth.LoginRequest, output any) *Result {
	method := http.MethodPost
	if path == auth.WhoAmIPath {
		method = http.MethodGet
	}
	if input == nil {
		return a.call(ctx, method, path, token, nil, output)
	}
	return a.call(ctx, method, path, token, input, output)
}

// apiCall names one documented route: its method, path, optional query string
// and the success status the HTTP contract documents for it.
type apiCall struct {
	method string
	path   string
	query  string
	status int
}

// accepts reports whether a response status is a documented success for this
// route. Grant creation and membership addition are the two idempotent
// mutations: each answers 201 when it committed and 200 with the same body
// when the row was already in place, so a retrying agent needs exactly one
// request either way.
func (route apiCall) accepts(status int) bool {
	if status == route.status {
		return true
	}
	idempotent := route.path == auth.GrantsPath || strings.HasSuffix(route.path, "/members/add")
	return route.method == http.MethodPost && idempotent &&
		route.status == http.StatusCreated && status == http.StatusOK
}

// call performs one bounded request on a route without query parameters.
// Creation (POST UsersPath) is the only such route whose documented success
// status is 201; every other one expects 200.
func (a authTransport) call(ctx context.Context, method, path string, token auth.Secret, input, output any) *Result {
	status := http.StatusOK
	if method == http.MethodPost && path == auth.UsersPath {
		status = http.StatusCreated
	}
	return a.send(ctx, apiCall{method: method, path: path, status: status}, token, input, output)
}

// send performs one bounded request against a documented route.
func (a authTransport) send(ctx context.Context, route apiCall, token auth.Secret, input, output any) *Result {
	method, path := route.method, route.path
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > requestLimit(path) {
			r := failure("INVALID_ARGUMENT", "Invalid request input", nil)
			return &r
		}
		body = bytes.NewReader(encoded)
	}
	address := a.origin + path
	if route.query != "" {
		address += "?" + route.query
	}
	request, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		r := failure("INVALID_ARGUMENT", "Invalid server origin", nil)
		return &r
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+string(token))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return transportFailure(ctx)
	}
	defer func() { _ = response.Body.Close() }()
	limit := responseLimit(method, path)
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if ctx.Err() != nil {
		return transportFailure(ctx)
	}
	invalid := failure("INVALID_RESPONSE", "Server returned an invalid authentication response", nil)
	contentType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	// Every documented body, success or error, is one JSON object.
	if err != nil || len(data) > limit || typeErr != nil || contentType != "application/json" ||
		!bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return &invalid
	}
	if !route.accepts(response.StatusCode) {
		var remote auth.ErrorResponse
		if !strictJSON(data, &remote) || remote.Error.Message == "" {
			return &invalid
		}
		status, safe, known := auth.LookupFailure(remote.Error.Code)
		if !known || status != response.StatusCode || !documentedFailure(remote.Error.Code, method, path) {
			return &invalid
		}
		// Only the source's own rejection carries a source block, and only on
		// the execution route: anywhere else it is an undocumented envelope.
		if remote.Source != nil &&
			(remote.Error.Code != auth.SourceError || path != auth.QueryPath || !validSourceFailure(*remote.Source)) {
			return &invalid
		}
		// The message is the client's own allowlisted text; only the optional
		// hint is server-authored, and it is rendered as guidance.
		r := failureWithHint(safe.Code, safe.Message, safeHint(remote.Error.Hint))
		r.Error.Source = remote.Source
		return &r
	}
	if decoder, twoShapes := output.(responseDecoder); twoShapes {
		if !decoder.decode(data) {
			return &invalid
		}
		return nil
	}
	if !strictJSON(data, output) {
		return &invalid
	}
	valid := false
	switch value := output.(type) {
	case *auth.LoginResponse:
		valid = auth.ValidToken(value.Token) && validIdentity(value.Identity) && value.ExpiresAt.After(time.Now())
	case *auth.Identity:
		valid = validIdentity(*value) && value.ExpiresAt.After(time.Now())
	case *auth.Revocation:
		valid = value.Revoked
	case *auth.UserRecord:
		valid = validRecord(*value)
	case *auth.UserList:
		valid = validList(*value)
	case *auth.UserMutation:
		valid = validRecord(value.User)
	case *auth.Connection:
		valid = validConnection(*value)
	case *auth.ConnectionList:
		valid = validConnectionList(*value)
	case *auth.ConnectionMutation:
		valid = validConnection(value.Connection)
	case *auth.ConnectionDeletion:
		valid = auth.ValidUserID(value.ID) && auth.ValidConnectionName(value.Name) && value.Deleted
	case *auth.ConnectionCheck:
		valid = validConnection(value.Connection) && validCheck(value.Check)
	case *auth.GrantList:
		valid = validGrantList(*value)
	case *auth.GrantMutation:
		valid = validGrant(value.Grant)
	case *auth.GrantRevocation:
		valid = validGrantRevocation(*value)
	case *auth.AccessList:
		valid = validAccessList(*value)
	case *auth.Group:
		valid = validGroup(*value)
	case *auth.GroupList:
		valid = validGroupList(*value)
	case *auth.GroupMutation:
		valid = validGroup(value.Group)
	case *auth.GroupDeletion:
		valid = validGrantParty(value.Group, auth.ValidGroupName)
	case *auth.MemberList:
		valid = validMemberList(*value)
	case *auth.MembershipMutation:
		valid = validMembership(value.Membership)
	case *auth.MembershipRemoval:
		valid = validMembershipRemoval(*value)
	case *auth.QueryResponse:
		valid = validQueryResponse(*value)
	}
	if !valid {
		return &invalid
	}
	return nil
}

func transportFailure(ctx context.Context) *Result {
	r := failure("SERVER_UNREACHABLE", "Server could not be reached", nil)
	if ctx.Err() != nil {
		r = failure("TIMEOUT", "Authentication request did not complete; a mutation may have taken effect", nil)
	}
	return &r
}
