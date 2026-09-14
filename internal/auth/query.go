package auth

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

// QueryRequestBudget is the whole-request deadline an execution runs under, on
// the route, in the CLI and as the service's own backstop. The service bounds
// a hung connection at ten times the connection's statement timeout plus five
// seconds, so this is the largest request any connection can produce plus
// headroom; the shared five-second operation bound would cut a perfectly
// ordinary query long before its own statement timeout expired.
const QueryRequestBudget = 10*MaxStatementTimeout + 10*time.Second

// QueryPath is the one execution route. It is not an administration route: a
// member with a grant uses it, so it sits outside /api/admin.
const QueryPath = "/api/query"

// Bounds shared by the service, the route and the CLI. MaxSQLBytes bounds the
// submitted statement; QueryEnvelopeAllowance is what a response may add on
// top of the connection's byte cap for column metadata, command tags and the
// JSON framing itself, so a route can bound a response it has not yet built.
const (
	MaxSQLBytes            = 256 << 10
	QueryEnvelopeAllowance = 64 << 10
	// MaxFilterBytes bounds the log discovery filter, which is a substring the
	// source matches against a field value rather than a query of its own. It
	// is deliberately far below MaxSQLBytes: a filter that needs a kilobyte is
	// a query, and a query belongs in the input the endpoint takes.
	MaxFilterBytes = 1024
)

// MetricsGrace is what a metrics request may spend beyond the connection's
// timeout before the platform cuts the HTTP exchange. The source is asked to
// abort its own evaluation at the timeout, so the grace only covers writing
// and reading the answer; a source that stops answering is cut here.
const MetricsGrace = 5 * time.Second

// maxLabelNameBytes bounds a label name. Prometheus documents no limit, so
// this is the platform's: the name forms a path segment on the source.
const maxLabelNameBytes = 256

// MetricsBodyCeiling is the hard bound on a metrics response body. It is four
// times the connection's byte cap, which counts only kept label and sample
// text, plus one MiB for the timestamps, the JSON framing and the envelope
// around them. A body beyond it fails the request: presenting a cut body as
// data would present something the platform never validated.
func MetricsBodyCeiling(maxBytes int) int {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	return 4*maxBytes + 1<<20
}

// maxTenantIDBytes bounds a tenant identifier: ten digits is the widest
// unsigned 32-bit decimal, so nothing longer can name a tenant.
const maxTenantIDBytes = 10

// ValidTenantID is the VictoriaLogs tenant grammar: an unsigned 32-bit decimal
// integer. It is validated, unlike a query, because it travels as a request
// header the source reads as an identity; a sign, a space or a stray byte
// there would be a header the administrator never configured.
func ValidTenantID(value string) bool {
	if value == "" || len(value) > maxTenantIDBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}

// ValidLabelName is the Prometheus label name grammar. A label name is
// validated, alone among the metrics inputs, because it forms a path segment
// on the source: anything else could reach a path no administrator granted.
func ValidLabelName(name string) bool {
	if name == "" || len(name) > maxLabelNameBytes {
		return false
	}
	for index := range len(name) {
		c := name[index]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case index > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// QueryRequest is one pass-through execution. Exactly one input is set: SQL
// for a PostgreSQL connection, for a VictoriaMetrics connection a PromQL
// expression or one of the three metrics discovery inputs, and for a
// VictoriaLogs connection a LogsQL query or one of the five log discovery
// inputs. Every string is forwarded to the source unchanged: the platform
// never parses, rewrites or restricts a query, a time, a step, a selector or a
// filter, and the source's own rules are the only boundary. MaxRows is
// optional and may only lower the connection's row cap, which is a sample cap
// for metrics and a row cap for logs.
type QueryRequest struct {
	Connection string `json:"connection"`
	SQL        string `json:"sql,omitempty"`
	PromQL     string `json:"promql,omitempty"`
	LogsQL     string `json:"logsql,omitempty"`
	// At pins an instant query; Start, End and Step make it a range query.
	// They carry the source's own time and duration formats, unparsed. Start
	// and End bound a log query too; At and Step never do.
	At    string `json:"at,omitempty"`
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
	Step  string `json:"step,omitempty"`
	// The three metrics discovery inputs, each reaching one read-only metadata
	// endpoint on the source.
	Labels      bool   `json:"labels,omitempty"`
	LabelValues string `json:"labelValues,omitempty"`
	Series      string `json:"series,omitempty"`
	// The five log discovery inputs, each reaching one read-only metadata
	// endpoint on the source and each taking Match as the source's own query.
	FieldNames        bool   `json:"fieldNames,omitempty"`
	FieldValues       string `json:"fieldValues,omitempty"`
	Streams           bool   `json:"streams,omitempty"`
	StreamFieldNames  bool   `json:"streamFieldNames,omitempty"`
	StreamFieldValues string `json:"streamFieldValues,omitempty"`
	// Match is an optional selector narrowing a metrics discovery request and
	// the required query of a log discovery request.
	Match string `json:"match,omitempty"`
	// Limit is the source's own limit, forwarded as its decimal text and never
	// added by the platform. It is a pointer because zero is the caller's
	// explicit "no limit" and absent is "the caller said nothing": the two
	// reach the source as a sent zero and as no parameter at all. A negative
	// value is refused.
	Limit *int64 `json:"limit,omitempty"`
	// Filter is the substring a log discovery endpoint matches against a value.
	// It is a parameter value, bounded and never parsed.
	Filter  string `json:"filter,omitempty"`
	MaxRows int    `json:"maxRows,omitempty"`
}

// QueryColumn names one column and the source's own type name for it.
type QueryColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// QueryResult is one statement's outcome. Rows are the text the source
// rendered, never a JSON number, boolean or object, so an exact numeric, a
// 64-bit integer and a timestamp all survive the trip unchanged; a nil pointer
// is SQL NULL, which is why an empty string stays distinguishable from it.
// Columns and Rows are empty lists, never null, for a statement without rows.
type QueryResult struct {
	Command   string        `json:"command"`
	Columns   []QueryColumn `json:"columns"`
	Rows      [][]*string   `json:"rows"`
	RowCount  int64         `json:"rowCount"`
	Truncated bool          `json:"truncated"`
}

// QueryResponse carries the shape the connection's provider defines, named by
// Provider so a caller branches on one field rather than on what it sent. For
// PostgreSQL that is Results, always a list even for a single statement. For
// VictoriaMetrics it is ResultType and Result, the source's own data in the
// Prometheus format, with the source's warnings, infos and partial-answer flag
// beside it. For VictoriaLogs it is the same two fields: ResultType is logs,
// fieldNames, fieldValues, streams, streamFieldNames or streamFieldValues, and
// Result holds the source's own rows or value-and-hits pairs as one array. Truncated is the platform's own word about the bounds it applied;
// IsPartial is the source's about its data, and the two are never folded into
// one another.
type QueryResponse struct {
	Provider   ProviderType    `json:"provider"`
	Results    []QueryResult   `json:"results,omitempty"`
	ResultType string          `json:"resultType,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Infos      []string        `json:"infos,omitempty"`
	IsPartial  bool            `json:"isPartial,omitempty"`
	Truncated  bool            `json:"truncated"`
	DurationMS int64           `json:"durationMs"`
}

// SourceFailure is the source's own rejection, passed to the caller who wrote
// the input and never logged: its message may quote values from that input.
// ErrorType is a metrics source's own classification of the failure, or the
// platform's http_<status> when the source answered an error carrying none,
// which is every failing answer of a log source; the platform's own
// response_too_large and malformed_response travel here too.
// Statement is the zero-based index of the failing statement in a submitted
// SQL string, so zero is meaningful and is rendered whenever it is set; it is
// absent for a source that has no statements. Position is the source's
// one-based character offset and is absent when the source reported none.
type SourceFailure struct {
	SQLState  string `json:"sqlstate,omitempty"`
	ErrorType string `json:"errorType,omitempty"`
	Message   string `json:"message,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Hint      string `json:"hint,omitempty"`
	Position  int    `json:"position,omitempty"`
	Statement *int   `json:"statement,omitempty"`
}

// StatementIndex is how a caller sets SourceFailure.Statement, where zero is a
// meaningful index rather than an absent one.
func StatementIndex(index int) *int { return &index }

// QueryExecutor is the one execution entry point. Implementations authorize
// the caller before opening any credential and hold no platform transaction
// while the source is working.
type QueryExecutor interface {
	ExecuteQuery(context.Context, Session, QueryRequest) (QueryResponse, error)
}
