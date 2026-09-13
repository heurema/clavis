package auth

import (
	"context"
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
)

// QueryRequest is one pass-through execution. The SQL is forwarded to the
// source unchanged: the platform never parses, rewrites or restricts it, and
// the source's own role is the only boundary. MaxRows is optional and may only
// lower the connection's row cap.
type QueryRequest struct {
	Connection string `json:"connection"`
	SQL        string `json:"sql"`
	MaxRows    int    `json:"maxRows,omitempty"`
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

// QueryResponse is always a list, even for a single statement, so a caller
// never has to branch on the shape of what it sent. Truncated is true when any
// result dropped a row against the bounds.
type QueryResponse struct {
	Results    []QueryResult `json:"results"`
	Truncated  bool          `json:"truncated"`
	DurationMS int64         `json:"durationMs"`
}

// SourceFailure is the source's own rejection, passed to the caller who wrote
// the SQL and never logged: its message may quote values from that SQL.
// Statement is the zero-based index of the failing statement in the submitted
// string, so zero is meaningful and always rendered. Position is the source's
// one-based character offset and is absent when the source reported none.
type SourceFailure struct {
	SQLState  string `json:"sqlstate,omitempty"`
	Message   string `json:"message,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Hint      string `json:"hint,omitempty"`
	Position  int    `json:"position,omitempty"`
	Statement int    `json:"statement"`
}

// QueryExecutor is the one execution entry point. Implementations authorize
// the caller before opening any credential and hold no platform transaction
// while the source is working.
type QueryExecutor interface {
	ExecuteQuery(context.Context, Session, QueryRequest) (QueryResponse, error)
}
