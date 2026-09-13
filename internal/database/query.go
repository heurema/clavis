package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/provider"
)

var _ auth.QueryExecutor = (*LocalAuth)(nil)

// The request deadline is a backstop for a connection that stops answering,
// and the only case in which the platform itself cancels anything: everywhere
// else the source enforces its own bound and we wait for its verdict. It
// cannot be the statement timeout plus a grace, because PostgreSQL applies
// statement_timeout to each statement of a script separately, so a legitimate
// script may run several times the bound; cutting it off would cancel a
// statement the source had not aborted. Ten times the bound plus the grace
// leaves room for that and still ends a hung connection. Reaching it is
// reported as the source's own timeout, which is what it looks like from here.
const (
	queryDeadlineFactor = 10
	queryGrace          = 5 * time.Second
)

// Hints are fixed application text: they name the next action or the valid
// range and never echo the submitted SQL, which is the caller's own data.
const (
	hintQueryRows        = "maxRows is 0 for the connection's own row cap, or a positive number at or below it."
	hintQueryUnsupported = "Only postgresql connections can execute queries in this release."
	hintQueryCheck       = "Run `clavis connections check` to see whether the source is reachable and the stored credentials still work."
)

// hintQuerySQL states the bound the route and the CLI share, from the one
// constant that defines it.
var hintQuerySQL = fmt.Sprintf("The SQL is 1 to %d bytes; send a shorter statement or split the script.", auth.MaxSQLBytes)

// hintQueryCap states the connection's own cap, which the caller cannot read
// off the request it sent.
func hintQueryCap(rows int) string {
	return fmt.Sprintf("maxRows is 0 for the connection's row cap of %d, or a positive number at or below it.", rows)
}

// hintQueryTimeout names the bound that was exceeded and the one command that
// raises it, so an agent can decide between a narrower statement and a wider
// connection without reading the record.
func hintQueryTimeout(milliseconds int) string {
	return fmt.Sprintf("The statement exceeded the connection's %d ms timeout; narrow it or raise the bound with `clavis connections update --statement-timeout`.",
		milliseconds)
}

// wipe clears a decrypted secret as soon as the call that needed it returned,
// so a plaintext credential does not linger in a live heap.
func wipe(plaintext []byte) {
	for index := range plaintext {
		plaintext[index] = 0
	}
}

// applicationName is what the source records for the request: the platform,
// the connection and the caller, all of them validated slugs. A source
// truncates it to its own identifier length, which costs nothing but detail.
func applicationName(connection, username string) string {
	return "clavis:" + connection + ":" + username
}

// queryFailure maps the provider's typed failures to the codes an agent
// branches on. Only a source rejection carries text, and that text is the
// source's own: it travels in the envelope's source block, never in a log.
func queryFailure(err error, timeoutMS int) error {
	var rejected *provider.SourceError
	switch {
	case errors.As(err, &rejected):
		failure := rejected.Failure
		return &auth.Error{Code: auth.SourceError, Source: &failure}
	case errors.Is(err, provider.ErrTimeout):
		return &auth.Error{Code: auth.SourceTimeout, Hint: hintQueryTimeout(timeoutMS)}
	case errors.Is(err, provider.ErrUnreachable):
		return &auth.Error{Code: auth.SourceUnreachable, Hint: hintQueryCheck}
	case errors.Is(err, provider.ErrAuthRejected):
		return &auth.Error{Code: auth.SourceAuthRejected, Hint: hintQueryCheck}
	case errors.Is(err, provider.ErrUnsupported):
		return &auth.Error{Code: auth.ProviderUnsupported, Hint: hintQueryUnsupported}
	}
	return unavailable()
}

// ExecuteQuery forwards one SQL string to the connection's source under the
// connection's own credentials and bounds. It writes nothing: no advisory key,
// no row lock, no platform row changes, and no platform transaction is open
// while the source is working, because the authorization commits before the
// request leaves. Nothing records that the execution happened.
func (s *LocalAuth) ExecuteQuery(ctx context.Context, previous auth.Session,
	request auth.QueryRequest) (auth.QueryResponse, error) {
	var empty auth.QueryResponse
	// Local validation first: a malformed request never reaches a lookup, let
	// alone a source.
	if !auth.ValidConnectionRef(request.Connection) {
		return empty, invalidArgument(hintConnectionNotFound)
	}
	// Whitespace alone is nothing to execute; a comment-only string is not,
	// and is forwarded like any other.
	if strings.TrimSpace(request.SQL) == "" || len(request.SQL) > auth.MaxSQLBytes {
		return empty, invalidArgument(hintQuerySQL)
	}
	if request.MaxRows < 0 {
		return empty, invalidArgument(hintQueryRows)
	}
	record, err := s.AuthorizeConnection(ctx, previous, request.Connection)
	if err != nil {
		return empty, err
	}
	// The cap the caller may lower is the connection's, which only the record
	// knows, so this argument is checked as soon as it can be.
	maxRows := record.MaxRows
	if request.MaxRows > 0 {
		if request.MaxRows > record.MaxRows {
			return empty, invalidArgument(hintQueryCap(record.MaxRows))
		}
		maxRows = request.MaxRows
	}
	implementation, ok := provider.Lookup(record.Provider)
	if !ok {
		return empty, unavailable()
	}
	// The capability is a type, not a call: nothing is dialled and no
	// credential is opened for a provider that cannot execute.
	executor, executes := implementation.(provider.Executor)
	if !executes {
		return empty, &auth.Error{Code: auth.ProviderUnsupported, Hint: hintQueryUnsupported}
	}
	// The authorization returned the safe projection, which has no field for
	// the envelope. This read takes no lock and holds no transaction.
	row, err := findConnection(ctx, sqlc.New(s.pool), record.ID, false)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.ConnectionNotFound {
			return empty, failure
		}
		return empty, unavailable()
	}
	plaintext, opened := s.open(row.SecretEnvelope, row.ID)
	if !opened {
		return empty, &auth.Error{Code: auth.CredentialsUnavailable, Hint: hintCredentials}
	}
	defer wipe(plaintext)
	timeout := time.Duration(record.StatementTimeoutMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, queryDeadlineFactor*timeout+queryGrace)
	defer cancel()
	started := time.Now()
	result, err := executor.Execute(ctx, record.Target, auth.Secret(plaintext), provider.ExecuteRequest{
		SQL: request.SQL, Timeout: timeout, MaxRows: maxRows, MaxBytes: record.MaxBytes,
		Application: applicationName(record.Name, previous.User.Username),
	})
	duration := time.Since(started).Milliseconds()
	if err != nil {
		return empty, queryFailure(err, record.StatementTimeoutMS)
	}
	results := result.Results
	if results == nil {
		results = []auth.QueryResult{}
	}
	return auth.QueryResponse{Results: results, Truncated: result.Truncated, DurationMS: duration}, nil
}
