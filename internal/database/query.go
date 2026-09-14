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
	maxQueryTimeBytes    = 256
	hintQueryUnsupported = "This connection's provider does not execute queries; postgresql, victoriametrics and victorialogs connections do."
	hintQueryCheck       = "Run `clavis connections check` to see whether the source is reachable and the stored credentials still work."
	// The two failures the platform classified itself carry the next step; a
	// rejection the source wrote speaks for itself. A log answer is unbounded
	// unless the caller bounds it, so the ceiling names the caller's own limit
	// beside the bounds an administrator owns.
	hintQueryCeiling   = "The answer exceeded the platform's reading ceiling of four times the connection's byte cap plus 1 MiB; narrow the range, step or query, pass a limit, lower maxRows, or ask an administrator to raise the cap."
	hintQueryMalformed = "The answer was not the response the source's API documents; confirm the connection's URL is the source's query API and run `clavis connections check`."
	// The halves of the input rule: which inputs exist, which time fields each
	// of them takes, and the three rules the log inputs add. None of them names
	// the connection's provider, because all are decided before any record is
	// read.
	hintQueryInput = "Send exactly one input: sql for a postgresql connection, " +
		"promql, labels, labelValues or series for a victoriametrics connection, " +
		"or logsql, fieldNames, fieldValues, streams, streamFieldNames or streamFieldValues for a victorialogs connection."
	hintQueryTime = "at applies to promql without start, step requires start, neither applies to a log input, " +
		"match applies to the discovery inputs, and start and end apply to promql, a discovery input or logsql, never to sql."
	hintQueryMatch = "match carries the source's own query and is required with fieldNames, fieldValues, streams, " +
		"streamFieldNames and streamFieldValues; logsql carries its own query and takes no match."
	hintQueryLimit = "limit is a non-negative integer the source applies itself, and applies to logsql, fieldValues, " +
		"streams and streamFieldValues only."
	hintQueryLabel = "labelValues names one Prometheus label: a letter or underscore followed by letters, digits or underscores."
	// The mismatch hints name the input the connection's own provider takes.
	hintQueryWantsSQL     = "This connection is postgresql: send sql."
	hintQueryWantsMetrics = "This connection is victoriametrics: send promql, labels, labelValues or series."
	hintQueryWantsLogs    = "This connection is victorialogs: send logsql, fieldNames, fieldValues, streams, streamFieldNames or streamFieldValues."
)

// hintQuerySQL and hintQueryExpression state the bound the route and the CLI
// share, from the one constant that defines it.
var (
	hintQuerySQL        = fmt.Sprintf("The SQL is 1 to %d bytes; send a shorter statement or split the script.", auth.MaxSQLBytes)
	hintQueryExpression = fmt.Sprintf("The expression, query, selector or field name is 1 to %d bytes; send a shorter one.", auth.MaxSQLBytes)
	// The filter is a substring a log endpoint matches against a value, not a
	// query, so its bound is the short one and the rule travels with it.
	hintQueryFilter = fmt.Sprintf("filter is a substring of 1 to %d bytes and applies to fieldNames, fieldValues, "+
		"streamFieldNames and streamFieldValues only.", auth.MaxFilterBytes)
)

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
		return &auth.Error{Code: auth.SourceError, Source: &failure, Hint: sourceHint(failure.ErrorType)}
	case errors.Is(err, provider.ErrTimeout):
		return &auth.Error{Code: auth.SourceTimeout, Hint: hintQueryTimeout(timeoutMS)}
	case errors.Is(err, provider.ErrUnreachable):
		return &auth.Error{Code: auth.SourceUnreachable, Hint: hintQueryCheck}
	case errors.Is(err, provider.ErrAuthRejected):
		return &auth.Error{Code: auth.SourceAuthRejected, Hint: hintQueryCheck}
	case errors.Is(err, provider.ErrUnsupported):
		return &auth.Error{Code: auth.ProviderUnsupported, Hint: hintQueryUnsupported}
	case errors.Is(err, provider.ErrUnsupportedInput):
		// The service refuses a mismatched input before any credential is
		// opened, so this is the backstop for a rule the two sides disagree
		// about rather than something a caller can reach.
		return invalidArgument(hintQueryInput)
	}
	return unavailable()
}

// sourceHint names the next step for the two failures the platform wrote
// itself; the source's own rejection carries its own words and no hint.
func sourceHint(errorType string) string {
	switch errorType {
	case provider.ResponseTooLarge:
		return hintQueryCeiling
	case provider.MalformedResponse:
		return hintQueryMalformed
	}
	return ""
}

// discoveryInput reports whether the request carries one of the three metadata
// inputs, which share the selector and the time bounds but take no step.
func discoveryInput(request auth.QueryRequest) bool {
	return request.Labels || request.LabelValues != "" || request.Series != ""
}

// logDiscoveryInput reports whether the request carries one of the five log
// metadata inputs. Each of them takes the source's own query in Match, which
// is why they are named apart from the log stream.
func logDiscoveryInput(request auth.QueryRequest) bool {
	return request.FieldNames || request.FieldValues != "" || request.Streams ||
		request.StreamFieldNames || request.StreamFieldValues != ""
}

// logInput reports whether the request carries any log input at all. Limit and
// Filter are modifiers rather than inputs: they name no endpoint of their own
// and are only ever sent beside one of these.
func logInput(request auth.QueryRequest) bool {
	return request.LogsQL != "" || logDiscoveryInput(request)
}

// takesLimit and takesFilter name the log endpoints that have a parameter for
// each. The source drops a parameter its endpoint does not declare rather than
// refusing it, so a request that would be silently ignored is refused here.
func takesLimit(request auth.QueryRequest) bool {
	return request.LogsQL != "" || request.FieldValues != "" || request.Streams || request.StreamFieldValues != ""
}

func takesFilter(request auth.QueryRequest) bool {
	return request.FieldNames || request.FieldValues != "" ||
		request.StreamFieldNames || request.StreamFieldValues != ""
}

// validateLogRules applies the three rules the log inputs add: the query a
// discovery endpoint needs, the limit the source applies itself and the filter
// four of the endpoints take. They are decided before any record is read, so
// they hold for every connection, and a limit beside a SQL or PromQL input is
// refused here rather than sent to a source that has no parameter for it.
func validateLogRules(request auth.QueryRequest) error {
	logs, discovery := logInput(request), logDiscoveryInput(request)
	if logs && (request.At != "" || request.Step != "") {
		return invalidArgument(hintQueryTime)
	}
	// Discovery carries the source's query in match; the log stream carries its
	// own and takes no second one.
	if logs && discovery == (request.Match == "") {
		return invalidArgument(hintQueryMatch)
	}
	if request.Limit != nil && (*request.Limit < 0 || !takesLimit(request)) {
		return invalidArgument(hintQueryLimit)
	}
	if request.Filter != "" && (!takesFilter(request) || len(request.Filter) > auth.MaxFilterBytes) {
		return invalidArgument(hintQueryFilter)
	}
	return nil
}

// validateQueryInput applies the input rules that need no record: exactly one
// input, the time fields that input takes, the one validated label name and
// the bound on the submitted text. Every rejection carries the rule as its
// hint and none of them echoes a submitted value.
func validateQueryInput(request auth.QueryRequest) error {
	inputs := 0
	for _, set := range []bool{request.SQL != "", request.PromQL != "", request.Labels,
		request.LabelValues != "", request.Series != "", request.LogsQL != "", request.FieldNames,
		request.FieldValues != "", request.Streams, request.StreamFieldNames, request.StreamFieldValues != ""} {
		if set {
			inputs++
		}
	}
	if inputs != 1 {
		return invalidArgument(hintQueryInput)
	}
	if err := validateLogRules(request); err != nil {
		return err
	}
	expression, discovery := request.PromQL != "", discoveryInput(request)
	logs := logInput(request)
	switch {
	// An instant query is the only input a pinned time belongs to; a step
	// belongs to a range query alone, and a selector to metrics discovery
	// alone. A log input takes neither time pin, and its own match rule was
	// decided above.
	case request.At != "" && (!expression || request.Start != ""):
		return invalidArgument(hintQueryTime)
	case request.Step != "" && (!expression || request.Start == ""):
		return invalidArgument(hintQueryTime)
	case request.Match != "" && !discovery && !logs:
		return invalidArgument(hintQueryTime)
	case request.End != "" && !discovery && !logs && (!expression || request.Start == ""):
		return invalidArgument(hintQueryTime)
	case request.Start != "" && !expression && !discovery && !logs:
		return invalidArgument(hintQueryTime)
	}
	if request.LabelValues != "" && !auth.ValidLabelName(request.LabelValues) {
		return invalidArgument(hintQueryLabel)
	}
	// A time or step string is short in every format the source accepts; the
	// bound keeps a form body from carrying a quarter megabyte of timestamp.
	for _, when := range []string{request.At, request.Start, request.End, request.Step} {
		if len(when) > maxQueryTimeBytes {
			return invalidArgument(hintQueryTime)
		}
	}
	// Whitespace alone is nothing to execute; a comment-only string is not,
	// and is forwarded like any other.
	if request.SQL != "" && (strings.TrimSpace(request.SQL) == "" || len(request.SQL) > auth.MaxSQLBytes) {
		return invalidArgument(hintQuerySQL)
	}
	// A field name is a parameter value, bounded like the queries beside it and
	// never validated by a grammar of its own: only a label name forms a path
	// segment on a source.
	for _, text := range []string{request.PromQL, request.Series, request.Match, request.LogsQL,
		request.FieldValues, request.StreamFieldValues} {
		if text != "" && (strings.TrimSpace(text) == "" || len(text) > auth.MaxSQLBytes) {
			return invalidArgument(hintQueryExpression)
		}
	}
	if request.MaxRows < 0 {
		return invalidArgument(hintQueryRows)
	}
	return nil
}

// providerInput refuses an input the connection's provider does not take. It
// is decided on the authorized record, before the capability assertion and
// before the secret is opened, so a mismatch never reaches a credential.
func providerInput(kind auth.ProviderType, request auth.QueryRequest) error {
	switch kind {
	case auth.ProviderPostgreSQL:
		if request.SQL == "" {
			return invalidArgument(hintQueryWantsSQL)
		}
	case auth.ProviderVictoriaMetrics:
		if request.SQL != "" || logInput(request) {
			return invalidArgument(hintQueryWantsMetrics)
		}
	case auth.ProviderVictoriaLogs:
		if !logInput(request) {
			return invalidArgument(hintQueryWantsLogs)
		}
	}
	return nil
}

// ExecuteQuery forwards one input to the connection's source under the
// connection's own credentials and bounds: a SQL string for a SQL source, an
// expression or one discovery input for a metrics source, or a LogsQL query or
// one log discovery input for a log source, each with the time fields, limit
// and filter it takes. It writes nothing: no advisory key,
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
	if err := validateQueryInput(request); err != nil {
		return empty, err
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
	if err := providerInput(record.Provider, request); err != nil {
		return empty, err
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
		SQL: request.SQL, PromQL: request.PromQL, At: request.At, Start: request.Start, End: request.End,
		Step: request.Step, Labels: request.Labels, LabelValues: request.LabelValues, Series: request.Series,
		Match: request.Match, LogsQL: request.LogsQL, FieldNames: request.FieldNames,
		FieldValues: request.FieldValues, Streams: request.Streams, StreamFieldNames: request.StreamFieldNames,
		StreamFieldValues: request.StreamFieldValues, Limit: request.Limit, Filter: request.Filter,
		Timeout: timeout, MaxRows: maxRows, MaxBytes: record.MaxBytes,
		Application: applicationName(record.Name, previous.User.Username),
	})
	duration := time.Since(started).Milliseconds()
	if err != nil {
		return empty, queryFailure(err, record.StatementTimeoutMS)
	}
	// The shape is the provider's, named by the record rather than inferred
	// from the answer: a caller branches on one field it can trust.
	response := auth.QueryResponse{Provider: record.Provider, Truncated: result.Truncated, DurationMS: duration}
	if record.Provider != auth.ProviderPostgreSQL {
		// Both HTTP sources answer with one named shape. A log source writes no
		// warnings, infos or partial flag of its own, so those stay absent
		// rather than being invented here.
		response.ResultType, response.Result = result.ResultType, result.Result
		response.Warnings, response.Infos, response.IsPartial = result.Warnings, result.Infos, result.IsPartial
		return response, nil
	}
	response.Results = result.Results
	if response.Results == nil {
		response.Results = []auth.QueryResult{}
	}
	return response, nil
}
