package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// queryInputHint names every channel an input may arrive through: the three a
// statement, an expression or a query takes, and the eight discovery flags. It
// never repeats the input itself, which is true of every message this command
// produces.
const queryInputHint = "Supply exactly one input: --sql <text>, --sql-stdin, --sql-file <absolute path>, " +
	"--promql <expr>, --promql-stdin, --promql-file <absolute path>, --labels, " +
	"--label-values <name>, --series <selector>, --logsql <query>, --logsql-stdin, " +
	"--logsql-file <absolute path>, --field-names, --field-values <name>, --streams, " +
	"--stream-field-names or --stream-field-values <name>"

// queryTimeHint states which input each time flag belongs to. The source
// parses the strings themselves; only their applicability is decided here.
const queryTimeHint = "--at applies to --promql without --start, --step requires --start, neither applies " +
	"to a log input, --match applies to --labels, --label-values and --series, and --start and --end apply to " +
	"the PromQL, discovery and LogsQL inputs only"

// queryMatchHint states the rule the log discovery inputs add: each of them
// takes the source's own query, and the log stream carries its own.
const queryMatchHint = "--match carries the source's query and is required with --field-names, --field-values, " +
	"--streams, --stream-field-names and --stream-field-values; --logsql carries its own query and takes no --match"

// queryLimitHint states the one parameter the platform never adds: the limit
// is the caller's own and only four of the endpoints take one.
const queryLimitHint = "--limit is a non-negative integer the source applies itself, and applies to --logsql, " +
	"--field-values, --streams and --stream-field-values only"

// queryLabelHint states the one input the platform validates, because it forms
// a path segment on the source.
const queryLabelHint = "--label-values takes one Prometheus label name: a letter or underscore " +
	"followed by letters, digits or underscores"

// sqlBoundHint states the one local bound on a statement, an expression, a
// query or the field name a discovery endpoint takes as a parameter value.
var sqlBoundHint = "The SQL, expression, query or field name must be non-empty, valid UTF-8 and at most " +
	strconv.Itoa(auth.MaxSQLBytes) + " bytes"

// queryFilterHint states the filter's own short bound and the four inputs that
// take it: a filter is a substring the source matches, never a query.
var queryFilterHint = "--filter is a substring of at most " + strconv.Itoa(auth.MaxFilterBytes) +
	" bytes and applies to --field-names, --field-values, --stream-field-names and --stream-field-values only"

// maxRowsHint states what a caller may ask for. The connection's own cap is
// the server's to apply; only a value no connection could honor is refused here.
var maxRowsHint = "--max-rows accepts 1 to the connection's row cap, at most " + strconv.Itoa(auth.MaxMaxRows)

// queryTimeoutUsage explains why execution's whole-request deadline is not the
// five seconds every other command takes.
const queryTimeoutUsage = "Whole-request deadline; the default covers the connection's statement timeout " +
	"on the source and the platform's hung-connection backstop"

var errSQLInput = errors.New("SQL input unavailable or invalid")

// queryCommand builds the one execution command. It is top-level rather than a
// group because it is one verb with one object, exactly like whoami, and it
// shares the server, timeout, output, envelope and hint conventions of every
// group. No flag carries a secret: the SQL is not one, and the credential is
// the stored session.
func queryCommand(makeCommand func(operation, usage string, extra ...urfave.Flag) *urfave.Command) *urfave.Command {
	return makeCommand("query", "Execute SQL, PromQL or LogsQL against a connection you may use",
		&urfave.StringFlag{Name: "connection", Usage: "Target connection UUID or name"},
		&urfave.StringFlag{Name: "sql", Usage: "The statement or script to execute"},
		&urfave.BoolFlag{Name: "sql-stdin", Usage: "Read the bounded SQL from stdin, for example from a heredoc"},
		&urfave.StringFlag{Name: "sql-file", Usage: "Absolute path of a regular file holding the SQL"},
		&urfave.StringFlag{Name: "promql", Usage: "The PromQL expression to evaluate"},
		&urfave.BoolFlag{Name: "promql-stdin", Usage: "Read the bounded PromQL expression from stdin"},
		&urfave.StringFlag{Name: "promql-file", Usage: "Absolute path of a regular file holding the expression"},
		&urfave.BoolFlag{Name: "labels", Usage: "List the source's label names"},
		&urfave.StringFlag{Name: "label-values", Usage: "List the values of one label, such as __name__"},
		&urfave.StringFlag{Name: "series", Usage: "List the label sets matching a selector"},
		&urfave.StringFlag{Name: "at", Usage: "Evaluation time of an instant query, in the source's own format"},
		&urfave.StringFlag{Name: "start", Usage: "Range start, in the source's own format"},
		&urfave.StringFlag{Name: "end", Usage: "Range end, in the source's own format"},
		&urfave.StringFlag{Name: "step", Usage: "Range resolution, in the source's own format"},
		&urfave.StringFlag{Name: "match", Usage: "Selector narrowing a metrics discovery request, or the query a log discovery request runs"},
		&urfave.StringFlag{Name: "logsql", Usage: "The LogsQL query to execute"},
		&urfave.BoolFlag{Name: "logsql-stdin", Usage: "Read the bounded LogsQL query from stdin"},
		&urfave.StringFlag{Name: "logsql-file", Usage: "Absolute path of a regular file holding the query"},
		&urfave.BoolFlag{Name: "field-names", Usage: "List the field names the query's logs carry"},
		&urfave.StringFlag{Name: "field-values", Usage: "List the values of one log field, such as level"},
		&urfave.BoolFlag{Name: "streams", Usage: "List the log streams the query matches"},
		&urfave.BoolFlag{Name: "stream-field-names", Usage: "List the stream field names the query's logs carry"},
		&urfave.StringFlag{Name: "stream-field-values", Usage: "List the values of one stream field"},
		&urfave.IntFlag{Name: "limit", Usage: "The source's own limit, forwarded as typed; never added by the CLI"},
		&urfave.StringFlag{Name: "filter", Usage: "Substring a log discovery endpoint matches against a value"},
		&urfave.IntFlag{Name: "max-rows", Usage: "Keep at most this many rows or samples, at or below the connection's cap"})
}

// validateQueryArguments refuses a malformed reference or bound before any SQL
// is read, any cache is opened and any request is made.
func validateQueryArguments(command *urfave.Command) *Result {
	if !auth.ValidConnectionRef(command.String("connection")) {
		return argumentFailure("Provide a connection UUID or name", connectionRefHint)
	}
	if rows := command.Int("max-rows"); command.IsSet("max-rows") && (rows < 1 || rows > auth.MaxMaxRows) {
		return argumentFailure("Provide a max-rows value within the allowed range", maxRowsHint)
	}
	return nil
}

// textChannels is one text input's three channels. The SQL and the PromQL
// inputs take exactly the same three, so they share this shape and the reading
// below; the discovery inputs are flags and take none.
type textChannels struct {
	inline, stdin bool
	text, file    string
}

func channelsFor(command *urfave.Command, name string) textChannels {
	return textChannels{
		inline: command.IsSet(name), stdin: command.Bool(name + "-stdin"),
		text: command.String(name), file: command.String(name + "-file"),
	}
}

// used counts the channels of one input, so two of them are a rejection rather
// than a silent preference.
func (c textChannels) used() int {
	given := 0
	for _, set := range []bool{c.inline, c.stdin, c.file != ""} {
		if set {
			given++
		}
	}
	return given
}

// readSQL is the query input path. Exactly one input may be given, its time
// flags must belong to it, and the text it carries is bounded before anything
// is sent, so an input the route would refuse is refused locally instead. It
// returns the text of whichever text channel was used and the empty string for
// a discovery input, which carries none. Every rejection happens before any
// cache or network access and none of them echoes the input.
func readSQL(ctx context.Context, command *urfave.Command, streams IO) (string, *Result) {
	sql, promql := channelsFor(command, "sql"), channelsFor(command, "promql")
	logsql := channelsFor(command, "logsql")
	labelValues, series := command.String("label-values"), command.String("series")
	given := sql.used() + promql.used() + logsql.used()
	for _, set := range []bool{command.Bool("labels"), labelValues != "", series != ""} {
		if set {
			given++
		}
	}
	given += logDiscoveryGiven(command)
	if given != 1 {
		return "", argumentFailure("Provide exactly one query input", queryInputHint)
	}
	if failed := validateLogArguments(command, logsql.used() == 1); failed != nil {
		return "", failed
	}
	if failed := validateQueryTimes(command, promql.used() == 1); failed != nil {
		return "", failed
	}
	if labelValues != "" && !auth.ValidLabelName(labelValues) {
		return "", argumentFailure("Provide one Prometheus label name", queryLabelHint)
	}
	// Selectors and field names travel as request members rather than as the
	// text input, but they are bounded by the same rule, and locally, so an
	// oversized one is refused before any request like an oversized expression.
	for _, selector := range []string{series, command.String("match"),
		command.String("field-values"), command.String("stream-field-values")} {
		if selector != "" && (len(selector) > auth.MaxSQLBytes || !utf8.ValidString(selector)) {
			return "", argumentFailure("Provide a selector or field name within the documented bound", sqlBoundHint)
		}
	}
	if sql.used()+promql.used()+logsql.used() == 0 {
		return "", nil
	}
	channels := sql
	switch {
	case promql.used() == 1:
		channels = promql
	case logsql.used() == 1:
		channels = logsql
	}
	return readTextInput(ctx, channels, streams)
}

// logDiscoveryFlags are the five log metadata inputs, each of them a flag
// rather than a text channel and each requiring --match.
var logDiscoveryFlags = []string{"field-names", "field-values", "streams", "stream-field-names", "stream-field-values"}

// logDiscoveryGiven counts the log discovery inputs, so two of them are a
// rejection rather than a silent preference.
func logDiscoveryGiven(command *urfave.Command) int {
	given := 0
	for _, flag := range logDiscoveryFlags {
		if logDiscoverySet(command, flag) {
			given++
		}
	}
	return given
}

// logDiscoverySet reads one of the five, which are booleans except the two
// naming a field.
func logDiscoverySet(command *urfave.Command, flag string) bool {
	switch flag {
	case "field-values", "stream-field-values":
		return command.String(flag) != ""
	default:
		return command.Bool(flag)
	}
}

// validateLogArguments applies the rules the log inputs add: the query a
// discovery endpoint needs, the limit only four endpoints take and the filter
// the four field inputs take. A limit or a filter beside a SQL or PromQL input
// is refused here too, because no such source has a parameter for it.
func validateLogArguments(command *urfave.Command, stream bool) *Result {
	discovery := logDiscoveryGiven(command) == 1
	if (stream || discovery) && discovery == (command.String("match") == "") {
		return argumentFailure("Provide --match with a log discovery input", queryMatchHint)
	}
	limited := stream || command.String("field-values") != "" ||
		command.Bool("streams") || command.String("stream-field-values") != ""
	if command.IsSet("limit") && (command.Int("limit") < 0 || !limited) {
		return argumentFailure("Provide a limit the input takes", queryLimitHint)
	}
	filtered := command.Bool("field-names") || command.String("field-values") != "" ||
		command.Bool("stream-field-names") || command.String("stream-field-values") != ""
	filter := command.String("filter")
	if filter != "" && (!filtered || len(filter) > auth.MaxFilterBytes || !utf8.ValidString(filter)) {
		return argumentFailure("Provide a filter the input takes", queryFilterHint)
	}
	return nil
}

// validateQueryTimes refuses a time flag the chosen input does not take. The
// strings themselves are never parsed: their format is the source's business,
// and only the platform's own rule about which input takes which flag is
// decided here.
func validateQueryTimes(command *urfave.Command, expression bool) *Result {
	at, start, end := command.String("at"), command.String("start"), command.String("end")
	step, match := command.String("step"), command.String("match")
	discovery := command.Bool("labels") || command.String("label-values") != "" || command.String("series") != ""
	// A log input takes start and end and its own match, and never a pinned
	// time or a step; the match rule itself was decided before this.
	logs := channelsFor(command, "logsql").used() == 1 || logDiscoveryGiven(command) == 1
	switch {
	case at != "" && (!expression || start != ""),
		step != "" && (!expression || start == ""),
		match != "" && !discovery && !logs,
		end != "" && !discovery && !logs && (!expression || start == ""),
		start != "" && !expression && !discovery && !logs:
		return argumentFailure("Provide time flags the input takes", queryTimeHint)
	}
	return nil
}

// readTextInput reads one text input from the channel that was used and bounds
// it, so an oversized script or expression is refused locally rather than by
// the route.
func readTextInput(ctx context.Context, channels textChannels, streams IO) (string, *Result) {
	var value []byte
	var err error
	switch {
	case channels.inline:
		value = []byte(channels.text)
	case channels.stdin:
		value, err = sqlFromStdin(ctx, streams.Stdin)
	default:
		value, err = sqlFromFile(channels.file)
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		r := failure("TIMEOUT", "Query input was canceled", nil)
		return "", &r
	}
	if err != nil {
		return "", argumentFailure("Provide a readable input from one channel", queryInputHint)
	}
	if len(value) == 0 || len(value) > auth.MaxSQLBytes || !utf8.Valid(value) {
		return "", argumentFailure("Provide SQL or an expression within the documented bound", sqlBoundHint)
	}
	return string(value), nil
}

// sqlFromStdin reads the whole bounded script. A statement is not a secret and
// may be a quarter of a megabyte, so it is read in one bounded pass rather
// than byte by byte, and one byte beyond the bound separates an exactly full
// script from a truncated oversized one.
func sqlFromStdin(ctx context.Context, input io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type outcome struct {
		body []byte
		err  error
	}
	// The read runs aside so a stalled stdin can still be interrupted by the
	// deadline; the reader is abandoned, not closed, exactly like the
	// per-byte secret channels when their context ends.
	done := make(chan outcome, 1)
	go func() {
		body, err := io.ReadAll(io.LimitReader(input, auth.MaxSQLBytes+1))
		done <- outcome{body, err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			return nil, errSQLInput
		}
		return result.body, ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// sqlFromFile applies the secret-file rules that still make sense for a
// statement: an absolute path, special files opened nonblocking, a regular
// file and a bounded size. The permission rule is deliberately absent, because
// SQL is not a secret and a script is ordinarily world-readable.
func sqlFromFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errSQLInput
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errSQLInput
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errSQLInput
	}
	if info.Size() > auth.MaxSQLBytes+1 {
		return nil, errSQLInput
	}
	body, err := io.ReadAll(io.LimitReader(file, auth.MaxSQLBytes+1))
	if err != nil {
		return nil, errSQLInput
	}
	return body, nil
}

// runQuery sends exactly one request carrying the one input that was given.
// The reference, the bound and the input were validated before the cached
// session was read; the server authorizes the caller, decides whether the
// input fits the connection's provider and the source judges the input itself.
func runQuery(ctx context.Context, command *urfave.Command, api authTransport, token auth.Secret, text string) Result {
	input := auth.QueryRequest{Connection: command.String("connection"),
		At: command.String("at"), Start: command.String("start"), End: command.String("end"),
		Step: command.String("step"), Match: command.String("match")}
	// The body carries the one input that was given and nothing else: an
	// absent field is an absent parameter on the source.
	switch {
	case channelsFor(command, "promql").used() == 1:
		input.PromQL = text
	case channelsFor(command, "logsql").used() == 1:
		input.LogsQL = text
	case command.Bool("labels"):
		input.Labels = true
	case command.String("label-values") != "":
		input.LabelValues = command.String("label-values")
	case command.String("series") != "":
		input.Series = command.String("series")
	case command.Bool("field-names"):
		input.FieldNames = true
	case command.String("field-values") != "":
		input.FieldValues = command.String("field-values")
	case command.Bool("streams"):
		input.Streams = true
	case command.Bool("stream-field-names"):
		input.StreamFieldNames = true
	case command.String("stream-field-values") != "":
		input.StreamFieldValues = command.String("stream-field-values")
	default:
		input.SQL = text
	}
	input.Filter = command.String("filter")
	// The limit is sent only when it was given: an explicit zero is the
	// caller's own "no limit" and an absent one is no parameter at all, and the
	// CLI never invents one.
	if command.IsSet("limit") {
		limit := int64(command.Int("limit"))
		input.Limit = &limit
	}
	if command.IsSet("max-rows") {
		input.MaxRows = command.Int("max-rows")
	}
	var response auth.QueryResponse
	route := apiCall{http.MethodPost, auth.QueryPath, "", http.StatusOK}
	if failed := api.send(ctx, route, token, &input, &response); failed != nil {
		return *failed
	}
	return success(listedResults(response))
}

// listedResults keeps the documented list shape in the rendered envelope even
// when a server omitted an empty one, so a caller never has to branch on null.
// A metrics answer has no results list at all and is rendered as it arrived.
func listedResults(response auth.QueryResponse) auth.QueryResponse {
	if response.Provider != auth.ProviderPostgreSQL {
		return response
	}
	if response.Results == nil {
		response.Results = []auth.QueryResult{}
	}
	for index, result := range response.Results {
		if result.Columns == nil {
			response.Results[index].Columns = []auth.QueryColumn{}
		}
		if result.Rows == nil {
			response.Results[index].Rows = [][]*string{}
		}
	}
	return response
}
