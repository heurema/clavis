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
// statement or an expression takes, and the three discovery flags. It never
// repeats the input itself, which is true of every message this command
// produces.
const queryInputHint = "Supply exactly one input: --sql <text>, --sql-stdin, --sql-file <absolute path>, " +
	"--promql <expr>, --promql-stdin, --promql-file <absolute path>, --labels, " +
	"--label-values <name> or --series <selector>"

// queryTimeHint states which input each time flag belongs to. The source
// parses the strings themselves; only their applicability is decided here.
const queryTimeHint = "--at applies to --promql without --start, --step requires --start, " +
	"--match applies to --labels, --label-values and --series, and --start and --end apply to " +
	"the PromQL and discovery inputs only"

// queryLabelHint states the one input the platform validates, because it forms
// a path segment on the source.
const queryLabelHint = "--label-values takes one Prometheus label name: a letter or underscore " +
	"followed by letters, digits or underscores"

// sqlBoundHint states the one local bound on a statement or an expression.
var sqlBoundHint = "The SQL or expression must be non-empty, valid UTF-8 and at most " +
	strconv.Itoa(auth.MaxSQLBytes) + " bytes"

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
	return makeCommand("query", "Execute SQL or PromQL against a connection you may use",
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
		&urfave.StringFlag{Name: "match", Usage: "Selector narrowing a discovery request"},
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
	labelValues, series := command.String("label-values"), command.String("series")
	given := sql.used() + promql.used()
	for _, set := range []bool{command.Bool("labels"), labelValues != "", series != ""} {
		if set {
			given++
		}
	}
	if given != 1 {
		return "", argumentFailure("Provide exactly one query input", queryInputHint)
	}
	if failed := validateQueryTimes(command, promql.used() == 1); failed != nil {
		return "", failed
	}
	if labelValues != "" && !auth.ValidLabelName(labelValues) {
		return "", argumentFailure("Provide one Prometheus label name", queryLabelHint)
	}
	// Selectors travel as request members rather than as the text input, but
	// they are bounded by the same rule, and locally, so an oversized one is
	// refused before any request like an oversized expression.
	for _, selector := range []string{series, command.String("match")} {
		if selector != "" && (len(selector) > auth.MaxSQLBytes || !utf8.ValidString(selector)) {
			return "", argumentFailure("Provide a selector within the documented bound", sqlBoundHint)
		}
	}
	if sql.used()+promql.used() == 0 {
		return "", nil
	}
	channels := sql
	if promql.used() == 1 {
		channels = promql
	}
	return readTextInput(ctx, channels, streams)
}

// validateQueryTimes refuses a time flag the chosen input does not take. The
// strings themselves are never parsed: their format is the source's business,
// and only the platform's own rule about which input takes which flag is
// decided here.
func validateQueryTimes(command *urfave.Command, expression bool) *Result {
	at, start, end := command.String("at"), command.String("start"), command.String("end")
	step, match := command.String("step"), command.String("match")
	discovery := command.Bool("labels") || command.String("label-values") != "" || command.String("series") != ""
	switch {
	case at != "" && (!expression || start != ""),
		step != "" && (!expression || start == ""),
		match != "" && !discovery,
		end != "" && !discovery && (!expression || start == ""),
		start != "" && !expression && !discovery:
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
	case command.Bool("labels"):
		input.Labels = true
	case command.String("label-values") != "":
		input.LabelValues = command.String("label-values")
	case command.String("series") != "":
		input.Series = command.String("series")
	default:
		input.SQL = text
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
