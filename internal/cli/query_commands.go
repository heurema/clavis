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

// sqlInputHint names the three channels a statement may arrive through. It
// never repeats the statement itself, which is true of every message this
// command produces.
const sqlInputHint = "Supply the SQL through exactly one of: --sql <text>, --sql-stdin, " +
	"or --sql-file <absolute path to a regular file>"

// sqlBoundHint states the one local bound on a statement.
var sqlBoundHint = "The SQL must be non-empty, valid UTF-8 and at most " + strconv.Itoa(auth.MaxSQLBytes) + " bytes"

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
	return makeCommand("query", "Execute SQL against a connection you may use",
		&urfave.StringFlag{Name: "connection", Usage: "Target connection UUID or name"},
		&urfave.StringFlag{Name: "sql", Usage: "The statement or script to execute"},
		&urfave.BoolFlag{Name: "sql-stdin", Usage: "Read the bounded SQL from stdin, for example from a heredoc"},
		&urfave.StringFlag{Name: "sql-file", Usage: "Absolute path of a regular file holding the SQL"},
		&urfave.IntFlag{Name: "max-rows", Usage: "Keep at most this many rows, at or below the connection's cap"})
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

// readSQL is the statement input path. Exactly one channel may be used, and
// the statement is bounded before anything is sent, so an oversized script is
// refused locally rather than by the route. Every rejection happens before any
// cache or network access and none of them echoes the statement.
func readSQL(ctx context.Context, command *urfave.Command, streams IO) (string, *Result) {
	inline, stdin, file := command.IsSet("sql"), command.Bool("sql-stdin"), command.String("sql-file")
	given := 0
	for _, used := range []bool{inline, stdin, file != ""} {
		if used {
			given++
		}
	}
	if given != 1 {
		return "", argumentFailure("Provide exactly one SQL input", sqlInputHint)
	}
	var value []byte
	var err error
	switch {
	case inline:
		value = []byte(command.String("sql"))
	case stdin:
		value, err = sqlFromStdin(ctx, streams.Stdin)
	default:
		value, err = sqlFromFile(file)
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		r := failure("TIMEOUT", "SQL input was canceled", nil)
		return "", &r
	}
	if err != nil {
		return "", argumentFailure("Provide readable SQL from one input", sqlInputHint)
	}
	if len(value) == 0 || len(value) > auth.MaxSQLBytes || !utf8.Valid(value) {
		return "", argumentFailure("Provide SQL within the documented bound", sqlBoundHint)
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

// runQuery sends exactly one request. The reference, the bound and the
// statement were validated before the cached session was read; the server
// authorizes the caller and the source judges the SQL.
func runQuery(ctx context.Context, command *urfave.Command, api authTransport, token auth.Secret, sql string) Result {
	input := auth.QueryRequest{Connection: command.String("connection"), SQL: sql}
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
func listedResults(response auth.QueryResponse) auth.QueryResponse {
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
