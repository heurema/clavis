package server

import (
	"net/http"
	"strconv"

	"github.com/heurema/clavis/internal/auth"
)

// queryBodyAllowance is what the request body may add on top of the SQL
// itself: the JSON framing, the connection reference and maxRows. The CLI
// bounds its own request with the same sum, so a body one side refuses is a
// body the other never builds.
const queryBodyAllowance = 4096

// The hints below are the adapter's own. A request that fails these checks
// never reaches the service, so the guidance has to be given here; none of
// them echoes a submitted value, and none of them repeats the SQL.
var (
	hintQueryBody       = "Send a JSON object with connection, sql and an optional positive maxRows"
	hintQueryConnection = "Address the connection by its UUID or its name"
	hintQuerySQL        = "sql is required, non-empty and at most " + strconv.Itoa(auth.MaxSQLBytes) + " bytes"
	hintQueryMaxRows    = "maxRows is optional and must be a positive integer at or below the connection's row cap"
)

// The executor owns authorization, the credential and the source call; a
// composition without one must reject the route instead of invoking anything.
func (a *authHTTP) requireExecutor() error {
	if a.executor == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

// queryRequest decodes and locally validates the one execution body. The SQL
// is bounded but never inspected: the platform forwards it unchanged, so the
// only judgements here are shape, size and the connection reference.
func queryRequest(r *http.Request, request *auth.QueryRequest) error {
	if _, err := query(r); err != nil {
		return err
	}
	var maxRows bool
	if err := decodeFields(r, auth.MaxSQLBytes+queryBodyAllowance, map[string]jsonValue{
		"connection": jsonString(func(value string) { request.Connection = value }),
		"sql":        jsonString(func(value string) { request.SQL = value }),
		"maxRows":    jsonInt(func(value int) { request.MaxRows, maxRows = value, true }),
	}); err != nil {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryBody}
	}
	if !auth.ValidConnectionRef(request.Connection) {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryConnection}
	}
	if request.SQL == "" || len(request.SQL) > auth.MaxSQLBytes {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQuerySQL}
	}
	// The connection's own cap is the service's to apply; only a value that can
	// never lower anything is refused here.
	if maxRows && request.MaxRows < 1 {
		return &auth.Error{Code: auth.InvalidArgument, Hint: hintQueryMaxRows}
	}
	return nil
}

// executeQueryJSON is the one execution route. It follows the shared shape of
// the grant and connection routes: bounded body first, then a bearer-only
// session, then the service call, with every failure rendered through the one
// envelope, which carries the source's own rejection as error.source.
//
// The results are encoded and served as they are. The drain keeps the row that
// crosses the byte cap and always keeps the first row, and JSON escaping grows
// values, so a legitimate response can exceed the connection's byte cap plus
// the envelope allowance; refusing it here would turn a correct execution into
// a fault. The CLI reads the body under a bound with the escaping headroom.
func (a *authHTTP) executeQueryJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.QueryRequest
	err := queryRequest(r, &request)
	var session auth.Session
	if err == nil {
		session, err = a.cliSession(r)
	}
	if err == nil {
		err = a.requireExecutor()
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	response, err := a.executor.ExecuteQuery(r.Context(), session, request)
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
