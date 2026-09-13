package provider

import (
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Raw input key and canonical stored keys.
const (
	keyURL = "url"

	keyHost     = "host"
	keyPort     = "port"
	keyDatabase = "database"
	keyRole     = "role"
	keySSLMode  = "sslmode"
)

const (
	defaultPostgresPort    = "5432"
	defaultPostgresSSLMode = "prefer"
	probeApplicationName   = "clavis-probe"

	postgresCloseTimeout = time.Second
	// The SQLSTATE the server reports for a statement it cancelled, which is
	// what statement_timeout produces.
	postgresQueryCanceled = "57014"
	// Rows are appended, not preallocated against the row cap: a cap of
	// 100,000 must not cost an allocation for a statement returning three.
	postgresRowBatch = 32
)

var (
	postgresSchemes = []string{"postgres://", "postgresql://"}
	sslModes        = []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
)

type postgreSQL struct{}

func (postgreSQL) Type() auth.ProviderType { return auth.ProviderPostgreSQL }

// ParseTarget accepts one connection URL and stores its parts separately. The
// URL is never stored or reused for connecting: the probe rebuilds a DSN from
// the canonical parts, so a password can never travel inside a target.
func (postgreSQL) ParseTarget(raw map[string]string) (map[string]string, error) {
	if err := allowedKeys(raw, keyURL); err != nil {
		return nil, err
	}
	value := raw[keyURL]
	if !printableURL(value) {
		return nil, invalid("Setting url is required and must be a URL without spaces or control characters.")
	}
	if !hasPrefix(value, postgresSchemes) {
		return nil, invalid("Setting url must begin with postgres:// or postgresql://.")
	}
	if strings.Contains(value, "#") {
		return nil, invalid("Setting url must not contain a fragment.")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" {
		return nil, invalid("Setting url must be a valid PostgreSQL connection URL.")
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		return nil, invalid("Setting url must carry the role as its user, as postgres://role@host/database.")
	}
	if _, present := parsed.User.Password(); present {
		return nil, invalid("Setting url must not contain a password; supply the secret separately.")
	}
	role := parsed.User.Username()
	if !validIdentifier(role) {
		return nil, invalid("The role in setting url must be 1 to 63 bytes without control characters.")
	}
	host := parsed.Hostname()
	if !validHost(host) {
		return nil, invalid("Setting url must name exactly one host or IP address.")
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPostgresPort
	}
	if !validPort(port) {
		return nil, invalid("The port in setting url must be between 1 and 65535.")
	}
	database := strings.TrimPrefix(parsed.Path, "/")
	if !validIdentifier(database) || strings.Contains(database, "/") {
		return nil, invalid("Setting url must name one database in its path, as postgres://role@host/database.")
	}
	sslmode, err := postgresSSLMode(parsed)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		keyHost:     host,
		keyPort:     port,
		keyDatabase: database,
		keyRole:     role,
		keySSLMode:  sslmode,
	}, nil
}

// postgresSSLMode allows exactly one optional query parameter. Anything else
// would let a submitted URL reach driver settings an administrator never
// reviewed, such as a client certificate path or a startup option.
func postgresSSLMode(parsed *url.URL) (string, error) {
	unknown := invalid("Setting url accepts no query parameter other than sslmode.")
	if parsed.ForceQuery {
		return "", unknown
	}
	if parsed.RawQuery == "" {
		return defaultPostgresSSLMode, nil
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(values) != 1 || len(values[keySSLMode]) != 1 {
		return "", unknown
	}
	sslmode := values[keySSLMode][0]
	if !slices.Contains(sslModes, sslmode) {
		return "", invalid("Query parameter sslmode must be one of " + strings.Join(sslModes, ", ") + ".")
	}
	return sslmode, nil
}

func (postgreSQL) ValidateSecret(_ map[string]string, secret auth.Secret) error {
	if !auth.ValidSecret(secret) {
		return invalid("The secret is the role's password: 1 to 4096 bytes without null bytes or line breaks.")
	}
	return nil
}

// postgresConfig builds the driver configuration from the canonical target
// parts. The URL it parses never carries the password: that is set on the
// parsed config afterwards, so no string holding it is ever handed to the
// driver's parser or logged.
func postgresConfig(target map[string]string, secret auth.Secret, timeout time.Duration) (*pgx.ConnConfig, error) {
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.User(target[keyRole]),
		Host:     net.JoinHostPort(target[keyHost], target[keyPort]),
		Path:     "/" + target[keyDatabase],
		RawQuery: url.Values{keySSLMode: {target[keySSLMode]}}.Encode(),
	}).String()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.Password = string(secret)
	config.ConnectTimeout = timeout
	return config, nil
}

// closePostgres ends a connection on its own short deadline: the caller's may
// already be spent, and a terminate message must not extend the operation.
func closePostgres(ctx context.Context, conn *pgx.Conn) {
	closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), postgresCloseTimeout)
	defer cancel()
	_ = conn.Close(closing)
}

// Probe opens one connection and runs SELECT 1. The driver's error text stays
// inside this function: only the outcome leaves it.
func (postgreSQL) Probe(ctx context.Context, target map[string]string, secret auth.Secret) auth.CheckOutcome {
	timeout, ok := probeTimeout(ctx)
	if !ok {
		return auth.CheckUnreachable
	}
	config, err := postgresConfig(target, secret, timeout)
	if err != nil {
		return auth.CheckUnreachable
	}
	config.RuntimeParams["application_name"] = probeApplicationName
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return postgresOutcome(err)
	}
	defer closePostgres(ctx, conn)
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		return postgresOutcome(err)
	}
	return auth.CheckReachable
}

// Execute runs one SQL string over the simple query protocol. That protocol is
// what makes a multi-statement script possible: PostgreSQL splits the string,
// runs the statements in order under its implicit transaction and returns one
// result for each. Nothing here inspects, rewrites or restricts the string.
func (postgreSQL) Execute(ctx context.Context, target map[string]string, secret auth.Secret, request ExecuteRequest) (ExecuteResult, error) {
	// The same deadline-to-driver-timeout conversion the probe uses: an
	// exhausted budget is an unreachable source rather than a spent dial.
	timeout, ok := probeTimeout(ctx)
	if !ok {
		return ExecuteResult{}, ErrUnreachable
	}
	// Dialling gets the probe's budget at most: a black-holed host must fail
	// within seconds, not within the hung-connection backstop that bounds the
	// whole request.
	config, err := postgresConfig(target, secret, min(timeout, auth.OperationTimeout))
	if err != nil {
		return ExecuteResult{}, ErrUnreachable
	}
	// The source enforces the time bound itself, so an overrunning statement
	// is aborted with its implicit transaction and we never cancel anything.
	config.RuntimeParams["statement_timeout"] = strconv.FormatInt(statementTimeoutMS(request.Timeout), 10)
	config.RuntimeParams["client_encoding"] = "UTF8"
	config.RuntimeParams["application_name"] = applicationName(request.Application)
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return ExecuteResult{}, postgresConnectError(err)
	}
	defer closePostgres(ctx, conn)
	return postgresExecute(ctx, conn, boundedRequest(request))
}

// applicationName keeps the source from seeing an empty name: the platform
// always identifies itself, even when a caller forgot to compose the name.
func applicationName(value string) string {
	if value == "" {
		return "clavis"
	}
	return value
}

// boundedRequest gives missing caps their documented defaults, as the timeout
// gets, so a zero cap can never mean "keep one row".
func boundedRequest(request ExecuteRequest) ExecuteRequest {
	if request.MaxRows <= 0 {
		request.MaxRows = auth.DefaultMaxRows
	}
	if request.MaxBytes <= 0 {
		request.MaxBytes = auth.DefaultMaxBytes
	}
	return request
}

// statementTimeoutMS keeps a missing bound from becoming an unbounded
// statement: PostgreSQL reads 0 as "no timeout", so a caller that passes none
// gets the documented default instead of a statement nothing stops.
func statementTimeoutMS(timeout time.Duration) int64 {
	if timeout < time.Millisecond {
		return auth.DefaultStatementTimeout.Milliseconds()
	}
	return timeout.Milliseconds()
}

// postgresExecute reads the result stream to its end. Results are collected as
// they arrive and rows beyond the bounds are dropped rather than held, so the
// response is bounded without the statements ever being cut short.
func postgresExecute(ctx context.Context, conn *pgx.Conn, request ExecuteRequest) (ExecuteResult, error) {
	keeper := &rowKeeper{maxRows: request.MaxRows, maxBytes: int64(request.MaxBytes)}
	results := make([]auth.QueryResult, 0, 2)
	reader := conn.PgConn().Exec(ctx, request.SQL)
	var failed error
	for reader.NextResult() {
		result := reader.ResultReader()
		// The field descriptions and their backing array are only valid until
		// this reader closes, so the columns are copied out first. A statement
		// without rows has none at all, which is how the two kinds are told
		// apart without guessing from the command tag.
		fields := result.FieldDescriptions()
		columns := postgresColumns(conn.TypeMap(), fields)
		rows, truncated := keeper.collect(result)
		tag, err := result.Close()
		if err != nil {
			// A statement that failed produces no result: its implicit
			// transaction rolled everything before it back.
			failed = err
			break
		}
		results = append(results, postgresQueryResult(tag, columns, rows, truncated, fields != nil))
	}
	if err := reader.Close(); err != nil && failed == nil {
		failed = err
	}
	if failed != nil {
		return ExecuteResult{}, postgresExecuteError(failed, len(results))
	}
	return ExecuteResult{
		Results:    results,
		Truncated:  keeper.dropped,
		Statements: int64(len(results)),
		Rows:       keeper.rows,
		Bytes:      keeper.bytes,
	}, nil
}

// postgresColumns copies the column list out of the reader. An OID the driver
// has no name for is rendered as the OID itself, which is stable and tells the
// caller what to look up; the values are text either way and stay exact.
func postgresColumns(types *pgtype.Map, fields []pgconn.FieldDescription) []auth.QueryColumn {
	columns := make([]auth.QueryColumn, 0, len(fields))
	for _, field := range fields {
		name := strconv.FormatUint(uint64(field.DataTypeOID), 10)
		if known, ok := types.TypeForOID(field.DataTypeOID); ok {
			name = known.Name
		}
		columns = append(columns, auth.QueryColumn{Name: field.Name, Type: name})
	}
	return columns
}

// postgresQueryResult assembles one result. rowCount is the kept row count for
// a row-producing statement, so it always describes the rows in the response
// rather than the rows the source scanned, and the source's own affected count
// for a statement without rows.
func postgresQueryResult(tag pgconn.CommandTag, columns []auth.QueryColumn, rows [][]*string, truncated, producedRows bool) auth.QueryResult {
	count := tag.RowsAffected()
	if producedRows {
		count = int64(len(rows))
	}
	return auth.QueryResult{
		Command:   commandWord(tag.String()),
		Columns:   columns,
		Rows:      rows,
		RowCount:  count,
		Truncated: truncated,
	}
}

// commandWord is the command tag's first word. The rest of the tag is the
// affected count, which rowCount already reports.
func commandWord(tag string) string {
	word, _, _ := strings.Cut(tag, " ")
	return word
}

// rowSource is the part of the driver's result reader the drain needs, so the
// bounds and the byte accounting can be exercised without a database.
type rowSource interface {
	NextRow() bool
	Values() [][]byte
}

// rowKeeper applies the row and byte caps across the whole response. Every row
// of every result is read to the end whatever the caps say: what the database
// did must never depend on what the caller is shown, so a cut response is
// never a cancelled statement.
type rowKeeper struct {
	maxRows  int
	maxBytes int64
	rows     int64
	bytes    int64
	started  bool
	dropped  bool
}

// collect reads one result to its end and returns the rows it kept and whether
// this result lost any.
func (k *rowKeeper) collect(source rowSource) ([][]*string, bool) {
	rows := make([][]*string, 0, postgresRowBatch)
	truncated := false
	for source.NextRow() {
		values := source.Values()
		size := int64(0)
		for _, value := range values {
			size += int64(len(value))
		}
		if !k.keep(size) {
			truncated, k.dropped = true, true
			continue
		}
		// The values point into the reader's buffer and are overwritten by the
		// next row, so every kept value is copied. A nil value is SQL NULL and
		// an empty one is an empty string: the two stay apart.
		row := make([]*string, len(values))
		for index, value := range values {
			if value == nil {
				continue
			}
			text := string(value)
			row[index] = &text
		}
		rows = append(rows, row)
	}
	return rows, truncated
}

// keep decides one row against the caps. The first row of the first
// row-producing result is always kept, so a caller sees the shape of what it
// asked for even when that one row is larger than the byte cap.
func (k *rowKeeper) keep(size int64) bool {
	if k.started && (k.rows >= int64(k.maxRows) || k.bytes > k.maxBytes) {
		return false
	}
	k.started = true
	k.rows++
	k.bytes += size
	return true
}

// postgresConnectError maps a failed connect. Only SQLSTATE class 28 means the
// source refused the credentials; everything else, including an unknown
// database, a TLS failure and a spent deadline, is indistinguishable from an
// unreachable source, exactly as the probe treats it.
func postgresConnectError(err error) error {
	if postgresOutcome(err) == auth.CheckAuthRejected {
		return ErrAuthRejected
	}
	return ErrUnreachable
}

// postgresExecuteError maps a failure reported once the statements are
// running. The statement index is the number of results that completed before
// the failing one, which is where the caller finds it in the string it sent.
func postgresExecuteError(err error, completed int) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == postgresQueryCanceled {
			return ErrTimeout
		}
		return &SourceError{Failure: auth.SourceFailure{
			SQLState:  pgErr.Code,
			Message:   pgErr.Message,
			Detail:    pgErr.Detail,
			Hint:      pgErr.Hint,
			Position:  int(pgErr.Position),
			Statement: completed,
		}}
	}
	// The request deadline is the backstop for a source that stops answering;
	// reaching it is the same outcome as the source's own statement timeout.
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrUnreachable
}

// postgresOutcome maps a driver failure to a safe category. SQLSTATE class 28
// is the only one the server uses for a refused authentication; everything
// else, including an unknown database, a TLS failure and a spent deadline, is
// indistinguishable from an unreachable source for our purposes.
func postgresOutcome(err error) auth.CheckOutcome {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "28") {
		return auth.CheckAuthRejected
	}
	return auth.CheckUnreachable
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
