package provider

import (
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// Probe opens one connection and runs SELECT 1. The driver's error text stays
// inside this function: only the outcome leaves it.
func (postgreSQL) Probe(ctx context.Context, target map[string]string, secret auth.Secret) auth.CheckOutcome {
	timeout, ok := probeTimeout(ctx)
	if !ok {
		return auth.CheckUnreachable
	}
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.User(target[keyRole]),
		Host:     net.JoinHostPort(target[keyHost], target[keyPort]),
		Path:     "/" + target[keyDatabase],
		RawQuery: url.Values{keySSLMode: {target[keySSLMode]}}.Encode(),
	}).String()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return auth.CheckUnreachable
	}
	// The password is set on the parsed config, never parsed out of a URL, so
	// no string holding it is ever handed to the driver's parser or logged.
	config.Password = string(secret)
	config.ConnectTimeout = timeout
	config.RuntimeParams["application_name"] = probeApplicationName
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return postgresOutcome(err)
	}
	// Closing uses its own short deadline: the caller's may already be spent,
	// and a terminate message must not extend the probe.
	defer func() {
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = conn.Close(closing)
	}()
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		return postgresOutcome(err)
	}
	return auth.CheckReachable
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
