package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	HTTPAddr              string        `env:"CLAVIS_HTTP_ADDR" envDefault:"127.0.0.1:8080"`
	DatabaseURL           string        `env:"CLAVIS_DATABASE_URL"`
	DBCheckTimeout        time.Duration `env:"CLAVIS_DB_CHECK_TIMEOUT" envDefault:"2s"`
	ShutdownTimeout       time.Duration `env:"CLAVIS_SHUTDOWN_TIMEOUT" envDefault:"10s"`
	LogLevel              string        `env:"CLAVIS_LOG_LEVEL" envDefault:"info"`
	BootstrapUsername     string        `env:"CLAVIS_BOOTSTRAP_USERNAME"`
	BootstrapPasswordFile string        `env:"CLAVIS_BOOTSTRAP_PASSWORD_FILE"`
	PublicURL             string        `env:"CLAVIS_PUBLIC_URL"`
	SessionTTL            time.Duration `env:"CLAVIS_SESSION_TTL" envDefault:"8h"`
}

// Error contains only application-owned field names and categories, never input.
type Error struct{ Field, Code string }

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Code) }

func Load(environment map[string]string) (Config, error) {
	var cfg Config
	if environment["CLAVIS_DATABASE_URL"] == "" {
		return cfg, &Error{"CLAVIS_DATABASE_URL", "REQUIRED"}
	}
	if err := env.ParseWithOptions(&cfg, env.Options{Environment: environment}); err != nil {
		var parse env.ParseError
		if errors.As(err, &parse) {
			switch parse.Name {
			case "DBCheckTimeout":
				return Config{}, &Error{"CLAVIS_DB_CHECK_TIMEOUT", "INVALID_DURATION"}
			case "ShutdownTimeout":
				return Config{}, &Error{"CLAVIS_SHUTDOWN_TIMEOUT", "INVALID_DURATION"}
			case "SessionTTL":
				return Config{}, &Error{"CLAVIS_SESSION_TTL", "INVALID_DURATION"}
			}
		}
		return Config{}, &Error{"environment", "INVALID_CONFIG"}
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	host, port, err := net.SplitHostPort(c.HTTPAddr)
	if err != nil || host == "" {
		return &Error{"CLAVIS_HTTP_ADDR", "INVALID_ADDRESS"}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return &Error{"CLAVIS_HTTP_ADDR", "INVALID_PORT"}
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" {
		return &Error{"CLAVIS_DATABASE_URL", "INVALID_DATABASE_URL"}
	}
	if _, err := pgxpool.ParseConfig(c.DatabaseURL); err != nil {
		return &Error{"CLAVIS_DATABASE_URL", "INVALID_DATABASE_URL"}
	}
	if c.DBCheckTimeout <= 0 {
		return &Error{"CLAVIS_DB_CHECK_TIMEOUT", "MUST_BE_POSITIVE"}
	}
	if c.ShutdownTimeout <= 0 {
		return &Error{"CLAVIS_SHUTDOWN_TIMEOUT", "MUST_BE_POSITIVE"}
	}
	if c.SessionTTL < auth.MinSessionTTL || c.SessionTTL > auth.MaxSessionTTL {
		return &Error{"CLAVIS_SESSION_TTL", "INVALID_DURATION"}
	}
	if _, err := c.ResolvePublicOrigin(c.HTTPAddr); err != nil {
		return err
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return &Error{"CLAVIS_LOG_LEVEL", "INVALID_LEVEL"}
	}
	return nil
}

// ResolvePublicOrigin is called again with listener.Addr before serving so a
// port-zero loopback listener gets its actual origin. Host/forwarded headers
// never participate in this decision.
func (c Config) ResolvePublicOrigin(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	loopback := err == nil && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if c.PublicURL == "" {
		if !loopback {
			return "", &Error{"CLAVIS_PUBLIC_URL", "REQUIRED"}
		}
		return CanonicalOrigin("http://" + address)
	}
	origin, err := CanonicalOrigin(c.PublicURL)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(origin, "http:") && !loopback {
		return "", &Error{"CLAVIS_PUBLIC_URL", "HTTPS_REQUIRED"}
	}
	return origin, nil
}

func CanonicalOrigin(value string) (string, error) {
	failure := &Error{"CLAVIS_PUBLIC_URL", "INVALID_ORIGIN"}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil ||
		u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(value, "\\?#") {
		return "", failure
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "%") {
		return "", failure
	}
	ip := net.ParseIP(host)
	if u.Scheme == "http" && (ip == nil || !ip.IsLoopback()) {
		return "", failure
	}
	if ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return "", failure
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}

func (c Config) Level() slog.Level {
	switch c.LogLevel {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
