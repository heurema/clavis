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
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
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
	// A port-zero bind address is valid here; only the actual listener can
	// supply a derived public origin after binding.
	if _, err := c.configuredPublicOrigin(host); err != nil {
		return err
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return &Error{"CLAVIS_LOG_LEVEL", "INVALID_LEVEL"}
	}
	return nil
}

// ResolvePublicOrigin uses the actual listener.Addr before serving so a
// port-zero loopback bind gets its assigned port. Host/forwarded headers never
// participate in this decision.
func (c Config) ResolvePublicOrigin(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", &Error{"CLAVIS_PUBLIC_URL", "INVALID_ORIGIN"}
	}
	origin, err := c.configuredPublicOrigin(host)
	if err != nil || origin != "" {
		return origin, err
	}
	// Listener addresses may use mapped IPv4 notation. Resolve those to the
	// ordinary IPv4 form reported by a bound TCP listener.
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return CanonicalOrigin("http://" + net.JoinHostPort(host, port))
}

// An empty origin means that a loopback listener may derive it after binding.
func (c Config) configuredPublicOrigin(host string) (string, error) {
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if c.PublicURL == "" {
		if !loopback {
			return "", &Error{"CLAVIS_PUBLIC_URL", "REQUIRED"}
		}
		return "", nil
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
	origin, err := auth.CanonicalOrigin(value)
	if err != nil {
		return "", &Error{"CLAVIS_PUBLIC_URL", "INVALID_ORIGIN"}
	}
	return origin, nil
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
