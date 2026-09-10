package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	HTTPAddr        string        `env:"CLAVIS_HTTP_ADDR" envDefault:"127.0.0.1:8080"`
	DatabaseURL     string        `env:"CLAVIS_DATABASE_URL"`
	DBCheckTimeout  time.Duration `env:"CLAVIS_DB_CHECK_TIMEOUT" envDefault:"2s"`
	ShutdownTimeout time.Duration `env:"CLAVIS_SHUTDOWN_TIMEOUT" envDefault:"10s"`
	LogLevel        string        `env:"CLAVIS_LOG_LEVEL" envDefault:"info"`
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
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return &Error{"CLAVIS_LOG_LEVEL", "INVALID_LEVEL"}
	}
	return nil
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
