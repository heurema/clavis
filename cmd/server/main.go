package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v11"
	"github.com/heurema/clavis/internal/config"
	"github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/secrets"
	"github.com/heurema/clavis/internal/server"
)

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.Load(env.ToMap(os.Environ()))
	if err != nil {
		var problem *config.Error
		if errors.As(err, &problem) {
			logger.Error("configuration_invalid", "field", problem.Field, "code", problem.Code)
		} else {
			logger.Error("configuration_invalid", "code", "INVALID_CONFIG")
		}
		return 1
	}
	// The key is read once, before any listener or database connection. Its
	// path and contents never reach the log; only the category does.
	keys, err := secrets.LoadKeyFile(cfg.EncryptionKeyFile)
	if err != nil {
		code := "UNREADABLE"
		var failure *secrets.FileError
		if errors.As(err, &failure) {
			code = failure.Code
		}
		logger.Error("configuration_invalid", "field", "CLAVIS_ENCRYPTION_KEY_FILE", "code", code)
		return 1
	}
	cfg.Keys = keys
	logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.Level()}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database_config_invalid", "code", "INVALID_DATABASE_URL")
		return 1
	}
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		pool.Close()
		logger.Error("listen_failed", "code", "LISTEN_FAILED")
		return 1
	}
	if err := server.Serve(ctx, listener, cfg, pool, logger); err != nil {
		logger.Error("server_failed", "code", "HTTP_SERVE_FAILED")
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
