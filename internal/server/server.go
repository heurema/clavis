package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/heurema/clavis/internal/config"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/web"
)

type Database interface {
	Ping(context.Context) error
	Close()
}

func Handler(checkTimeout time.Duration, database Database, logger *slog.Logger) http.Handler {
	// Preserve the existing runtime until the initialization service is wired.
	return HandlerWithReadiness(checkTimeout, platform.CheckFunc(func(ctx context.Context) platform.Readiness {
		state := platform.DependencyUnavailable
		if databaseReady(ctx, checkTimeout, database) {
			state = platform.Ready
		}
		return platform.Readiness{State: state}
	}), logger)
}

// HandlerWithReadiness is the injection boundary shared by real initialization
// and isolated fixtures. Public documents never invoke the checker.
func HandlerWithReadiness(checkTimeout time.Duration, checker platform.Checker, logger *slog.Logger) http.Handler {
	check := func(ctx context.Context) platform.Readiness {
		ctx, cancel := context.WithTimeout(ctx, checkTimeout)
		defer cancel()
		return checker.Check(ctx)
	}
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			response := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(response, r)
			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = "unmatched"
			}
			method := "OTHER"
			if r.Method == http.MethodGet {
				method = http.MethodGet
			}
			logger.Info("request", "route", route, "method", method, "status", response.Status(), "duration_ms", time.Since(start).Milliseconds())
		})
	})
	router.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	})
	router.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		result := check(r.Context())
		status := http.StatusServiceUnavailable
		if result.Ready() {
			status = http.StatusOK
		}
		writeJSON(w, status, result.Response())
	})
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if err := web.Render(w, r, http.StatusOK, web.Page()); err != nil {
			logger.Error("web_response_failed", "code", "WEB_RESPONSE_FAILED")
		}
	})
	router.Get("/ui/readiness", func(w http.ResponseWriter, r *http.Request) {
		result := check(r.Context())
		status := http.StatusServiceUnavailable
		if result.Ready() {
			status = http.StatusOK
		}
		w.Header().Set("X-Clavis-Fragment", "readiness")
		if err := web.Render(w, r, status, web.Readiness(result)); err != nil {
			logger.Error("web_response_failed", "code", "WEB_RESPONSE_FAILED")
		}
	})
	router.Get("/assets/*", web.ServeAsset)
	router.Head("/assets/*", web.ServeAsset)
	return router
}

func databaseReady(ctx context.Context, timeout time.Duration, database Database) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return database.Ping(ctx) == nil
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// Serve owns the listener and database. Shutdown has one shared time budget
// for draining requests and releasing the pool, even if a check is blocked.
// Callers must keep returned error details out of operational logs.
func Serve(ctx context.Context, listener net.Listener, cfg config.Config, database Database, logger *slog.Logger) error {
	requests, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	server := &http.Server{
		Handler:           Handler(cfg.DBCheckTimeout, database, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.DBCheckTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return requests },
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	logger.Info("server_started")
	var serveError error
	select {
	case <-ctx.Done():
	case serveError = <-finished:
	}
	logger.Info("server_stopping")
	grace, cancelGrace := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelGrace()
	if err := server.Shutdown(grace); err != nil {
		logger.Warn("shutdown_deadline", "code", "SHUTDOWN_TIMEOUT")
		cancelRequests()
		_ = server.Close()
	}
	closed := make(chan struct{})
	go func() { database.Close(); close(closed) }()
	select {
	case <-closed:
	case <-grace.Done():
		logger.Warn("database_close_deadline", "code", "SHUTDOWN_TIMEOUT")
	}
	logger.Info("server_stopped")
	if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
		return serveError
	}
	return nil
}
