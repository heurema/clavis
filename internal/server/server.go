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
	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/buildinfo"
	"github.com/heurema/clavis/internal/config"
	store "github.com/heurema/clavis/internal/database"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/web"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Database interface {
	Close()
}

func Handler(checkTimeout time.Duration, database Database, logger *slog.Logger) http.Handler {
	if checker, ok := database.(platform.Checker); ok {
		return HandlerWithReadiness(checkTimeout, checker, logger)
	}
	return HandlerWithReadiness(checkTimeout, platform.CheckFunc(func(context.Context) platform.Readiness {
		return platform.Readiness{State: platform.DependencyUnavailable}
	}), logger)
}

// HandlerWithReadiness is the injection boundary shared by real initialization
// and isolated fixtures. Public documents never invoke the checker.
func HandlerWithReadiness(checkTimeout time.Duration, checker platform.Checker, logger *slog.Logger) http.Handler {
	adapter, _ := newAuthHTTP("http://127.0.0.1", nil, AuthViews{})
	return handler(checkTimeout, checker, logger, adapter)
}

// HandlerWithAuth is the explicit runtime/test composition boundary.
func HandlerWithAuth(checkTimeout time.Duration, checker platform.Checker, service auth.Service, admin auth.Administration, connections auth.Connections, grants auth.Grants, groups auth.Groups, members MemberConnections, executor auth.QueryExecutor, origin string, views AuthViews, logger *slog.Logger) (http.Handler, error) {
	if service == nil || admin == nil || connections == nil || grants == nil || groups == nil || members == nil || executor == nil || checker == nil {
		return nil, &auth.Error{Code: auth.InvalidArgument}
	}
	adapter, err := newAuthHTTP(origin, service, views)
	if err != nil {
		return nil, err
	}
	adapter.admin = admin
	adapter.connections = connections
	adapter.grants = grants
	adapter.groups = groups
	adapter.members = members
	adapter.executor = executor
	return handler(checkTimeout, checker, logger, adapter), nil
}

func handler(checkTimeout time.Duration, checker platform.Checker, logger *slog.Logger, adapter *authHTTP) http.Handler {
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
	// A fresh map per request: a shared one would be writable by any handler.
	live := func() map[string]string { return map[string]string{"status": "alive"} }
	readyStatus := func(result platform.Readiness) int {
		if result.Ready() {
			return http.StatusOK
		}
		return http.StatusServiceUnavailable
	}
	router.Get("/livez", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, live())
	})
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		result := check(r.Context())
		writeJSON(w, readyStatus(result), result.Response())
	})
	// The aggregate serves a person, an uptime monitor or an agent: the same
	// readiness check under the same timeout, both bodies nested so a reader
	// sees which half failed, and the build version. Commit and date stay in
	// the startup log entry, where an operator reads them once.
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		result := check(r.Context())
		status := "unhealthy"
		if result.Ready() {
			status = "ok"
		}
		writeJSON(w, readyStatus(result), map[string]any{
			"status":  status,
			"version": buildinfo.Version,
			"checks":  map[string]any{"live": live(), "ready": result.Response()},
		})
	})
	// The origin has no document of its own: the administration shell owns the
	// interface and sends a visitor without a session on to sign-in. The
	// redirect is public, so it never reads the database.
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	})
	router.Get("/assets/*", web.ServeAsset)
	router.Head("/assets/*", web.ServeAsset)
	adapter.mount(router)
	return router
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
	origin, err := cfg.ResolvePublicOrigin(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		database.Close()
		return err
	}
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	workerDone := make(chan struct{})
	var httpHandler http.Handler
	if pool, ok := database.(*pgxpool.Pool); ok {
		initializer := store.NewInitializer(pool, cfg.BootstrapUsername, cfg.BootstrapPasswordFile)
		local, err := store.NewLocalAuth(pool, initializer, cfg.SessionTTL)
		if err != nil {
			_ = listener.Close()
			database.Close()
			return err
		}
		// The keyring is loaded before the listener exists; connection
		// operations fail closed while it is absent.
		service := local.WithKeyring(cfg.Keys)
		// The one store value satisfies every service contract.
		httpHandler, err = HandlerWithAuth(cfg.DBCheckTimeout, initializer, service, service, service, service, service, service, service, origin, AuthViews{}, logger)
		if err != nil {
			_ = listener.Close()
			database.Close()
			return err
		}
		go func() { defer close(workerDone); initializer.Run(workerCtx) }()
	} else {
		httpHandler = Handler(cfg.DBCheckTimeout, database, logger)
		close(workerDone)
	}
	server := &http.Server{
		Handler:           httpHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      max(cfg.DBCheckTimeout, auth.OperationTimeout) + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return requests },
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	build := buildinfo.Current()
	logger.Info("server_started", "version", build.Version, "commit", build.Commit, "date", build.Date)
	var serveError error
	select {
	case <-ctx.Done():
	case serveError = <-finished:
	}
	logger.Info("server_stopping")
	grace, cancelGrace := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelGrace()
	cancelWorker()
	if err := server.Shutdown(grace); err != nil {
		logger.Warn("shutdown_deadline", "code", "SHUTDOWN_TIMEOUT")
		cancelRequests()
		_ = server.Close()
	}
	select {
	case <-workerDone:
	case <-grace.Done():
		logger.Warn("initialization_close_deadline", "code", "SHUTDOWN_TIMEOUT")
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
