package database

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	randv2 "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
)

// Initializer is also the read-only installation checker. Advisory state only
// describes an absent marker; it can never override fresh database evidence.
type Initializer struct {
	pool         *pgxpool.Pool
	username     string
	passwordFile string
	state        atomic.Value
}

func NewInitializer(pool *pgxpool.Pool, username, passwordFile string) *Initializer {
	i := &Initializer{pool: pool, username: username, passwordFile: passwordFile}
	i.state.Store(platform.Initializing)
	return i
}

func (i *Initializer) Check(ctx context.Context) platform.Readiness {
	state := i.check(ctx)
	return platform.Readiness{State: state}
}

func (i *Initializer) check(ctx context.Context) platform.State {
	tx, err := i.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return platform.DependencyUnavailable
	}
	defer rollback(ctx, tx)
	n, err := schemaVersions(ctx, tx, embeddedMigrations())
	if err != nil {
		if schemaFailure(err) {
			return platform.SchemaError
		}
		return platform.DependencyUnavailable
	}
	if n != len(embeddedMigrations()) {
		if i.state.Load() == platform.SchemaError {
			return platform.SchemaError
		}
		return platform.Initializing
	}
	// Referencing all required columns detects incompatible/dropped schema even
	// if its ledger has not changed. These are reads, never repair operations.
	queries := sqlc.New(tx)
	for _, check := range []func(context.Context) error{
		queries.CheckUsersColumns,
		queries.CheckSessionsColumns,
		queries.CheckLoginLimitsColumns,
		queries.CheckConnectionsColumns,
		queries.CheckGrantsColumns,
	} {
		if err := check(ctx); err != nil {
			if schemaFailure(err) {
				return platform.SchemaError
			}
			return platform.DependencyUnavailable
		}
	}
	initialized, err := queries.InstallationInitialized(ctx)
	if err != nil {
		if schemaFailure(err) {
			return platform.SchemaError
		}
		return platform.DependencyUnavailable
	}
	if ctx.Err() != nil {
		return platform.DependencyUnavailable
	}
	if initialized {
		return platform.Ready
	}
	state := i.state.Load().(platform.State)
	switch state {
	case platform.SetupRequired, platform.BootstrapFailed, platform.SchemaError:
		return state
	default:
		return platform.Initializing
	}
}

// ReadBootstrapPassword follows projected-volume symlinks but opens special
// files nonblocking and checks the opened target, not a racy pre-open stat.
// It returns only an application-owned error; paths never leave this boundary.
func ReadBootstrapPassword(path string) (auth.Secret, error) {
	failure := func() (auth.Secret, error) { return "", &auth.Error{Code: platform.CodeBootstrapFailed} }
	if !filepath.IsAbs(path) {
		return failure()
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return failure()
	}
	file := os.NewFile(uintptr(fd), "bootstrap-secret")
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1026 {
		return failure()
	}
	data, err := io.ReadAll(io.LimitReader(file, 1027))
	if err != nil || len(data) > 1026 {
		return failure()
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) != len(data) {
		value = strings.TrimSuffix(value, "\r")
	}
	password := auth.Secret(value)
	if !auth.ValidPassword(password) {
		return failure()
	}
	return password, nil
}

func bootstrapID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (i *Initializer) bootstrap(ctx context.Context) platform.State {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return platform.DependencyUnavailable
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	if err = queries.LockTransaction(ctx, MigrationLock); err != nil {
		return platform.DependencyUnavailable
	}
	n, err := schemaVersions(ctx, tx, embeddedMigrations())
	if err != nil {
		if schemaFailure(err) {
			return platform.SchemaError
		}
		return platform.DependencyUnavailable
	}
	if n != len(embeddedMigrations()) {
		return platform.SchemaError
	}
	state, err := queries.BootstrapState(ctx)
	if err != nil {
		if schemaFailure(err) {
			return platform.SchemaError
		}
		return platform.DependencyUnavailable
	}
	// This must precede every bootstrap input operation, including validation.
	if state.Initialized {
		return platform.Ready
	}
	if state.HasUsers {
		return bootstrapValidationFailure()
	}
	if i.username == "" || i.passwordFile == "" {
		return platform.SetupRequired
	}
	if !auth.ValidUsername(i.username) {
		return bootstrapValidationFailure()
	}
	password, err := ReadBootstrapPassword(i.passwordFile)
	if err != nil {
		return bootstrapValidationFailure()
	}
	hash, err := auth.HashPassword(ctx, password)
	if err != nil {
		return platform.DependencyUnavailable
	}
	userID, err := bootstrapID()
	if err != nil {
		return platform.DependencyUnavailable
	}
	if err = queries.CreateInitialAdministrator(ctx, sqlc.CreateInitialAdministratorParams{
		ID: userID, Username: i.username, PasswordHash: hash,
	}); err != nil {
		return platform.DependencyUnavailable
	}
	if err = queries.MarkInstallationInitialized(ctx); err != nil {
		return platform.DependencyUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return platform.DependencyUnavailable
	}
	return platform.Ready
}

// Reached only during validation, before any account or marker mutation. The
// attempt writes nothing: the caller's deferred rollback closes the
// transaction and the installation keeps no marker and no user.
func bootstrapValidationFailure() platform.State {
	return platform.BootstrapFailed
}

// Attempt is useful to operators/tests too: no inputs or driver error is exposed.
func (i *Initializer) Attempt(ctx context.Context) platform.Readiness {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var state platform.State
	if err := Migrate(ctx, i.pool); err != nil {
		state = platform.DependencyUnavailable
		if schemaFailure(err) {
			state = platform.SchemaError
		}
	} else {
		state = i.bootstrap(ctx)
	}
	i.state.Store(state)
	return platform.Readiness{State: state}
}

func (i *Initializer) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		state := i.Attempt(ctx).State
		if state == platform.Ready || state == platform.SchemaError {
			return
		}
		delay := min(30*time.Second, backoff+time.Duration(randv2.Int64N(int64(backoff/4)+1)))
		if state == platform.SetupRequired || state == platform.BootstrapFailed {
			delay = 30 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
