package cli

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// sharedTimeout is the whole-request deadline every command but execution
// takes: none of them waits on anything but the platform itself.
const sharedTimeout = 5 * time.Second

type cachedSession struct {
	Origin string `json:"origin"`
	auth.LoginResponse
}

func authCommands(streams IO, check func(*urfave.Command) error, set func(Result)) []*urfave.Command {
	flags := func(timeout time.Duration, timeoutUsage string) []urfave.Flag {
		return []urfave.Flag{
			&urfave.StringFlag{Name: "server", Usage: "Server root origin for this command only"},
			&urfave.StringFlag{Name: "profile", Usage: "Configured profile naming the server"},
			&urfave.DurationFlag{Name: "timeout", Value: timeout, Usage: timeoutUsage},
		}
	}
	// The operation names the runAuth branch; a group prefix ("users.") is
	// dropped from the command name. Every command takes the same whole-request
	// deadline; only execution, which waits on an external source, defaults to
	// a different one.
	timedCommand := func(timeout time.Duration, timeoutUsage string) func(string, string, ...urfave.Flag) *urfave.Command {
		return func(operation, usage string, extra ...urfave.Flag) *urfave.Command {
			name := operation[strings.LastIndex(operation, ".")+1:]
			return &urfave.Command{Name: name, Usage: usage, Flags: append(flags(timeout, timeoutUsage), extra...), Action: func(ctx context.Context, command *urfave.Command) error {
				if err := check(command); err != nil {
					return err
				}
				set(runAuth(ctx, operation, command, streams))
				return nil
			}}
		}
	}
	makeCommand := timedCommand(sharedTimeout, "Whole-request and credential-lock deadline")
	group := func(name, usage string, commands ...*urfave.Command) *urfave.Command {
		return &urfave.Command{Name: name, Usage: usage, Action: func(ctx context.Context, command *urfave.Command) error {
			if err := check(command); err != nil {
				return err
			}
			return urfave.ShowSubcommandHelp(command)
		}, Commands: commands}
	}
	return []*urfave.Command{
		makeCommand("login", "Sign in through the browser and store a private local session",
			&urfave.BoolFlag{Name: "no-browser", Usage: "Print the sign-in link without opening a browser"}),
		makeCommand("logout", "Revoke and remove the local session"),
		makeCommand("whoami", "Check current identity with the server"),
		queryCommand(timedCommand(auth.QueryRequestBudget, queryTimeoutUsage)),
		group("sessions", "Manage sessions",
			makeCommand("revoke", "Revoke all current sessions for a user (administrator only)",
				&urfave.StringFlag{Name: "user", Usage: "Target user UUID or username"})),
		group("users", "Manage local users (administrator only)", usersCommands(makeCommand)...),
		group("connections", "Manage data-source connections (members see the ones granted to them)", connectionsCommands(makeCommand)...),
		group("groups", "Manage groups of users that connections can be granted to (administrator only)", groupsCommands(makeCommand)...),
		group("grants", "Manage which users and groups may use which connections", grantsCommands(makeCommand)...),
	}
}

// storageFailure names the offending local path when a check identified one.
func storageFailure(err error) Result {
	message := "Private credential storage is unavailable or unsafe"
	var unsafe storageError
	if errors.As(err, &unsafe) {
		message = unsafe.Error()
	}
	return failure("CREDENTIAL_STORAGE_FAILED", message+"; credentials were not displayed", nil)
}

// validateAuthArguments rejects invalid targets before any credential input,
// cache access or network I/O.
func validateAuthArguments(operation string, command *urfave.Command) *Result {
	if connectionCommand(operation) {
		return validateConnectionArguments(operation, command)
	}
	if grantCommand(operation) {
		return validateGrantArguments(operation, command)
	}
	if groupCommand(operation) {
		return validateGroupArguments(operation, command)
	}
	if operation == "query" {
		return validateQueryArguments(command)
	}
	var message, hint string
	switch operation {
	case "users.create":
		// Creation is the one place a username is chosen rather than resolved,
		// so the rule, including the UUID-shape exclusion, is spelled out.
		if !auth.ValidUsername(command.String("username")) {
			message, hint = "Provide a valid username", auth.UsernameHint
		}
	case "revoke", "users.block", "users.unblock", "users.reset-password", "users.set-role":
		// A target is a reference: a UUID or a username, sent unchanged for the
		// server to resolve.
		if !auth.ValidUserRef(command.String("user")) {
			message, hint = "Provide a valid user UUID or username", userRefHint
		}
	}
	if message == "" && operation == "users.set-role" && !validRole(auth.Role(command.String("role"))) {
		message = "Provide a role of admin or member"
	}
	if message == "" {
		return nil
	}
	r := failureWithHint("INVALID_ARGUMENT", message, hint)
	return &r
}

func needsPassword(operation string) bool {
	return operation == "users.create" || operation == "users.reset-password"
}

// readPassword is the single credential input path: hidden terminal input or
// explicit --password-stdin, never arguments or the environment.
func readPassword(ctx context.Context, command *urfave.Command, streams IO) ([]byte, *Result) {
	var password []byte
	var err error
	if command.Bool("password-stdin") {
		password, err = passwordFromStdin(ctx, streams.Stdin)
	} else if streams.ReadPassword != nil {
		password, err = streams.ReadPassword(ctx, streams.Stdin, streams.Stderr)
	} else {
		err = errPasswordInput
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		r := failure("TIMEOUT", "Password input was canceled", nil)
		return nil, &r
	}
	if err != nil || !validPassword(password) {
		r := failure("INVALID_ARGUMENT", "Use valid hidden terminal input or explicit --password-stdin", nil)
		return nil, &r
	}
	return password, nil
}

func runAuth(ctx context.Context, operation string, command *urfave.Command, streams IO) Result {
	resolved, failed := resolveCommandTarget(command)
	if failed != nil {
		return *failed
	}
	return resolved.named(runResolved(ctx, operation, command, streams, resolved.Origin))
}

// runResolved runs an operation against a resolved origin. Every result it
// returns, however early, is named by runAuth.
func runResolved(ctx context.Context, operation string, command *urfave.Command, streams IO, origin string) Result {
	timeout := command.Duration("timeout")
	if timeout <= 0 {
		return failure("INVALID_ARGUMENT", "Use a positive timeout", nil)
	}
	if invalid := validateAuthArguments(operation, command); invalid != nil {
		return *invalid
	}
	if operation == "login" {
		return browserLogin(ctx, command, streams, origin, timeout)
	}
	var password []byte
	if needsPassword(operation) {
		var failed *Result
		if password, failed = readPassword(ctx, command, streams); failed != nil {
			return *failed
		}
	}
	var secret auth.Secret
	if secretCommand(operation) {
		var failed *Result
		if secret, failed = readSecret(ctx, command, streams, connectionSecretRequired(operation, command)); failed != nil {
			return *failed
		}
	}
	// The statement is read on the same terms as a credential: exactly one
	// channel, bounded, and before any cache or network access.
	var sql string
	if operation == "query" {
		var failed *Result
		if sql, failed = readSQL(ctx, command, streams); failed != nil {
			return *failed
		}
	}
	lockCtx, cancel := context.WithTimeout(ctx, min(timeout, 5*time.Second))
	cache, err := openCache(lockCtx, origin)
	cancel()
	if err != nil {
		return storageFailure(err)
	}
	defer cache.close()
	previous, err := cache.read()
	if err != nil {
		return storageFailure(err)
	}
	api := authTransport{origin: origin, timeout: timeout}
	if operation == "whoami" {
		var token auth.Secret
		if previous != nil {
			token = previous.Token
		}
		var identity auth.Identity
		if failed := api.request(ctx, auth.WhoAmIPath, token, &identity); failed != nil {
			return *failed
		}
		return success(identity)
	}
	if previous == nil {
		if operation == "logout" {
			return success(auth.Revocation{Revoked: true})
		}
		return failure(auth.Unauthenticated, "Sign-in is required", nil)
	}
	switch operation {
	case "logout":
		var revoked auth.Revocation
		failed := api.request(ctx, auth.LogoutPath, previous.Token, &revoked)
		if err := cache.remove(previous); err != nil {
			return storageFailure(err)
		}
		if failed != nil && failed.Error.Code != auth.Unauthenticated {
			return failure(failed.Error.Code, "Local credential removed; remote revocation was not confirmed", nil)
		}
		return success(auth.Revocation{Revoked: true})
	case "query":
		return runQuery(ctx, command, api, previous.Token, sql)
	case "revoke":
		var revoked auth.Revocation
		path := userPath(auth.RevokePath, command.String("user"))
		if failed := api.request(ctx, path, previous.Token, &revoked); failed != nil {
			return *failed
		}
		return success(revoked)
	default:
		if connectionCommand(operation) {
			return runConnections(ctx, operation, command, api, previous.Token, secret)
		}
		if grantCommand(operation) {
			return runGrants(ctx, operation, command, api, previous.Token)
		}
		if groupCommand(operation) {
			return runGroups(ctx, operation, command, api, previous.Token)
		}
		return runUsers(ctx, operation, command, api, previous.Token, password)
	}
}

func userPath(pattern, userID string) string {
	return strings.Replace(pattern, "{userID}", strings.ToLower(userID), 1)
}

func (a authTransport) cleanup(token auth.Secret) {
	// A canceled foreground operation must still have a bounded chance to revoke
	// a newly issued but unpersisted credential. This is one attempt, never retry.
	a.timeout = min(a.timeout, time.Second)
	var revoked auth.Revocation
	_ = a.request(context.Background(), auth.LogoutPath, token, &revoked)
}
