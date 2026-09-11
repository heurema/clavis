package cli

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

type cachedSession struct {
	Origin string `json:"origin"`
	auth.LoginResponse
}

func authCommands(streams IO, check func(*urfave.Command) error, set func(Result)) []*urfave.Command {
	flags := func() []urfave.Flag {
		return []urfave.Flag{
			&urfave.StringFlag{Name: "server", Value: "http://127.0.0.1:8080", Sources: urfave.EnvVars("CLAVIS_SERVER_URL"), Usage: "Server root origin"},
			&urfave.DurationFlag{Name: "timeout", Value: 5 * time.Second, Usage: "Whole-request and credential-lock deadline"},
		}
	}
	// The operation names the runAuth branch; a group prefix ("users.") is
	// dropped from the command name.
	makeCommand := func(operation, usage string, extra ...urfave.Flag) *urfave.Command {
		name := operation[strings.LastIndex(operation, ".")+1:]
		return &urfave.Command{Name: name, Usage: usage, Flags: append(flags(), extra...), Action: func(ctx context.Context, command *urfave.Command) error {
			if err := check(command); err != nil {
				return err
			}
			set(runAuth(ctx, operation, command, streams))
			return nil
		}}
	}
	group := func(name, usage string, commands ...*urfave.Command) *urfave.Command {
		return &urfave.Command{Name: name, Usage: usage, Action: func(ctx context.Context, command *urfave.Command) error {
			if err := check(command); err != nil {
				return err
			}
			return urfave.ShowSubcommandHelp(command)
		}, Commands: commands}
	}
	return []*urfave.Command{
		makeCommand("login", "Sign in and store a private local session",
			&urfave.StringFlag{Name: "username", Usage: "Personal username"},
			&urfave.BoolFlag{Name: "password-stdin", Usage: "Read a bounded password from stdin instead of a hidden terminal prompt"}),
		makeCommand("logout", "Revoke and remove the local session"),
		makeCommand("whoami", "Check current identity with the server"),
		group("sessions", "Manage sessions",
			makeCommand("revoke", "Revoke all current sessions for a user (administrator only)",
				&urfave.StringFlag{Name: "user", Usage: "Target user UUID"})),
		group("users", "Manage local users (administrator only)", usersCommands(makeCommand)...),
	}
}

func storageFailure() Result {
	return failure("CREDENTIAL_STORAGE_FAILED", "Private credential storage is unavailable or unsafe; credentials were not displayed", nil)
}

// validateAuthArguments rejects invalid targets before any credential input,
// cache access or network I/O.
func validateAuthArguments(operation string, command *urfave.Command) *Result {
	var message string
	switch operation {
	case "login", "users.create":
		if !auth.ValidUsername(command.String("username")) {
			message = "Provide a valid username"
		}
	case "revoke", "users.block", "users.unblock", "users.reset-password", "users.set-role":
		if !auth.ValidUserID(command.String("user")) {
			message = "Provide a valid user UUID"
		}
	}
	if message == "" && operation == "users.set-role" && !validRole(auth.Role(command.String("role"))) {
		message = "Provide a role of admin or member"
	}
	if message == "" {
		return nil
	}
	r := failure("INVALID_ARGUMENT", message, nil)
	return &r
}

func needsPassword(operation string) bool {
	return operation == "login" || operation == "users.create" || operation == "users.reset-password"
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
	origin, err := auth.CanonicalOrigin(command.String("server"))
	timeout := command.Duration("timeout")
	if err != nil || timeout <= 0 {
		return failure("INVALID_ARGUMENT", "Use an HTTPS root origin (literal loopback HTTP is allowed) and a positive timeout", nil)
	}
	if invalid := validateAuthArguments(operation, command); invalid != nil {
		return *invalid
	}
	var password []byte
	if needsPassword(operation) {
		var failed *Result
		if password, failed = readPassword(ctx, command, streams); failed != nil {
			return *failed
		}
	}
	lockCtx, cancel := context.WithTimeout(ctx, min(timeout, 5*time.Second))
	cache, err := openCache(lockCtx, origin)
	cancel()
	if err != nil {
		return storageFailure()
	}
	defer cache.close()
	previous, err := cache.read()
	if err != nil {
		return storageFailure()
	}
	api := authTransport{origin: origin, timeout: timeout}
	if operation == "login" {
		input := auth.LoginRequest{Username: command.String("username"), Password: auth.Secret(password)}
		var issued auth.LoginResponse
		if failed := api.request(ctx, auth.LoginPath, "", &input, &issued); failed != nil {
			return *failed
		}
		if err := cache.write(cachedSession{Origin: origin, LoginResponse: issued}); err != nil {
			api.cleanup(issued.Token)
			return storageFailure()
		}
		if previous != nil && previous.Token != issued.Token {
			api.cleanup(previous.Token)
		}
		return success(issued.Identity)
	}
	if operation == "whoami" {
		var token auth.Secret
		if previous != nil {
			token = previous.Token
		}
		var identity auth.Identity
		if failed := api.request(ctx, auth.WhoAmIPath, token, nil, &identity); failed != nil {
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
		failed := api.request(ctx, auth.LogoutPath, previous.Token, nil, &revoked)
		if err := cache.remove(previous); err != nil {
			return storageFailure()
		}
		if failed != nil && failed.Error.Code != auth.Unauthenticated {
			return failure(failed.Error.Code, "Local credential removed; remote revocation was not confirmed", nil)
		}
		return success(auth.Revocation{Revoked: true})
	case "revoke":
		var revoked auth.Revocation
		path := userPath(auth.RevokePath, command.String("user"))
		if failed := api.request(ctx, path, previous.Token, nil, &revoked); failed != nil {
			return *failed
		}
		return success(revoked)
	default:
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
	_ = a.request(context.Background(), auth.LogoutPath, token, nil, &revoked)
}
