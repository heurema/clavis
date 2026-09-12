package cli

import (
	"context"
	"net/http"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// usersCommands builds the administrator user-management group. Passwords for
// create and reset-password use the login input path (hidden prompt or
// --password-stdin); no command accepts a password or token argument.
func usersCommands(makeCommand func(operation, usage string, extra ...urfave.Flag) *urfave.Command) []*urfave.Command {
	user := func() urfave.Flag {
		return &urfave.StringFlag{Name: "user", Usage: "Target user UUID or username"}
	}
	stdin := func() urfave.Flag {
		return &urfave.BoolFlag{Name: "password-stdin", Usage: "Read a bounded password from stdin instead of a hidden terminal prompt"}
	}
	return []*urfave.Command{
		makeCommand("users.list", "List local users (bounded; a truncated flag reports overflow)"),
		makeCommand("users.create", "Create a member with an administrator-supplied password",
			&urfave.StringFlag{Name: "username", Usage: "New username"}, stdin()),
		makeCommand("users.block", "Disable a user and revoke their sessions", user()),
		makeCommand("users.unblock", "Re-enable a blocked user", user()),
		makeCommand("users.reset-password", "Replace a user's password and revoke their sessions", user(), stdin()),
		makeCommand("users.set-role", "Assign the admin or member role", user(),
			&urfave.StringFlag{Name: "role", Usage: "Role: admin or member"}),
	}
}

// runUsers calls exactly one documented administration endpoint. Arguments
// and the password were validated before the cached session was read; the
// server rechecks the actor's current role.
func runUsers(ctx context.Context, operation string, command *urfave.Command, api authTransport, token auth.Secret, password []byte) Result {
	switch operation {
	case "users.list":
		var list auth.UserList
		if failed := api.call(ctx, http.MethodGet, auth.UsersPath, token, nil, &list); failed != nil {
			return *failed
		}
		if list.Users == nil {
			list.Users = []auth.UserRecord{}
		}
		return success(list)
	case "users.create":
		input := auth.CreateUserRequest{Username: command.String("username"), Password: auth.Secret(password)}
		var record auth.UserRecord
		if failed := api.call(ctx, http.MethodPost, auth.UsersPath, token, &input, &record); failed != nil {
			return *failed
		}
		return success(record)
	}
	var pattern string
	var input any
	switch operation {
	case "users.block":
		pattern = auth.UserBlockPath
	case "users.unblock":
		pattern = auth.UserUnblockPath
	case "users.reset-password":
		pattern = auth.UserPasswordPath
		input = &auth.ResetPasswordRequest{Password: auth.Secret(password)}
	case "users.set-role":
		pattern = auth.UserRolePath
		input = &auth.SetRoleRequest{Role: auth.Role(command.String("role"))}
	default:
		return failure("INVALID_ARGUMENT", "Invalid arguments or configuration; run clavis help", nil)
	}
	var mutation auth.UserMutation
	if failed := api.call(ctx, http.MethodPost, userPath(pattern, command.String("user")), token, input, &mutation); failed != nil {
		return *failed
	}
	return success(mutation)
}
