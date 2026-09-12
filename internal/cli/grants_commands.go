package cli

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// userRefHint explains the two accepted spellings of a user reference. It is
// the grant group's counterpart of the connection reference hint and never
// echoes the value that was refused.
const userRefHint = "A username matches [a-z][a-z0-9._-]{2,63}; a UUID is the 36-character form"

// connectionRefHint is the same rule for connection references.
const connectionRefHint = "A name matches [a-z][a-z0-9._-]{2,63}; a UUID is the 36-character form"

// grantsCommands builds the grant group. It shares the verb vocabulary of the
// other groups: list, create, revoke, with the same reference, dry-run and
// listing-bound conventions. No command carries a secret.
func grantsCommands(makeCommand func(operation, usage string, extra ...urfave.Flag) *urfave.Command) []*urfave.Command {
	user := func() urfave.Flag {
		return &urfave.StringFlag{Name: "user", Usage: "Target user UUID or username"}
	}
	connection := func() urfave.Flag {
		return &urfave.StringFlag{Name: "connection", Usage: "Target connection UUID or name"}
	}
	dryRun := func() urfave.Flag {
		return &urfave.BoolFlag{Name: "dry-run", Usage: "Validate, authorize and guard on the server without committing"}
	}
	return []*urfave.Command{
		makeCommand("grants.list", "List grants (bounded; a truncated flag reports overflow; members see their own)",
			user(), connection(), &urfave.IntFlag{Name: "limit", Usage: "Maximum grants to return"}),
		makeCommand("grants.create", "Allow a user to use a connection", user(), connection(), dryRun()),
		makeCommand("grants.revoke", "Withdraw a user's access to a connection", user(), connection(), dryRun()),
	}
}

func grantCommand(operation string) bool { return strings.HasPrefix(operation, "grants.") }

// validateGrantArguments refuses malformed references and bounds before any
// cache access or network I/O, so an invalid invocation never becomes a request.
func validateGrantArguments(operation string, command *urfave.Command) *Result {
	optional := operation == "grants.list"
	if command.IsSet("user") || !optional {
		if !auth.ValidUserRef(command.String("user")) {
			return argumentFailure("Provide a valid user UUID or username", userRefHint)
		}
	}
	if command.IsSet("connection") || !optional {
		if !auth.ValidConnectionRef(command.String("connection")) {
			return argumentFailure("Provide a connection UUID or name", connectionRefHint)
		}
	}
	if limit := command.Int("limit"); optional && command.IsSet("limit") && (limit < 1 || limit > auth.MaxGrantListing) {
		return argumentFailure("Provide a positive limit within the listing bound",
			"--limit accepts 1 to "+strconv.Itoa(auth.MaxGrantListing))
	}
	return nil
}

// runGrants calls exactly one documented grant route. The references were
// validated before the cached session was read; the server resolves them and
// rechecks the actor's current role.
func runGrants(ctx context.Context, operation string, command *urfave.Command, api authTransport, token auth.Secret) Result {
	if operation == "grants.list" {
		values := url.Values{}
		for _, flag := range []string{"user", "connection"} {
			if command.IsSet(flag) {
				values.Set(flag, command.String(flag))
			}
		}
		if command.IsSet("limit") {
			values.Set("limit", strconv.Itoa(command.Int("limit")))
		}
		var list auth.GrantList
		route := apiCall{http.MethodGet, auth.GrantsPath, values.Encode(), http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &list); failed != nil {
			return *failed
		}
		if list.Grants == nil {
			list.Grants = []auth.Grant{}
		}
		return success(list)
	}
	input := auth.GrantRequest{User: command.String("user"), Connection: command.String("connection")}
	query := dryRunQuery(command)
	if operation == "grants.revoke" {
		var revocation auth.GrantRevocation
		route := apiCall{http.MethodPost, auth.GrantRevokePath, query, http.StatusOK}
		if failed := api.send(ctx, route, token, &input, &revocation); failed != nil {
			return *failed
		}
		return success(revocation)
	}
	// A committed creation answers 201; a grant that already existed answers
	// 200 with the same body, which the route's accepted statuses allow in one
	// request. A dry run is always 200.
	status := http.StatusCreated
	if query != "" {
		status = http.StatusOK
	}
	var mutation auth.GrantMutation
	route := apiCall{http.MethodPost, auth.GrantsPath, query, status}
	if failed := api.send(ctx, route, token, &input, &mutation); failed != nil {
		return *failed
	}
	return success(mutation)
}
