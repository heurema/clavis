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
	group := func() urfave.Flag {
		return &urfave.StringFlag{Name: "group", Usage: "Target group UUID or name"}
	}
	connection := func() urfave.Flag {
		return &urfave.StringFlag{Name: "connection", Usage: "Target connection UUID or name"}
	}
	dryRun := func() urfave.Flag {
		return &urfave.BoolFlag{Name: "dry-run", Usage: "Validate, authorize and guard on the server without committing"}
	}
	return []*urfave.Command{
		makeCommand("grants.list", "List grants (bounded; a truncated flag reports overflow; members see their own)",
			user(), group(), connection(), &urfave.IntFlag{Name: "limit", Usage: "Maximum grants to return"},
			&urfave.BoolFlag{Name: "effective", Usage: "Report where one user's access comes from: direct grants and group memberships"}),
		makeCommand("grants.create", "Allow a user or a group to use a connection", user(), group(), connection(), dryRun()),
		makeCommand("grants.revoke", "Withdraw a user's or a group's access to a connection", user(), group(), connection(), dryRun()),
	}
}

func grantCommand(operation string) bool { return strings.HasPrefix(operation, "grants.") }

// effectiveGroupHint states why the two flags cannot be combined: the
// effective listing answers for one user, and a group has no access of its own
// to report.
const effectiveGroupHint = "--effective reports one user's access; pass --user or omit it, never --group"

// validateGrantArguments refuses malformed references, recipient combinations
// and bounds before any cache access or network I/O, so an invalid invocation
// never becomes a request.
func validateGrantArguments(operation string, command *urfave.Command) *Result {
	optional := operation == "grants.list"
	effective := optional && command.Bool("effective")
	user, group := command.IsSet("user"), command.IsSet("group")
	// A mutation is keyed on exactly one recipient; a listing filters on at
	// most one. The effective listing takes a user or nothing at all.
	switch {
	case effective && group:
		return argumentFailure("Provide --user or no recipient with --effective", effectiveGroupHint)
	case user && group:
		return argumentFailure("Name exactly one recipient, a user or a group", auth.RecipientHint)
	case !optional && !user && !group:
		return argumentFailure("Name exactly one recipient, a user or a group", auth.RecipientHint)
	}
	if user || !optional && !group {
		if !auth.ValidUserRef(command.String("user")) {
			return argumentFailure("Provide a valid user UUID or username", userRefHint)
		}
	}
	if group {
		if !auth.ValidGroupRef(command.String("group")) {
			return argumentFailure("Provide a group UUID or name", groupRefHint)
		}
	}
	if command.IsSet("connection") || !optional {
		if !auth.ValidConnectionRef(command.String("connection")) {
			return argumentFailure("Provide a connection UUID or name", connectionRefHint)
		}
	}
	bound := auth.MaxGrantListing
	if effective {
		bound = auth.MaxAccessListing
	}
	if limit := command.Int("limit"); optional && command.IsSet("limit") && (limit < 1 || limit > bound) {
		return argumentFailure("Provide a positive limit within the listing bound",
			"--limit accepts 1 to "+strconv.Itoa(bound))
	}
	return nil
}

// runGrants calls exactly one documented grant route. The references were
// validated before the cached session was read; the server resolves them and
// rechecks the actor's current role.
func runGrants(ctx context.Context, operation string, command *urfave.Command, api authTransport, token auth.Secret) Result {
	if operation == "grants.list" {
		values := url.Values{}
		filters := []string{"user", "group", "connection"}
		if command.Bool("effective") {
			// The subject is sent as given or omitted: the role-dependent
			// default and refusal are the server's, never the client's.
			filters = []string{"user", "connection"}
		}
		for _, flag := range filters {
			if command.IsSet(flag) {
				values.Set(flag, command.String(flag))
			}
		}
		if command.IsSet("limit") {
			values.Set("limit", strconv.Itoa(command.Int("limit")))
		}
		if command.Bool("effective") {
			var access auth.AccessList
			route := apiCall{http.MethodGet, auth.GrantsEffectivePath, values.Encode(), http.StatusOK}
			if failed := api.send(ctx, route, token, nil, &access); failed != nil {
				return *failed
			}
			if access.Entries == nil {
				access.Entries = []auth.AccessEntry{}
			}
			return success(access)
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
	input := auth.GrantRequest{User: command.String("user"), Group: command.String("group"),
		Connection: command.String("connection")}
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
