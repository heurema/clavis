package cli

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// groupRefHint explains the two accepted spellings of a group reference, and
// groupNameHint the one rule a chosen name must satisfy. Neither ever echoes
// the value that was refused.
const (
	groupRefHint  = "A group name matches [a-z][a-z0-9._-]{2,63}; a UUID is the 36-character form"
	groupNameHint = "A group name matches [a-z][a-z0-9._-]{2,63} and is never shaped like a UUID"
)

// groupsCommands builds the administrator group-management group. It shares
// the verb vocabulary of users and connections: list, get, create, update,
// delete, plus the membership verbs. No command carries a secret.
func groupsCommands(makeCommand func(operation, usage string, extra ...urfave.Flag) *urfave.Command) []*urfave.Command {
	group := func() urfave.Flag {
		return &urfave.StringFlag{Name: "group", Usage: "Target group UUID or name"}
	}
	user := func() urfave.Flag {
		return &urfave.StringFlag{Name: "user", Usage: "Target user UUID or username"}
	}
	description := func() urfave.Flag {
		return &urfave.StringFlag{Name: "description", Usage: "What the group is for"}
	}
	dryRun := func() urfave.Flag {
		return &urfave.BoolFlag{Name: "dry-run", Usage: "Validate, authorize and guard on the server without committing"}
	}
	return []*urfave.Command{
		makeCommand("groups.list", "List groups (bounded; a truncated flag reports overflow)",
			&urfave.IntFlag{Name: "limit", Usage: "Maximum groups to return"}),
		makeCommand("groups.get", "Show one group by UUID or name", group()),
		makeCommand("groups.create", "Create a group that connections can be granted to",
			&urfave.StringFlag{Name: "name", Usage: "New group name"}, description(), dryRun()),
		makeCommand("groups.update", "Change the supplied fields of a group", group(),
			&urfave.StringFlag{Name: "name", Usage: "New group name"}, description(), dryRun()),
		makeCommand("groups.delete", "Delete a group that holds no grants", group(), dryRun()),
		makeCommand("groups.members", "List a group's members (bounded; a truncated flag reports overflow)",
			group(), &urfave.IntFlag{Name: "limit", Usage: "Maximum members to return"}),
		makeCommand("groups.add-member", "Add a user to a group", group(), user(), dryRun()),
		makeCommand("groups.remove-member", "Remove a user from a group", group(), user(), dryRun()),
	}
}

func groupCommand(operation string) bool { return strings.HasPrefix(operation, "groups.") }

// membershipRequest is the one member a membership mutation body carries: the
// group is named on the path, so only the user travels in the body.
type membershipRequest struct {
	User string `json:"user"`
}

// groupUpdateFields are the two fields an update may change; at least one must
// be given, because an update that changes nothing is a malformed invocation
// rather than a no-op request.
var groupUpdateFields = []string{"name", "description"}

// validateGroupArguments refuses malformed references, names and bounds before
// any cache access or network I/O, so an invalid invocation never becomes a
// request.
func validateGroupArguments(operation string, command *urfave.Command) *Result {
	switch operation {
	case "groups.list":
		return listingBound(command, auth.MaxGroupListing, "groups")
	case "groups.create":
		if !auth.ValidGroupName(command.String("name")) {
			return argumentFailure("Provide a valid group name", groupNameHint)
		}
	default:
		if !auth.ValidGroupRef(command.String("group")) {
			return argumentFailure("Provide a group UUID or name", groupRefHint)
		}
	}
	switch operation {
	case "groups.members":
		return listingBound(command, auth.MaxMemberListing, "members")
	case "groups.add-member", "groups.remove-member":
		if !auth.ValidUserRef(command.String("user")) {
			return argumentFailure("Provide a valid user UUID or username", userRefHint)
		}
		return nil
	case "groups.update":
		if command.IsSet("name") && !auth.ValidGroupName(command.String("name")) {
			return argumentFailure("Provide a valid group name", groupNameHint)
		}
		if !updatesAGroup(command) {
			return argumentFailure("Provide at least one field to update",
				"Pass --name, --description or both")
		}
	}
	// The description is bounded in characters, not bytes, exactly as the
	// stored value is, so a legitimate multibyte description is never refused
	// here. An empty one is meaningful on update: it clears the field.
	if command.IsSet("description") {
		value := command.String("description")
		if utf8.RuneCountInString(value) > auth.MaxDescriptionLength || !printableText(value) {
			return argumentFailure("Provide a valid description",
				"--description takes printable text of up to "+strconv.Itoa(auth.MaxDescriptionLength)+" characters")
		}
	}
	return nil
}

// listingBound is the shared bound check of the two group listings.
func listingBound(command *urfave.Command, bound int, noun string) *Result {
	if limit := command.Int("limit"); command.IsSet("limit") && (limit < 1 || limit > bound) {
		return argumentFailure("Provide a positive limit within the listing bound",
			"--limit accepts 1 to "+strconv.Itoa(bound)+" "+noun)
	}
	return nil
}

func updatesAGroup(command *urfave.Command) bool {
	for _, field := range groupUpdateFields {
		if command.IsSet(field) {
			return true
		}
	}
	return false
}

func groupPath(pattern, reference string) string {
	return strings.Replace(pattern, "{groupID}", strings.ToLower(reference), 1)
}

// runGroups calls exactly one documented group route. Arguments were validated
// before the cached session was read; the server resolves the references and
// rechecks the actor's current role.
func runGroups(ctx context.Context, operation string, command *urfave.Command, api authTransport, token auth.Secret) Result {
	reference := command.String("group")
	query := dryRunQuery(command)
	switch operation {
	case "groups.list", "groups.members":
		values := url.Values{}
		if command.IsSet("limit") {
			values.Set("limit", strconv.Itoa(command.Int("limit")))
		}
		if operation == "groups.list" {
			var list auth.GroupList
			route := apiCall{http.MethodGet, auth.GroupsPath, values.Encode(), http.StatusOK}
			if failed := api.send(ctx, route, token, nil, &list); failed != nil {
				return *failed
			}
			if list.Groups == nil {
				list.Groups = []auth.Group{}
			}
			return success(list)
		}
		var list auth.MemberList
		route := apiCall{http.MethodGet, groupPath(auth.GroupMembersPath, reference), values.Encode(), http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &list); failed != nil {
			return *failed
		}
		if list.Members == nil {
			list.Members = []auth.GroupMember{}
		}
		return success(list)
	case "groups.get":
		var record auth.Group
		route := apiCall{http.MethodGet, groupPath(auth.GroupPath, reference), "", http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &record); failed != nil {
			return *failed
		}
		return success(record)
	case "groups.create":
		input := auth.GroupRequest{Name: command.String("name"), Description: command.String("description")}
		// A committed creation answers 201; a dry run is always 200.
		status := http.StatusCreated
		if query != "" {
			status = http.StatusOK
		}
		var mutation auth.GroupMutation
		route := apiCall{http.MethodPost, auth.GroupsPath, query, status}
		if failed := api.send(ctx, route, token, &input, &mutation); failed != nil {
			return *failed
		}
		return success(mutation)
	case "groups.update":
		var mutation auth.GroupMutation
		route := apiCall{http.MethodPost, groupPath(auth.GroupUpdatePath, reference), query, http.StatusOK}
		if failed := api.send(ctx, route, token, groupUpdate(command), &mutation); failed != nil {
			return *failed
		}
		return success(mutation)
	case "groups.delete":
		var deletion auth.GroupDeletion
		route := apiCall{http.MethodPost, groupPath(auth.GroupDeletePath, reference), query, http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &deletion); failed != nil {
			return *failed
		}
		return success(deletion)
	case "groups.add-member":
		input := membershipRequest{User: command.String("user")}
		// A committed membership answers 201; one that already existed answers
		// 200 with the same body, which the route's accepted statuses allow in
		// one request. A dry run is always 200.
		status := http.StatusCreated
		if query != "" {
			status = http.StatusOK
		}
		var mutation auth.MembershipMutation
		route := apiCall{http.MethodPost, groupPath(auth.GroupMemberAddPath, reference), query, status}
		if failed := api.send(ctx, route, token, &input, &mutation); failed != nil {
			return *failed
		}
		return success(mutation)
	case "groups.remove-member":
		input := membershipRequest{User: command.String("user")}
		var removal auth.MembershipRemoval
		route := apiCall{http.MethodPost, groupPath(auth.GroupMemberRemovePath, reference), query, http.StatusOK}
		if failed := api.send(ctx, route, token, &input, &removal); failed != nil {
			return *failed
		}
		return success(removal)
	}
	return failure(auth.InvalidArgument, "Invalid arguments or configuration; run clavis help", nil)
}

// groupUpdate carries a pointer only for the fields actually given, so an
// omitted field is left untouched and a supplied empty description clears it.
func groupUpdate(command *urfave.Command) *auth.GroupUpdate {
	update := &auth.GroupUpdate{}
	for _, field := range []struct {
		flag  string
		value **string
	}{{"name", &update.Name}, {"description", &update.Description}} {
		if command.IsSet(field.flag) {
			value := command.String(field.flag)
			*field.value = &value
		}
	}
	return update
}
