package cli

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// connectionAuthMethods is the CLI-side spelling of the provider-neutral
// authentication methods. Provider-specific validation belongs to the server;
// the CLI only refuses values that cannot be meant at all.
var connectionAuthMethods = []string{"none", "basic", "bearer", "header"}

// targetFlags maps target flags onto the request's target keys. Only flags
// actually given are sent, so the server sees exactly what was asked for.
var targetFlags = []struct{ flag, key string }{
	{"url", "url"}, {"auth", "auth"}, {"auth-user", "user"}, {"auth-header", "header"},
}

// connectionsCommands builds the administrator connection group. It shares the
// verb vocabulary of users: list, get, create, update, enable, disable, delete.
// Secrets use the secret-input channels only; no command takes a secret value.
func connectionsCommands(makeCommand func(operation, usage string, extra ...urfave.Flag) *urfave.Command) []*urfave.Command {
	connection := func() urfave.Flag {
		return &urfave.StringFlag{Name: "connection", Usage: "Target connection UUID or name"}
	}
	dryRun := func() urfave.Flag {
		return &urfave.BoolFlag{Name: "dry-run", Usage: "Validate, authorize and guard on the server without committing"}
	}
	// settings are the optional record fields shared by create and update.
	// --statement-timeout is the source's per-statement limit; the global
	// --timeout stays the whole-request deadline.
	settings := func() []urfave.Flag {
		return []urfave.Flag{
			&urfave.StringFlag{Name: "url", Usage: "Provider target URL without credentials"},
			&urfave.StringFlag{Name: "auth", Usage: "Authentication method: none, basic, bearer or header"},
			&urfave.StringFlag{Name: "auth-user", Usage: "Non-secret user name for basic authentication"},
			&urfave.StringFlag{Name: "auth-header", Usage: "Non-secret header name for header authentication"},
			&urfave.StringSliceFlag{Name: "label", Usage: "Label as key=value; repeat to add more (update replaces the whole set)"},
			&urfave.StringFlag{Name: "title", Usage: "Human-readable title"},
			&urfave.StringFlag{Name: "description", Usage: "What the connection exposes"},
			&urfave.StringFlag{Name: "scope", Usage: "Access scope description"},
			&urfave.DurationFlag{Name: "statement-timeout", Usage: "Statement timeout on the source, for example 30s"},
			&urfave.IntFlag{Name: "max-rows", Usage: "Maximum rows one result may carry"},
			&urfave.IntFlag{Name: "max-bytes", Usage: "Maximum bytes one result may carry"},
		}
	}
	join := func(groups ...[]urfave.Flag) []urfave.Flag {
		var all []urfave.Flag
		for _, group := range groups {
			all = append(all, group...)
		}
		return all
	}
	target := func(extra ...urfave.Flag) []urfave.Flag { return append([]urfave.Flag{connection()}, extra...) }
	return []*urfave.Command{
		makeCommand("connections.list", "List connections (bounded; a truncated flag reports overflow)",
			&urfave.StringFlag{Name: "selector", Usage: "Label selector: key=value, key!=value or key, combined with commas"},
			&urfave.IntFlag{Name: "limit", Usage: "Maximum connections to return"}),
		makeCommand("connections.get", "Show one connection by UUID or name", connection()),
		makeCommand("connections.create", "Register a connection with an encrypted credential",
			join([]urfave.Flag{
				&urfave.StringFlag{Name: "name", Usage: "New connection name"},
				&urfave.StringFlag{Name: "provider", Usage: "Provider: postgresql or victoriametrics"},
			}, settings(), []urfave.Flag{dryRun()}, secretFlags())...),
		makeCommand("connections.update", "Change the supplied fields of a connection",
			join(target(&urfave.StringFlag{Name: "name", Usage: "New connection name"}), settings(), []urfave.Flag{dryRun()})...),
		makeCommand("connections.set-credentials", "Replace the stored credential and clear the last check",
			join(target(dryRun()), secretFlags())...),
		makeCommand("connections.enable", "Enable a connection", target(dryRun())...),
		makeCommand("connections.disable", "Disable a connection", target(dryRun())...),
		makeCommand("connections.delete", "Delete a disabled connection that holds no grants", target(dryRun())...),
		makeCommand("connections.check", "Probe the source once and store the outcome", connection()),
	}
}

func connectionCommand(operation string) bool { return strings.HasPrefix(operation, "connections.") }

// secretCommand names the two operations that carry a credential.
func secretCommand(operation string) bool {
	return operation == "connections.create" || operation == "connections.set-credentials"
}

// connectionSecretRequired mirrors the one provider case that authenticates
// with nothing: VictoriaMetrics with the none method.
func connectionSecretRequired(operation string, command *urfave.Command) bool {
	if operation != "connections.create" {
		return secretCommand(operation)
	}
	return command.String("provider") != string(auth.ProviderVictoriaMetrics) || command.String("auth") != "none"
}

// argumentFailure is the shared local-validation refusal of the connection and
// grant groups: exit 2, INVALID_ARGUMENT and a hint naming the valid form.
func argumentFailure(message, hint string) *Result {
	r := failureWithHint(auth.InvalidArgument, message, hint)
	return &r
}

// printableSetting bounds a non-secret setting and refuses control characters,
// so neither an argument nor a server value can rewrite the terminal.
func printableSetting(value string) bool {
	if value == "" || len(value) > auth.MaxDescriptionLength || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// printableText is printableSetting for free text: empty is allowed and so
// are tabs and line breaks, but no other control characters.
func printableText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return (r < 0x20 && r != '\t' && r != '\n') || r == 0x7f })
}

// validateConnectionArguments rejects malformed targets and bounds before any
// secret input, cache access or network I/O.
func validateConnectionArguments(operation string, command *urfave.Command) *Result {
	switch operation {
	case "connections.list":
		if _, ok := auth.ParseSelector(command.String("selector")); !ok {
			return argumentFailure("Provide a valid label selector",
				"Use up to 8 comma-separated terms of key=value, key!=value or key")
		}
		if limit := command.Int("limit"); command.IsSet("limit") && (limit < 1 || limit > auth.MaxConnectionListing) {
			return argumentFailure("Provide a positive limit within the listing bound",
				"--limit accepts 1 to "+strconv.Itoa(auth.MaxConnectionListing))
		}
		return nil
	case "connections.create":
		if !auth.ValidConnectionName(command.String("name")) {
			return argumentFailure("Provide a valid connection name",
				"A name matches [a-z][a-z0-9._-]{2,63} and is never shaped like a UUID")
		}
		if !auth.ValidProvider(auth.ProviderType(command.String("provider"))) {
			return argumentFailure("Provide a registered provider", "--provider accepts postgresql or victoriametrics")
		}
		if !printableSetting(command.String("url")) {
			return argumentFailure("Provide a target URL", "--url takes the source URL without credentials")
		}
	default:
		if !auth.ValidConnectionRef(command.String("connection")) {
			return argumentFailure("Provide a connection UUID or name", connectionRefHint)
		}
	}
	if operation != "connections.create" && operation != "connections.update" {
		return nil
	}
	return validateConnectionSettings(operation, command)
}

// validateConnectionSettings checks the optional record fields shared by create
// and update. Bounds come from the shared contract package.
func validateConnectionSettings(operation string, command *urfave.Command) *Result {
	if command.IsSet("label") {
		if _, ok := auth.ParseLabels(command.StringSlice("label")); !ok {
			return argumentFailure("Provide valid, distinct labels",
				"Use up to 16 distinct --label key=value pairs matching [a-z0-9][a-z0-9._-]{0,62}")
		}
	}
	for _, field := range []struct {
		flag  string
		limit int
	}{{"title", auth.MaxTitleLength}, {"description", auth.MaxDescriptionLength}, {"scope", auth.MaxDescriptionLength}} {
		if value := command.String(field.flag); command.IsSet(field.flag) && (len(value) > field.limit || !printableSetting(value)) {
			return argumentFailure("Provide a valid "+field.flag,
				"--"+field.flag+" takes printable text of up to "+strconv.Itoa(field.limit)+" bytes")
		}
	}
	for _, flag := range []string{"url", "auth-user", "auth-header"} {
		if command.IsSet(flag) && !printableSetting(command.String(flag)) {
			return argumentFailure("Provide a valid --"+flag+" value", "The value must be printable and non-empty")
		}
	}
	if command.IsSet("auth") && !slices.Contains(connectionAuthMethods, command.String("auth")) {
		return argumentFailure("Provide a supported authentication method",
			"--auth accepts "+strings.Join(connectionAuthMethods, ", "))
	}
	if timeout := command.Duration("statement-timeout"); command.IsSet("statement-timeout") &&
		(timeout < auth.MinStatementTimeout || timeout > auth.MaxStatementTimeout ||
			timeout%time.Millisecond != 0) {
		return argumentFailure("Provide a statement timeout within the allowed range",
			"--statement-timeout accepts whole milliseconds from "+auth.MinStatementTimeout.String()+" to "+auth.MaxStatementTimeout.String())
	}
	for _, bound := range []struct {
		flag     string
		low, max int
	}{{"max-rows", 1, auth.MaxMaxRows}, {"max-bytes", auth.MinMaxBytes, auth.MaxMaxBytes}} {
		if value := command.Int(bound.flag); command.IsSet(bound.flag) && (value < bound.low || value > bound.max) {
			return argumentFailure("Provide a "+bound.flag+" value within the allowed range",
				"--"+bound.flag+" accepts "+strconv.Itoa(bound.low)+" to "+strconv.Itoa(bound.max))
		}
	}
	if operation == "connections.update" && !updateRequested(command) {
		return argumentFailure("Provide at least one field to update",
			"Pass any of --name, --url, --auth, --auth-user, --auth-header, --label, --title, --description, --scope, --statement-timeout, --max-rows or --max-bytes")
	}
	if operation == "connections.update" && !command.IsSet("url") {
		// The target is replaced as a whole, so a partial target can never be
		// applied; require the URL alongside any authentication flag.
		for _, mapping := range targetFlags {
			if mapping.flag != "url" && command.IsSet(mapping.flag) {
				return argumentFailure("Provide --url together with any target flag",
					"The target is replaced as a whole on update; pass --url with --auth, --auth-user or --auth-header")
			}
		}
	}
	return nil
}

var updateFields = []string{
	"name", "url", "auth", "auth-user", "auth-header", "label",
	"title", "description", "scope", "statement-timeout", "max-rows", "max-bytes",
}

func updateRequested(command *urfave.Command) bool {
	for _, flag := range updateFields {
		if command.IsSet(flag) {
			return true
		}
	}
	return false
}

// connectionTarget carries only the target flags that were given; the provider
// registry on the server decides what the combination means.
func connectionTarget(command *urfave.Command) map[string]string {
	target := map[string]string{}
	for _, mapping := range targetFlags {
		if command.IsSet(mapping.flag) {
			target[mapping.key] = command.String(mapping.flag)
		}
	}
	return target
}

func connectionPath(pattern, reference string) string {
	return strings.Replace(pattern, "{connectionID}", strings.ToLower(reference), 1)
}

func dryRunQuery(command *urfave.Command) string {
	if !command.Bool("dry-run") {
		return ""
	}
	return url.Values{auth.DryRunQuery: []string{"true"}}.Encode()
}

func milliseconds(value time.Duration) int { return int(value / time.Millisecond) }

// runConnections calls exactly one documented connection route. Arguments, the
// selector and the secret were validated before the cached session was read;
// the server rechecks the actor's current role.
func runConnections(ctx context.Context, operation string, command *urfave.Command, api authTransport, token, secret auth.Secret) Result {
	reference := command.String("connection")
	query := dryRunQuery(command)
	switch operation {
	case "connections.list":
		values := url.Values{}
		if command.IsSet("selector") {
			values.Set("selector", command.String("selector"))
		}
		if command.IsSet("limit") {
			values.Set("limit", strconv.Itoa(command.Int("limit")))
		}
		// The two read routes answer with the projection the caller's role
		// earns: the full record for an administrator, the summary for a
		// member. Either is accepted, strictly; a mixture is not.
		var list connectionListing
		route := apiCall{http.MethodGet, auth.ConnectionsPath, values.Encode(), http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &list); failed != nil {
			return *failed
		}
		return success(list.data())
	case "connections.get":
		var record connectionRecord
		route := apiCall{http.MethodGet, connectionPath(auth.ConnectionPath, reference), "", http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &record); failed != nil {
			return *failed
		}
		return success(record.data())
	case "connections.create":
		labels, _ := auth.ParseLabels(command.StringSlice("label"))
		input := auth.CreateConnectionRequest{
			Name:               command.String("name"),
			Title:              command.String("title"),
			Description:        command.String("description"),
			Scope:              command.String("scope"),
			Provider:           auth.ProviderType(command.String("provider")),
			Target:             connectionTarget(command),
			Labels:             labels,
			StatementTimeoutMS: milliseconds(command.Duration("statement-timeout")),
			MaxRows:            command.Int("max-rows"),
			MaxBytes:           command.Int("max-bytes"),
			Secret:             secret,
		}
		// A committed creation answers 201 with the record; a dry run answers
		// 200 with the mutation it would have made.
		if query != "" {
			var mutation auth.ConnectionMutation
			route := apiCall{http.MethodPost, auth.ConnectionsPath, query, http.StatusOK}
			if failed := api.send(ctx, route, token, &input, &mutation); failed != nil {
				return *failed
			}
			return success(mutation)
		}
		var record auth.Connection
		route := apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}
		if failed := api.send(ctx, route, token, &input, &record); failed != nil {
			return *failed
		}
		return success(record)
	case "connections.delete":
		var deletion auth.ConnectionDeletion
		route := apiCall{http.MethodPost, connectionPath(auth.ConnectionDeletePath, reference), query, http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &deletion); failed != nil {
			return *failed
		}
		return success(deletion)
	case "connections.check":
		var checked auth.ConnectionCheck
		route := apiCall{http.MethodPost, connectionPath(auth.ConnectionCheckPath, reference), "", http.StatusOK}
		if failed := api.send(ctx, route, token, nil, &checked); failed != nil {
			return *failed
		}
		return success(checked)
	}
	var pattern string
	var input any
	switch operation {
	case "connections.update":
		pattern = auth.ConnectionUpdatePath
		input = updateRequest(command)
	case "connections.set-credentials":
		pattern = auth.ConnectionCredentialsPath
		input = &auth.SetConnectionCredentialsRequest{Secret: secret}
	case "connections.enable":
		pattern = auth.ConnectionEnablePath
	case "connections.disable":
		pattern = auth.ConnectionDisablePath
	default:
		return failure(auth.InvalidArgument, "Invalid arguments or configuration; run clavis help", nil)
	}
	var mutation auth.ConnectionMutation
	route := apiCall{http.MethodPost, connectionPath(pattern, reference), query, http.StatusOK}
	if failed := api.send(ctx, route, token, input, &mutation); failed != nil {
		return *failed
	}
	return success(mutation)
}

// updateRequest carries a pointer only for the flags actually given; labels
// given on update replace the whole set.
func updateRequest(command *urfave.Command) *auth.UpdateConnectionRequest {
	input := &auth.UpdateConnectionRequest{}
	for _, field := range []struct {
		flag  string
		value **string
	}{
		{"name", &input.Name}, {"title", &input.Title},
		{"description", &input.Description}, {"scope", &input.Scope},
	} {
		if command.IsSet(field.flag) {
			value := command.String(field.flag)
			*field.value = &value
		}
	}
	for _, mapping := range targetFlags {
		if command.IsSet(mapping.flag) {
			target := connectionTarget(command)
			input.Target = &target
			break
		}
	}
	if command.IsSet("label") {
		labels, _ := auth.ParseLabels(command.StringSlice("label"))
		if labels == nil {
			labels = map[string]string{}
		}
		input.Labels = &labels
	}
	if command.IsSet("statement-timeout") {
		value := milliseconds(command.Duration("statement-timeout"))
		input.StatementTimeoutMS = &value
	}
	for _, field := range []struct {
		flag  string
		value **int
	}{{"max-rows", &input.MaxRows}, {"max-bytes", &input.MaxBytes}} {
		if command.IsSet(field.flag) {
			value := command.Int(field.flag)
			*field.value = &value
		}
	}
	return input
}
