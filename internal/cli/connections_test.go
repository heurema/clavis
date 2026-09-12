package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/stretchr/testify/require"
)

// The hints below are the fixture's application-owned guidance. They never
// echo a submitted value, exactly as the route contract requires.
const (
	existsHint   = "A connection with that name exists; update it instead"
	notFoundHint = "List connections to find the name or UUID"
	inUseHint    = "Disable the connection and revoke its grants before deleting it"
	invalidHint  = "Check the provider, target and bounds against the documented values"
)

func (f *cliAuthFixture) connectionIndex(reference string) int {
	for i, connection := range f.connections {
		if connection.ID == strings.ToLower(reference) || connection.Name == reference {
			return i
		}
	}
	return -1
}

func matchesSelector(connection auth.Connection, terms []auth.SelectorTerm) bool {
	for _, term := range terms {
		value, present := connection.Labels[term.Key]
		switch term.Op {
		case auth.SelectorEquals:
			if !present || value != term.Value {
				return false
			}
		case auth.SelectorNotEquals:
			if present && value == term.Value {
				return false
			}
		case auth.SelectorExists:
			if !present {
				return false
			}
		}
	}
	return true
}

// serveConnections implements the design's connection route table over the
// fixture's store: documented statuses, the dryRun query parameter, hints on
// every failure and a stored credential that never leaves the fixture.
func (f *cliAuthFixture) serveConnections(w http.ResponseWriter, r *http.Request, actor auth.Identity, body []byte, fail func(string)) {
	f.connCalls++
	f.connQuery = r.URL.RawQuery
	now := time.Now().UTC().Truncate(time.Second)
	encode := func(status int, value any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	failHint := func(code, hint string) {
		status, safe, _ := auth.LookupFailure(code)
		safe.Hint = hint
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: safe})
	}
	var reference, action string
	if strings.HasPrefix(r.URL.Path, auth.ConnectionsPath+"/") {
		reference, action, _ = strings.Cut(strings.TrimPrefix(r.URL.Path, auth.ConnectionsPath+"/"), "/")
	}
	list := r.Method == http.MethodGet && r.URL.Path == auth.ConnectionsPath
	create := r.Method == http.MethodPost && r.URL.Path == auth.ConnectionsPath
	record := r.Method == http.MethodGet && reference != "" && action == ""
	mutating := r.Method == http.MethodPost && reference != "" && action != ""
	hasBody := create || action == "update" || action == "credentials"
	if (!list && !create && !record && !mutating) || hasBody != (len(body) != 0) ||
		(hasBody && r.Header.Get("Content-Type") != "application/json") ||
		(reference != "" && !auth.ValidConnectionRef(reference)) {
		fail(auth.InvalidArgument)
		return
	}
	query := r.URL.Query()
	dryRun := false
	for key, values := range query {
		valid := len(values) == 1
		switch key {
		case auth.DryRunQuery:
			valid = valid && values[0] == "true" && (create || mutating) && action != "check"
			dryRun = true
		case "selector", "limit":
			valid = valid && list
		default:
			valid = false
		}
		if !valid {
			fail(auth.InvalidArgument)
			return
		}
	}
	role := actor.User.Role
	if i := f.userIndex(actor.User.ID); i >= 0 {
		role = f.users[i].Role
	}
	if role != auth.Admin {
		fail(auth.Forbidden)
		return
	}
	switch {
	case list:
		terms, ok := auth.ParseSelector(query.Get("selector"))
		limit := auth.MaxConnectionListing
		if raw := query.Get("limit"); ok && raw != "" {
			value, err := strconv.Atoi(raw)
			ok = err == nil && value >= 1 && value <= auth.MaxConnectionListing
			limit = value
		}
		if !ok {
			failHint(auth.InvalidArgument, invalidHint)
			return
		}
		matched := []auth.Connection{}
		for _, connection := range f.connections {
			if matchesSelector(connection, terms) {
				matched = append(matched, connection)
			}
		}
		sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })
		truncated := f.connTruncated
		if len(matched) > limit {
			matched, truncated = matched[:limit], true
		}
		encode(http.StatusOK, auth.ConnectionList{Connections: matched, Truncated: truncated})
		return
	case create:
		f.connBody = body
		var input auth.CreateConnectionRequest
		secretRequired := true
		if strictJSON(body, &input) {
			secretRequired = input.Provider != auth.ProviderVictoriaMetrics || input.Target["auth"] != "none"
		}
		if !strictJSON(body, &input) || !auth.ValidConnectionName(input.Name) || !auth.ValidProvider(input.Provider) ||
			!auth.ValidLabels(input.Labels) || input.Target["url"] == "" ||
			secretRequired != auth.ValidSecret(input.Secret) {
			failHint(auth.InvalidArgument, invalidHint)
			return
		}
		if f.connectionIndex(input.Name) >= 0 {
			failHint(auth.ConnectionExists, existsHint)
			return
		}
		created := auth.Connection{
			ID: testUserID(), Name: input.Name, Title: input.Title, Description: input.Description,
			Scope: input.Scope, Provider: input.Provider, Target: input.Target, Labels: input.Labels,
			Enabled: true, StatementTimeoutMS: input.StatementTimeoutMS, MaxRows: input.MaxRows,
			MaxBytes: input.MaxBytes, CreatedAt: now, UpdatedAt: now,
		}
		if created.StatementTimeoutMS == 0 {
			created.StatementTimeoutMS = int(auth.DefaultStatementTimeout / time.Millisecond)
		}
		if created.MaxRows == 0 {
			created.MaxRows = auth.DefaultMaxRows
		}
		if created.MaxBytes == 0 {
			created.MaxBytes = auth.DefaultMaxBytes
		}
		if dryRun {
			encode(http.StatusOK, auth.ConnectionMutation{Connection: created, DryRun: true})
			return
		}
		f.connections = append(f.connections, created)
		f.connSecrets[created.ID] = input.Secret
		f.connMutations++
		encode(http.StatusCreated, created)
		return
	}
	i := f.connectionIndex(reference)
	if i < 0 {
		failHint(auth.ConnectionNotFound, notFoundHint)
		return
	}
	updated := f.connections[i]
	updated.UpdatedAt = now
	commit := func(value auth.ConnectionMutation) {
		if !dryRun {
			f.connections[i] = value.Connection
			f.connMutations++
		}
		encode(http.StatusOK, value)
	}
	switch action {
	case "":
		encode(http.StatusOK, f.connections[i])
	case "update":
		var input auth.UpdateConnectionRequest
		if !strictJSON(body, &input) {
			failHint(auth.InvalidArgument, invalidHint)
			return
		}
		if input.Name != nil {
			if !auth.ValidConnectionName(*input.Name) {
				failHint(auth.InvalidArgument, invalidHint)
				return
			}
			if other := f.connectionIndex(*input.Name); other >= 0 && other != i {
				failHint(auth.ConnectionExists, existsHint)
				return
			}
			updated.Name = *input.Name
		}
		for _, field := range []struct {
			value  *string
			target *string
		}{{input.Title, &updated.Title}, {input.Description, &updated.Description}, {input.Scope, &updated.Scope}} {
			if field.value != nil {
				*field.target = *field.value
			}
		}
		if input.Target != nil {
			updated.Target = *input.Target
		}
		if input.Labels != nil {
			if !auth.ValidLabels(*input.Labels) {
				failHint(auth.InvalidArgument, invalidHint)
				return
			}
			updated.Labels = *input.Labels
		}
		for _, field := range []struct {
			value  *int
			target *int
		}{{input.StatementTimeoutMS, &updated.StatementTimeoutMS}, {input.MaxRows, &updated.MaxRows}, {input.MaxBytes, &updated.MaxBytes}} {
			if field.value != nil {
				*field.target = *field.value
			}
		}
		commit(auth.ConnectionMutation{Connection: updated, DryRun: dryRun})
	case "credentials":
		f.connBody = body
		var input auth.SetConnectionCredentialsRequest
		if !strictJSON(body, &input) || !auth.ValidSecret(input.Secret) {
			failHint(auth.InvalidArgument, invalidHint)
			return
		}
		// Replacing the credential always clears the last check result.
		updated.LastCheck = nil
		if !dryRun {
			f.connSecrets[updated.ID] = input.Secret
		}
		commit(auth.ConnectionMutation{Connection: updated, DryRun: dryRun})
	case "enable", "disable":
		updated.Enabled = action == "enable"
		commit(auth.ConnectionMutation{Connection: updated, DryRun: dryRun})
	case "delete":
		if updated.Enabled {
			failHint(auth.ConnectionInUse, inUseHint)
			return
		}
		if !dryRun {
			f.connections = slices.Delete(f.connections, i, i+1)
			delete(f.connSecrets, updated.ID)
			f.connMutations++
		}
		encode(http.StatusOK, auth.ConnectionDeletion{ID: updated.ID, Name: updated.Name, Deleted: true, DryRun: dryRun})
	case "check":
		outcome := f.connOutcome
		if _, stored := f.connSecrets[updated.ID]; !stored {
			outcome = auth.CheckCredentialsUnavailable
		}
		if outcome == auth.CheckCredentialsUnavailable {
			failHint(auth.CredentialsUnavailable, "Replace the credential with set-credentials")
			return
		}
		checked := auth.CheckResult{Outcome: outcome, CheckedAt: now}
		updated.LastCheck = &checked
		f.connections[i] = updated
		encode(http.StatusOK, auth.ConnectionCheck{Connection: updated, Check: checked})
	default:
		fail(auth.InvalidArgument)
	}
}

func secretFile(t *testing.T, home, name, value string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(home, name)
	require.NoError(t, os.WriteFile(path, []byte(value), mode))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func testConnection(name string) auth.Connection {
	moment := time.Date(2026, 9, 11, 8, 30, 0, 0, time.UTC)
	return auth.Connection{
		ID: "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba", Name: name, Title: "Payments reporting",
		Description: "Read-only reporting role", Scope: "payments", Provider: auth.ProviderPostgreSQL,
		Target:             map[string]string{"url": "postgres://reporting@db:5432/payments?sslmode=require"},
		Labels:             map[string]string{"env": "prod", "team": "data"},
		Enabled:            true,
		StatementTimeoutMS: 30000, MaxRows: 1000, MaxBytes: 1 << 20,
		CreatedAt: moment, UpdatedAt: moment,
	}
}

// TestConnectionsWorkflow walks the documented lifecycle over the fixture and
// pins the exact create body, the secret-free output and the dry-run behavior.
func TestConnectionsWorkflow(t *testing.T) {
	home := cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	secret := `pw"\/` + "\x01<>&" + string(testToken())
	path := secretFile(t, home, "reporting", secret+"\n", 0o600)

	run := func(args ...string) (int, Result, string) {
		t.Helper()
		return cliInvoke(t, "", append(args, "--server", server.URL)...)
	}
	// Text output is not a JSON document, so it bypasses the decoding helper.
	text := func(args ...string) (int, string) {
		t.Helper()
		var out, prompt bytes.Buffer
		arguments := append([]string{"clavis", "--output=text"}, append(args, "--server", server.URL)...)
		exit := RunWithIO(context.Background(), arguments, IO{
			Stdin: strings.NewReader(""), Stdout: &out, Stderr: &prompt, ReadPassword: ReadTerminalPassword,
		})
		require.Empty(t, prompt.String())
		return exit, out.String()
	}
	exit, result, output := run("connections", "create", "--name", "payments-prod-reporting",
		"--provider", "postgresql", "--url", "postgres://reporting@db:5432/payments?sslmode=require",
		"--label", "env=prod", "--label", "team=data", "--title", "Payments reporting",
		"--statement-timeout", "45s", "--max-rows", "500", "--password-file", path)
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.True(t, result.OK)
	created, ok := result.Data.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "payments-prod-reporting", created["name"])
	require.Equal(t, true, created["enabled"])
	require.Nil(t, created["lastCheck"])
	require.NotContains(t, keys(created), "secret")
	require.False(t, strings.Contains(output, secret[len(secret)-43:]))
	require.NotContains(t, output, "password")
	identifier, _ := created["id"].(string)
	require.True(t, auth.ValidUserID(identifier))

	expected, err := json.Marshal(auth.CreateConnectionRequest{
		Name: "payments-prod-reporting", Title: "Payments reporting",
		Provider:           auth.ProviderPostgreSQL,
		Target:             map[string]string{"url": "postgres://reporting@db:5432/payments?sslmode=require"},
		Labels:             map[string]string{"env": "prod", "team": "data"},
		StatementTimeoutMS: 45000, MaxRows: 500, Secret: auth.Secret(secret),
	})
	require.NoError(t, err)
	fixture.mu.Lock()
	require.Equal(t, string(expected), string(fixture.connBody))
	require.Empty(t, fixture.connQuery, "a committed create sends no query")
	fixture.mu.Unlock()

	// Reading back by name and by UUID resolves the same record.
	for _, reference := range []string{"payments-prod-reporting", strings.ToUpper(identifier)} {
		exit, result, _ = run("connections", "get", "--connection", reference)
		require.Equal(t, 0, exit)
		require.Equal(t, identifier, result.Data.(map[string]any)["id"])
	}

	exit, output = text("connections", "list", "--selector", "env=prod,team")
	require.Equal(t, 0, exit)
	require.Equal(t, identifier+" payments-prod-reporting postgresql enabled unchecked\n", output)
	exit, result, _ = run("connections", "list", "--selector", "env!=prod")
	require.Equal(t, 0, exit)
	require.Empty(t, result.Data.(map[string]any)["connections"])

	// Labels given on update replace the whole set; other fields stay put.
	exit, result, _ = run("connections", "update", "--connection", "payments-prod-reporting", "--label", "env=staging")
	require.Equal(t, 0, exit)
	updated, _ := result.Data.(map[string]any)["connection"].(map[string]any)
	require.Equal(t, map[string]any{"env": "staging"}, updated["labels"])
	require.Equal(t, float64(45000), updated["statementTimeoutMs"])
	require.Equal(t, false, result.Data.(map[string]any)["dryRun"])

	exit, result, _ = run("connections", "check", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, "reachable", result.Data.(map[string]any)["check"].(map[string]any)["outcome"])

	// Replacing the credential from a named variable clears the last check and
	// keeps the value out of the argument list.
	replacement := string(testToken())
	t.Setenv("CLAVIS_TEST_SECRET", replacement)
	args := []string{"connections", "set-credentials", "--connection", "payments-prod-reporting", "--password-env", "CLAVIS_TEST_SECRET"}
	require.False(t, slices.Contains(args, replacement))
	exit, result, output = run(args...)
	require.Equal(t, 0, exit)
	require.False(t, strings.Contains(output, replacement))
	require.Nil(t, result.Data.(map[string]any)["connection"].(map[string]any)["lastCheck"])
	fixture.mu.Lock()
	require.Equal(t, auth.Secret(replacement), fixture.connSecrets[identifier])
	fixture.mu.Unlock()

	// A dry run of a refused delete changes nothing and renders the hint.
	exit, result, _ = run("connections", "delete", "--connection", "payments-prod-reporting", "--dry-run")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.ConnectionInUse, result.Error.Code)
	require.Equal(t, inUseHint, result.Error.Hint)
	exit, output = text("connections", "delete", "--connection", "payments-prod-reporting", "--dry-run")
	require.Equal(t, 1, exit)
	require.Equal(t, "CONNECTION_IN_USE: "+result.Error.Message+"\nHint: "+inUseHint+"\n", output)
	fixture.mu.Lock()
	require.Equal(t, auth.DryRunQuery+"=true", fixture.connQuery)
	require.Len(t, fixture.connections, 1)
	fixture.mu.Unlock()

	exit, result, _ = run("connections", "disable", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, false, result.Data.(map[string]any)["connection"].(map[string]any)["enabled"])
	fixture.mu.Lock()
	before := fixture.connMutations
	fixture.mu.Unlock()
	exit, result, _ = run("connections", "delete", "--connection", "payments-prod-reporting", "--dry-run")
	require.Equal(t, 0, exit)
	require.Equal(t, true, result.Data.(map[string]any)["dryRun"])
	fixture.mu.Lock()
	require.Equal(t, before, fixture.connMutations, "a dry run commits nothing")
	require.Len(t, fixture.connections, 1)
	fixture.mu.Unlock()
	exit, output = text("connections", "delete", "--connection", "payments-prod-reporting")
	require.Equal(t, 0, exit)
	require.Equal(t, "Deleted: payments-prod-reporting ("+identifier+")\n", output)
	exit, result, _ = run("connections", "get", "--connection", "payments-prod-reporting")
	require.Equal(t, 1, exit)
	require.Equal(t, auth.ConnectionNotFound, result.Error.Code)
	require.Equal(t, notFoundHint, result.Error.Hint)

	// A second connection with the same name reports the documented conflict.
	other := secretFile(t, home, "other", string(testToken()), 0o400)
	for range 2 {
		exit, result, _ = run("connections", "create", "--name", "metrics-prod", "--provider", "victoriametrics",
			"--url", "https://metrics.example:8428", "--auth", "bearer", "--password-file", other)
		require.Contains(t, []int{0, 1}, exit)
	}
	require.Equal(t, auth.ConnectionExists, result.Error.Code)
	require.Equal(t, existsHint, result.Error.Hint)

	// VictoriaMetrics without authentication needs no secret at all.
	exit, result, _ = run("connections", "create", "--name", "metrics-open", "--provider", "victoriametrics",
		"--url", "https://open.example:8428", "--auth", "none")
	require.Equal(t, 0, exit, "%+v", result.Error)
	require.Equal(t, "metrics-open", result.Data.(map[string]any)["name"])

	exit, output = text("connections", "list")
	require.Equal(t, 0, exit)
	require.Equal(t, 2, strings.Count(output, "\n"))
	fixture.mu.Lock()
	fixture.connTruncated = true
	fixture.mu.Unlock()
	exit, output = text("connections", "list", "--limit", "1000")
	require.Equal(t, 0, exit)
	require.True(t, strings.HasSuffix(output, "Truncated: list is limited to 1000 connections\n"))
}

// TestConnectionsSecretInputsRejected proves every refused secret input exits 2
// with a hint and reaches neither the credential cache nor the server.
func TestConnectionsSecretInputsRejected(t *testing.T) {
	home := cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	valid := secretFile(t, home, "valid", string(testToken()), 0o600)
	unsafe := secretFile(t, home, "unsafe", string(testToken()), 0o644)
	oversized := secretFile(t, home, "oversized", strings.Repeat("x", auth.MaxSecretBytes+3), 0o600)
	empty := secretFile(t, home, "empty", "\n", 0o600)
	t.Setenv("CLAVIS_TEST_SECRET", string(testToken()))
	t.Setenv("CLAVIS_TEST_EMPTY", "")
	create := []string{"connections", "create", "--name", "payments-prod", "--provider", "postgresql",
		"--url", "postgres://reporting@db:5432/payments"}
	credentials := []string{"connections", "set-credentials", "--connection", "payments-prod"}
	for _, tc := range []struct {
		name string
		args []string
		// unknown marks the arguments the flag parser refuses before the
		// command runs: there is no flag carrying a secret value, so the
		// generic usage failure applies instead of the secret-input hint.
		unknown        bool
		noninteractive bool
	}{
		{name: "value-flag", args: append(slices.Clone(create), "--password", string(testToken()))},
		{name: "password-argument", args: append(slices.Clone(credentials), "--password="+string(testToken()))},
		{name: "two-inputs", args: append(slices.Clone(create), "--password-file", valid, "--password-env", "CLAVIS_TEST_SECRET")},
		{name: "stdin-and-file", args: append(slices.Clone(credentials), "--password-stdin", "--password-file", valid)},
		{name: "relative-file", args: append(slices.Clone(create), "--password-file", "reporting")},
		{name: "unsafe-file", args: append(slices.Clone(create), "--password-file", unsafe)},
		{name: "directory-file", args: append(slices.Clone(create), "--password-file", home)},
		{name: "missing-file", args: append(slices.Clone(create), "--password-file", filepath.Join(home, "absent"))},
		{name: "oversized-file", args: append(slices.Clone(create), "--password-file", oversized)},
		{name: "empty-file", args: append(slices.Clone(create), "--password-file", empty)},
		{name: "unset-variable", args: append(slices.Clone(create), "--password-env", "CLAVIS_TEST_ABSENT")},
		{name: "empty-variable", args: append(slices.Clone(credentials), "--password-env", "CLAVIS_TEST_EMPTY")},
		{name: "invalid-variable-name", args: append(slices.Clone(create), "--password-env", "clavis_test_secret")},
		{name: "secret-without-need", args: []string{"connections", "create", "--name", "metrics-open",
			"--provider", "victoriametrics", "--url", "https://open.example:8428", "--auth", "none",
			"--password-file", valid}},
		{name: "missing-secret", args: slices.Clone(create), noninteractive: true},
		{name: "missing-credential", args: slices.Clone(credentials), noninteractive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.mu.Lock()
			before := fixture.connCalls
			fixture.mu.Unlock()
			reader := HiddenPasswordReader(func(context.Context, io.Reader, io.Writer) ([]byte, error) {
				t.Fatal("an invalid secret input must be refused before any prompt")
				return nil, nil
			})
			if tc.noninteractive {
				// A non-terminal stdin makes the production adapter refuse.
				reader = ReadTerminalPassword
			}
			args := append([]string{"--output=text"}, append(slices.Clone(tc.args), "--server", server.URL)...)
			exit, result, output, prompt := usersInvoke(t, reader, string(testToken()), args...)
			require.Equal(t, 2, exit)
			require.Equal(t, auth.InvalidArgument, result.Error.Code)
			require.Equal(t, secretInputHint, result.Error.Hint)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
			require.Empty(t, prompt)
			// Neither a submitted path nor a submitted value is echoed.
			require.NotContains(t, output, home)
			require.NotContains(t, output, tc.args[len(tc.args)-1])
			fixture.mu.Lock()
			require.Equal(t, before, fixture.connCalls, "no request may be made")
			fixture.mu.Unlock()
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.connCalls)
	require.Empty(t, fixture.connections)
}

// TestConnectionsArgumentsRejectedBeforeIO covers the non-secret arguments.
func TestConnectionsArgumentsRejectedBeforeIO(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	identifier := testIdentity().User.ID
	for _, args := range [][]string{
		{"connections", "unknown"},
		{"connections", "list", "extra"},
		{"connections", "list", "--selector", "ENV=prod"},
		{"connections", "list", "--selector", "a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9"},
		{"connections", "list", "--limit", "0"},
		{"connections", "list", "--limit", "1001"},
		{"connections", "get"},
		{"connections", "get", "--connection", "UPPER"},
		{"connections", "check", "--connection", "7fde7ce1-cc8d-4de8-a9c0"},
		{"connections", "create", "--provider", "postgresql", "--url", "postgres://db"},
		{"connections", "create", "--name", identifier, "--provider", "postgresql", "--url", "postgres://db"},
		{"connections", "create", "--name", "payments", "--provider", "mysql", "--url", "mysql://db"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", ""},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--auth", "kerberos"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--label", "env"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--label", "env=prod", "--label", "env=dev"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--statement-timeout", "500ms"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--statement-timeout", "5m"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--max-rows", "100001"},
		{"connections", "create", "--name", "payments", "--provider", "postgresql", "--url", "postgres://db", "--max-bytes", "512"},
		{"connections", "update", "--connection", "payments"},
		{"connections", "update", "--connection", "payments", "--title", "New", "--timeout=0"},
		{"connections", "update", "--connection", "payments", "--title", "New", "--server=http://localhost:8080"},
		{"connections", "delete", "--connection", "payments", "extra"},
		{"connections", "disable"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			invocation := append([]string{"--output=text"}, slices.Clone(args)...)
			// A case that sets its own origin or deadline keeps it.
			if !slices.ContainsFunc(args, func(value string) bool {
				return strings.HasPrefix(value, "--server") || strings.HasPrefix(value, "--timeout")
			}) {
				invocation = append(invocation, "--server", server.URL)
			}
			exit, result, output := cliInvoke(t, string(testToken()), invocation...)
			require.Equal(t, 2, exit)
			require.Equal(t, auth.InvalidArgument, result.Error.Code)
			require.True(t, json.Valid([]byte(output)), "exit 2 forces JSON")
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.connCalls)
}

func TestConnectionsRequireCachedSession(t *testing.T) {
	cliHome(t)
	fixture, server := newCLIFixture(t, testToken())
	for _, args := range [][]string{
		{"connections", "list"}, {"connections", "get", "--connection", "payments"},
		{"connections", "enable", "--connection", "payments"},
		{"connections", "check", "--connection", "payments"},
	} {
		exit, result, _ := cliInvoke(t, "", append(args, "--server", server.URL)...)
		require.Equal(t, 1, exit)
		require.Equal(t, auth.Unauthenticated, result.Error.Code)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Zero(t, fixture.requests)
}

// connectionRoutes is the documented route table as the CLI calls it.
func connectionRoutes(reference string) []apiCall {
	return []apiCall{
		{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK},
		{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated},
		{http.MethodGet, connectionPath(auth.ConnectionPath, reference), "", http.StatusOK},
		{http.MethodPost, connectionPath(auth.ConnectionUpdatePath, reference), "", http.StatusOK},
		{http.MethodPost, connectionPath(auth.ConnectionCredentialsPath, reference), "", http.StatusOK},
		{http.MethodPost, connectionPath(auth.ConnectionEnablePath, reference), "", http.StatusOK},
		{http.MethodPost, connectionPath(auth.ConnectionDisablePath, reference), "", http.StatusOK},
		{http.MethodPost, connectionPath(auth.ConnectionDeletePath, reference), "dryRun=true", http.StatusOK},
		{http.MethodPost, connectionPath(auth.ConnectionCheckPath, reference), "", http.StatusOK},
	}
}

func connectionOutput(route apiCall) any {
	switch {
	case route.method == http.MethodGet && route.path == auth.ConnectionsPath:
		return &auth.ConnectionList{}
	case route.method == http.MethodPost && route.path == auth.ConnectionsPath:
		return &auth.Connection{}
	case route.method == http.MethodGet:
		return &auth.Connection{}
	case strings.HasSuffix(route.path, "/delete"):
		return &auth.ConnectionDeletion{}
	case strings.HasSuffix(route.path, "/check"):
		return &auth.ConnectionCheck{}
	}
	return &auth.ConnectionMutation{}
}

// TestConnectionsTransportStrictResponses refuses every undocumented response
// without reflecting its body.
func TestConnectionsTransportStrictResponses(t *testing.T) {
	connection := testConnection("payments-prod-reporting")
	record, err := json.Marshal(connection)
	require.NoError(t, err)
	mutation, err := json.Marshal(auth.ConnectionMutation{Connection: connection})
	require.NoError(t, err)
	list, err := json.Marshal(auth.ConnectionList{Connections: []auth.Connection{connection}})
	require.NoError(t, err)
	check, err := json.Marshal(auth.ConnectionCheck{Connection: connection,
		Check: auth.CheckResult{Outcome: auth.CheckReachable, CheckedAt: connection.CreatedAt}})
	require.NoError(t, err)
	deletion, err := json.Marshal(auth.ConnectionDeletion{ID: connection.ID, Name: connection.Name, Deleted: true})
	require.NoError(t, err)
	update := connectionPath(auth.ConnectionUpdatePath, connection.Name)
	errorBody := func(code string) string { return `{"error":{"code":"` + code + `","message":"sentinel"}}` }
	for _, tc := range []struct {
		name        string
		route       apiCall
		output      any
		status      int
		contentType string
		body        string
	}{
		{"create-200", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 200, "application/json", string(record)},
		{"update-201", apiCall{http.MethodPost, update, "", http.StatusOK}, &auth.ConnectionMutation{}, 201, "application/json", string(mutation)},
		{"record-secret", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.TrimSuffix(string(record), "}") + `,"secret":"sentinel"}`},
		{"record-alias", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"name":`, `"NAME":`, 1)},
		{"record-uuid-name", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"payments-prod-reporting"`, `"`+connection.ID+`"`, 1)},
		{"record-provider", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"postgresql"`, `"clickhouse"`, 1)},
		{"record-non-utc", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `Z"`, `+02:00"`, 1)},
		{"record-empty-target", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"target":{"url":"postgres://reporting@db:5432/payments?sslmode=require"}`, `"target":{}`, 1)},
		{"record-control-target", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `postgres://reporting`, `\u001b[2Jsentinel`, 1)},
		{"record-bounds", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"maxRows":1000`, `"maxRows":100001`, 1)},
		{"record-timeout", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"statementTimeoutMs":30000`, `"statementTimeoutMs":120001`, 1)},
		{"record-label", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 201, "application/json", strings.Replace(string(record), `"env":"prod"`, `"ENV":"prod"`, 1)},
		{"list-shape", apiCall{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK}, &auth.ConnectionList{}, 200, "application/json", string(record)},
		{"list-element", apiCall{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK}, &auth.ConnectionList{}, 200, "application/json", strings.Replace(string(list), connection.ID, "sentinel", 1)},
		{"list-null", apiCall{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK}, &auth.ConnectionList{}, 200, "application/json", `null`},
		{"mutation-shape", apiCall{http.MethodPost, update, "", http.StatusOK}, &auth.ConnectionMutation{}, 200, "application/json", string(record)},
		{"mutation-extra", apiCall{http.MethodPost, update, "", http.StatusOK}, &auth.ConnectionMutation{}, 200, "application/json", strings.TrimSuffix(string(mutation), "}") + `,"secret":"sentinel"}`},
		{"deletion-false", apiCall{http.MethodPost, connectionPath(auth.ConnectionDeletePath, connection.Name), "", http.StatusOK}, &auth.ConnectionDeletion{}, 200, "application/json", strings.Replace(string(deletion), `"deleted":true`, `"deleted":false`, 1)},
		{"check-outcome", apiCall{http.MethodPost, connectionPath(auth.ConnectionCheckPath, connection.Name), "", http.StatusOK}, &auth.ConnectionCheck{}, 200, "application/json", strings.Replace(string(check), `"reachable"`, `"sentinel"`, 1)},
		{"check-html", apiCall{http.MethodPost, connectionPath(auth.ConnectionCheckPath, connection.Name), "", http.StatusOK}, &auth.ConnectionCheck{}, 200, "text/html", string(check)},
		{"exists-on-get", apiCall{http.MethodGet, connectionPath(auth.ConnectionPath, connection.Name), "", http.StatusOK}, &auth.Connection{}, 409, "application/json", errorBody(auth.ConnectionExists)},
		{"in-use-on-update", apiCall{http.MethodPost, update, "", http.StatusOK}, &auth.ConnectionMutation{}, 409, "application/json", errorBody(auth.ConnectionInUse)},
		{"credentials-on-update", apiCall{http.MethodPost, update, "", http.StatusOK}, &auth.ConnectionMutation{}, 409, "application/json", errorBody(auth.CredentialsUnavailable)},
		{"not-found-on-list", apiCall{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK}, &auth.ConnectionList{}, 404, "application/json", errorBody(auth.ConnectionNotFound)},
		{"exists-wrong-status", apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}, &auth.Connection{}, 403, "application/json", errorBody(auth.ConnectionExists)},
		{"unknown-code", apiCall{http.MethodPost, update, "", http.StatusOK}, &auth.ConnectionMutation{}, 409, "application/json", errorBody("SECRET")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, tc.route.method, r.Method)
				require.Equal(t, tc.route.path, r.URL.Path)
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			result := (authTransport{server.URL, time.Second}).send(context.Background(), tc.route, testToken(), nil, tc.output)
			require.NotNil(t, result)
			require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
			require.Empty(t, result.Error.Hint)
			require.Equal(t, int32(1), calls.Load())
			for _, format := range []string{"json", "text"} {
				var out bytes.Buffer
				require.NoError(t, render(&out, *result, format))
				require.NotContains(t, out.String(), "sentinel")
			}
		})
	}
}

// TestConnectionsDocumentedFailures checks the per-route allowlist, the hint
// pass-through and that redirects are never followed.
func TestConnectionsDocumentedFailures(t *testing.T) {
	routes := connectionRoutes("payments-prod-reporting")
	var destinationCalls, calls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, route := range routes {
		result := (authTransport{redirect.URL, time.Second}).send(context.Background(), route, testToken(), nil, connectionOutput(route))
		require.Equal(t, "INVALID_RESPONSE", result.Error.Code)
	}
	require.Equal(t, int32(len(routes)), calls.Load(), "mutations must not retry")
	require.Zero(t, destinationCalls.Load())

	common := []string{auth.InvalidArgument, auth.Unauthenticated, auth.Forbidden, auth.ServiceUnavailable, platform.CodeSetupRequired}
	allowed := map[string][]string{
		"POST " + auth.ConnectionsPath: {auth.ConnectionExists},
		"POST " + connectionPath(auth.ConnectionUpdatePath, "payments-prod-reporting"):      {auth.ConnectionNotFound, auth.ConnectionExists},
		"POST " + connectionPath(auth.ConnectionCredentialsPath, "payments-prod-reporting"): {auth.ConnectionNotFound},
		"POST " + connectionPath(auth.ConnectionEnablePath, "payments-prod-reporting"):      {auth.ConnectionNotFound},
		"POST " + connectionPath(auth.ConnectionDisablePath, "payments-prod-reporting"):     {auth.ConnectionNotFound},
		"POST " + connectionPath(auth.ConnectionDeletePath, "payments-prod-reporting"):      {auth.ConnectionNotFound, auth.ConnectionInUse},
		"POST " + connectionPath(auth.ConnectionCheckPath, "payments-prod-reporting"):       {auth.ConnectionNotFound, auth.CredentialsUnavailable},
		"GET " + connectionPath(auth.ConnectionPath, "payments-prod-reporting"):             {auth.ConnectionNotFound},
	}
	connectionCodes := []string{auth.ConnectionExists, auth.ConnectionNotFound, auth.ConnectionInUse, auth.CredentialsUnavailable}
	for _, route := range routes {
		permitted := allowed[route.method+" "+route.path]
		for _, code := range append(slices.Clone(common), connectionCodes...) {
			status, safe, _ := auth.LookupFailure(code)
			hint := "Use the documented next step"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: platform.Failure{
					Code: code, Message: string(testToken()), Hint: hint,
				}})
			}))
			result := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), nil, connectionOutput(route))
			server.Close()
			require.NotNil(t, result)
			if slices.Contains(connectionCodes, code) && !slices.Contains(permitted, code) {
				require.Equal(t, "INVALID_RESPONSE", result.Error.Code, "%s %s %s", route.method, route.path, code)
				continue
			}
			require.Equal(t, safe.Code, result.Error.Code, "%s %s", route.path, code)
			require.Equal(t, safe.Message, result.Error.Message)
			require.Equal(t, hint, result.Error.Hint)
			require.Nil(t, result.Data)
		}
	}
}

// TestConnectionsHintSafety drops hints that could rewrite the terminal.
func TestConnectionsHintSafety(t *testing.T) {
	for _, hint := range []string{
		"", "\x1b[2Jsentinel", "line\nsentinel", "tab\tsentinel", "\x7fsentinel",
		strings.Repeat("x", maxHintBytes+1),
	} {
		status, _, _ := auth.LookupFailure(auth.ConnectionNotFound)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(auth.ErrorResponse{Error: platform.Failure{
				Code: auth.ConnectionNotFound, Message: "Connection not found", Hint: hint,
			}})
		}))
		route := apiCall{http.MethodGet, connectionPath(auth.ConnectionPath, "payments"), "", http.StatusOK}
		result := (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), nil, &auth.Connection{})
		server.Close()
		require.NotNil(t, result)
		require.Equal(t, auth.ConnectionNotFound, result.Error.Code)
		require.Empty(t, result.Error.Hint)
		var out bytes.Buffer
		require.NoError(t, render(&out, *result, "text"))
		require.NotContains(t, out.String(), "sentinel")
	}
}

func TestConnectionsTextRendering(t *testing.T) {
	connection := testConnection("payments-prod-reporting")
	checked := connection
	outcome := auth.CheckResult{Outcome: auth.CheckAuthRejected, CheckedAt: connection.CreatedAt.Add(time.Hour)}
	checked.LastCheck = &outcome
	metrics := auth.Connection{
		ID: "0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11", Name: "metrics-prod", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": "https://metrics.example:8428", "auth": "bearer"},
		Labels: map[string]string{}, StatementTimeoutMS: 5000, MaxRows: 10, MaxBytes: 2048,
		CreatedAt: connection.CreatedAt, UpdatedAt: connection.CreatedAt,
	}
	block := "Connection: payments-prod-reporting\nID: 7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba\n" +
		"Title: Payments reporting\nProvider: postgresql\n" +
		"Target: url=postgres://reporting@db:5432/payments?sslmode=require\nLabels: env=prod team=data\n" +
		"Status: enabled\nTimeout: 30s\nMax rows: 1000\nMax bytes: 1048576\nLast check: never\n" +
		"Created: 2026-09-11T08:30:00Z\nUpdated: 2026-09-11T08:30:00Z\n"
	checkedBlock := strings.Replace(block, "Last check: never", "Last check: auth_rejected at 2026-09-11T09:30:00Z", 1)
	lines := "7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba payments-prod-reporting postgresql enabled unchecked\n" +
		"0b6a8ca4-2b8a-4a06-9d6b-0d2c3f9c1e11 metrics-prod victoriametrics disabled unchecked\n"
	for name, tc := range map[string]struct {
		result Result
		want   string
	}{
		"list":           {success(auth.ConnectionList{Connections: []auth.Connection{connection, metrics}}), lines},
		"list-truncated": {success(auth.ConnectionList{Connections: []auth.Connection{connection}, Truncated: true}), strings.Split(lines, "\n")[0] + "\nTruncated: list is limited to 1000 connections\n"},
		"list-empty":     {success(auth.ConnectionList{Connections: []auth.Connection{}}), ""},
		"record":         {success(connection), block},
		"record-checked": {success(checked), checkedBlock},
		"mutation":       {success(auth.ConnectionMutation{Connection: connection}), block},
		"mutation-dry":   {success(auth.ConnectionMutation{Connection: connection, DryRun: true}), block + "Dry run: true\n"},
		"deletion":       {success(auth.ConnectionDeletion{ID: connection.ID, Name: connection.Name, Deleted: true}), "Deleted: payments-prod-reporting (7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba)\n"},
		"deletion-dry":   {success(auth.ConnectionDeletion{ID: connection.ID, Name: connection.Name, Deleted: true, DryRun: true}), "Deleted: payments-prod-reporting (7fde7ce1-cc8d-4de8-a9c0-df22ce8d92ba)\nDry run: true\n"},
		"check":          {success(auth.ConnectionCheck{Connection: checked, Check: outcome}), checkedBlock + "Check: auth_rejected at 2026-09-11T09:30:00Z\n"},
		"failure":        {failure(auth.ConnectionNotFound, "Connection not found", nil), "CONNECTION_NOT_FOUND: Connection not found\n"},
		"failure-hint":   {failureWithHint(auth.ConnectionExists, "A connection with that name already exists", existsHint), "CONNECTION_EXISTS: A connection with that name already exists\nHint: " + existsHint + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, render(&out, tc.result, "text"))
			require.Equal(t, tc.want, out.String())
			require.NotContains(t, strings.ToLower(out.String()), "secret")
			var encoded bytes.Buffer
			require.NoError(t, render(&encoded, tc.result, "json"))
			require.NotContains(t, strings.ToLower(encoded.String()), `"secret"`)
			decoded := decode(t, encoded.String())
			require.Equal(t, 1, decoded.SchemaVersion)
		})
	}
}

// TestConnectionsListingBodyLimit gives the connection listing the same
// dedicated response bound as the user listing. A connection record is far
// larger than a user record, so the shared 256 KiB bound, not the 1,000-record
// listing bound, is what the server must keep the listing under.
func TestConnectionsListingBodyLimit(t *testing.T) {
	full := auth.ConnectionList{}
	for n := 0; ; n++ {
		connection := testConnection("c" + strconv.Itoa(n) + "-name")
		connection.ID = "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(strconv.Itoa(n))) + strconv.Itoa(n)
		encoded, err := json.Marshal(append(slices.Clone(full.Connections), connection))
		require.NoError(t, err)
		if len(encoded) > auth.MaxListingBody-64 {
			break
		}
		full.Connections = append(full.Connections, connection)
	}
	require.Less(t, len(full.Connections), auth.MaxConnectionListing,
		"a full connection listing does not fit the shared listing body limit")
	body, err := json.Marshal(full)
	require.NoError(t, err)
	require.Greater(t, len(body), auth.MaxResponseBody)
	require.LessOrEqual(t, len(body), auth.MaxListingBody)
	serve := func(payload []byte, route apiCall, output any) *Result {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(route.status)
			_, _ = w.Write(payload)
		}))
		defer server.Close()
		return (authTransport{server.URL, time.Second}).send(context.Background(), route, testToken(), nil, output)
	}
	listing := apiCall{http.MethodGet, auth.ConnectionsPath, "", http.StatusOK}
	var list auth.ConnectionList
	require.Nil(t, serve(body, listing, &list))
	require.Len(t, list.Connections, len(full.Connections))
	padded := append([]byte(strings.Repeat(" ", auth.MaxListingBody)), body...)
	require.Equal(t, "INVALID_RESPONSE", serve(padded, listing, &auth.ConnectionList{}).Error.Code)

	record, err := json.Marshal(testConnection("payments-prod-reporting"))
	require.NoError(t, err)
	oversized := append([]byte(strings.Repeat(" ", auth.MaxResponseBody)), record...)
	create := apiCall{http.MethodPost, auth.ConnectionsPath, "", http.StatusCreated}
	require.Equal(t, "INVALID_RESPONSE", serve(oversized, create, &auth.Connection{}).Error.Code)
}

func TestConnectionsUpdateRequiresURLWithTargetFlags(t *testing.T) {
	cliHome(t)
	password := testToken()
	fixture, server := newCLIFixture(t, password)
	loginCLI(t, server, password)
	fixture.mu.Lock()
	before := fixture.connCalls
	fixture.mu.Unlock()
	for _, args := range [][]string{
		{"connections", "update", "--connection", "payments", "--auth", "bearer"},
		{"connections", "update", "--connection", "payments", "--auth-user", "bob"},
		{"connections", "update", "--connection", "payments", "--auth-header", "X-Key"},
	} {
		exit, result, _ := cliInvoke(t, "", append(args, "--server", server.URL)...)
		require.Equal(t, 2, exit, args)
		require.Equal(t, auth.InvalidArgument, result.Error.Code)
		require.Contains(t, result.Error.Hint, "--url")
	}
	fixture.mu.Lock()
	require.Equal(t, before, fixture.connCalls, "no request may be made")
	fixture.mu.Unlock()
}
