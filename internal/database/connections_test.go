package database

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file is fixture setup, fault injection, or an independent
// assertion against persisted state. Application operations use LocalAuth.

// Sentinels must never reach an event, an error, a hint or the projection.
const (
	sentinelSecret = "sentinel-secret-never-in-output"
	sentinelHost   = "sentinel-host.invalid"
)

func newTestKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	var key [secrets.KeyBytes]byte
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	keyring, err := secrets.NewKeyring(key[:])
	require.NoError(t, err)
	return keyring
}

func connectionFixture(t *testing.T) (*pgxpool.Pool, *LocalAuth, auth.Session, auth.LoginInput) {
	t.Helper()
	pool, s, admin, input := adminFixture(t)
	return pool, s.WithKeyring(newTestKeyring(t)), admin, input
}

func connectionRequest(name string) auth.CreateConnectionRequest {
	return auth.CreateConnectionRequest{
		Name: name, Title: "Payments", Description: "primary ledger", Scope: "read only",
		Provider: auth.ProviderPostgreSQL,
		Target:   map[string]string{"url": "postgres://reader@" + sentinelHost + ":6432/ledger?sslmode=require"},
		Labels:   map[string]string{"env": "prod", "service": "payments"},
		Secret:   sentinelSecret,
	}
}

func createConnection(t *testing.T, s *LocalAuth, admin auth.Session, request auth.CreateConnectionRequest) auth.Connection {
	t.Helper()
	result, err := s.CreateConnection(t.Context(), admin, request, false)
	require.NoError(t, err)
	require.False(t, result.DryRun)
	return result.Connection
}

func storedEnvelope(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var envelope string
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT secret_envelope FROM connections WHERE id=$1`, id).Scan(&envelope))
	return envelope
}

func storedOutcome(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var outcome string
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT coalesce(last_check_outcome,'') FROM connections WHERE id=$1`, id).Scan(&outcome))
	return outcome
}

func hintOf(t *testing.T, err error) string {
	t.Helper()
	require.Error(t, err)
	_, response := auth.FailureFor(err)
	return response.Error.Hint
}

func connectionNames(list auth.ConnectionList) []string {
	names := make([]string, 0, len(list.Connections))
	for _, record := range list.Connections {
		names = append(names, record.Name)
	}
	return names
}

func selector(t *testing.T, value string) []auth.SelectorTerm {
	t.Helper()
	terms, ok := auth.ParseSelector(value)
	require.True(t, ok, value)
	return terms
}

// connectionOperations is every service call, keyed by the event action it
// records, so denial and rollback tests can cover them uniformly.
func connectionOperations(ctx context.Context, s *LocalAuth, actor auth.Session, ref string, dryRun bool) map[string]func() error {
	title := "Updated title"
	return map[string]func() error{
		"connection.create": func() error {
			_, err := s.CreateConnection(ctx, actor, connectionRequest("denied-connection"), dryRun)
			return err
		},
		"connection.update": func() error {
			_, err := s.UpdateConnection(ctx, actor, ref, auth.UpdateConnectionRequest{Title: &title}, dryRun)
			return err
		},
		"connection.set_credentials": func() error {
			_, err := s.SetConnectionCredentials(ctx, actor, ref, "replacement-secret", dryRun)
			return err
		},
		"connection.enable": func() error {
			_, err := s.SetConnectionEnabled(ctx, actor, ref, true, dryRun)
			return err
		},
		"connection.disable": func() error {
			_, err := s.SetConnectionEnabled(ctx, actor, ref, false, dryRun)
			return err
		},
		"connection.delete": func() error {
			_, err := s.DeleteConnection(ctx, actor, ref, dryRun)
			return err
		},
		"connection.check": func() error {
			_, err := s.CheckConnection(ctx, actor, ref)
			return err
		},
		"connection.get": func() error {
			_, err := s.GetConnection(ctx, actor, ref)
			return err
		},
		"connections.list": func() error {
			_, err := s.ListConnections(ctx, actor, nil, 0)
			return err
		},
	}
}

// testDatabaseTarget reuses the test instance as a real probe target: the same
// role and password, with the password kept out of the stored URL.
func testDatabaseTarget(t *testing.T) (map[string]string, auth.Secret) {
	t.Helper()
	parsed, err := url.Parse(os.Getenv("CLAVIS_BACKEND_TEST_DATABASE_URL"))
	require.NoError(t, err)
	password, _ := parsed.User.Password()
	if password == "" {
		t.Skip("the test database URL carries no password to probe with")
	}
	query := url.Values{}
	if mode := parsed.Query().Get("sslmode"); mode != "" {
		query.Set("sslmode", mode)
	}
	safe := url.URL{
		Scheme: parsed.Scheme, User: url.User(parsed.User.Username()),
		Host: parsed.Host, Path: parsed.Path, RawQuery: query.Encode(),
	}
	return map[string]string{"url": safe.String()}, auth.Secret(password)
}

// closedPort returns a loopback port nothing listens on, so a probe fails
// immediately instead of spending the operation deadline.
func closedPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

func TestCreateConnectionStoresSealedRecord(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	require.True(t, auth.ValidUserID(record.ID))
	require.Equal(t, "payments-prod", record.Name)
	require.Equal(t, "Payments", record.Title)
	require.Equal(t, "primary ledger", record.Description)
	require.Equal(t, "read only", record.Scope)
	require.Equal(t, auth.ProviderPostgreSQL, record.Provider)
	require.Equal(t, map[string]string{
		"host": sentinelHost, "port": "6432", "database": "ledger", "role": "reader", "sslmode": "require",
	}, record.Target)
	require.Equal(t, map[string]string{"env": "prod", "service": "payments"}, record.Labels)
	require.True(t, record.Enabled)
	require.Equal(t, 30000, record.StatementTimeoutMS)
	require.Equal(t, auth.DefaultMaxRows, record.MaxRows)
	require.Equal(t, auth.DefaultMaxBytes, record.MaxBytes)
	require.Nil(t, record.LastCheck)
	require.Equal(t, time.UTC, record.CreatedAt.Location())
	require.WithinDuration(t, time.Now(), record.CreatedAt, 5*time.Second)

	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), sentinelSecret)
	require.NotContains(t, string(encoded), "envelope")
	envelope := storedEnvelope(t, pool, record.ID)
	require.True(t, strings.HasPrefix(envelope, "v1:"))
	require.NotContains(t, envelope, sentinelSecret)

	// The same secret under a fresh nonce is a different envelope.
	same := connectionRequest("metrics-prod")
	second := createConnection(t, s, admin, same)
	require.NotEqual(t, envelope, storedEnvelope(t, pool, second.ID))
	actor, target, sessionID := lastEvent(t, pool, "connection.create", "success")
	require.Equal(t, []string{admin.User.ID, second.ID, admin.ID}, []string{actor, target, sessionID})

	byName, err := s.GetConnection(t.Context(), admin, "payments-prod")
	require.NoError(t, err)
	byID, err := s.GetConnection(t.Context(), admin, record.ID)
	require.NoError(t, err)
	require.Equal(t, record, byName)
	require.Equal(t, record, byID)
	require.Equal(t, 0, eventCount(t, pool, "connection.get", "success"))

	// An omitted title defaults to the name; the bounds default too.
	bare := auth.CreateConnectionRequest{
		Name: "bare-connection", Provider: auth.ProviderPostgreSQL,
		Target: map[string]string{"url": "postgres://reader@127.0.0.1/ledger"}, Secret: sentinelSecret,
	}
	minimal := createConnection(t, s, admin, bare)
	require.Equal(t, "bare-connection", minimal.Title)
	require.Equal(t, map[string]string{}, minimal.Labels)
	require.Equal(t, 30000, minimal.StatementTimeoutMS)
	require.Equal(t, auth.DefaultMaxRows, minimal.MaxRows)
	require.Equal(t, auth.DefaultMaxBytes, minimal.MaxBytes)
	require.Equal(t, "prefer", minimal.Target["sslmode"])
}

func TestCreateConnectionAcceptsVictoriaMetricsWithoutASecret(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	request := auth.CreateConnectionRequest{
		Name: "metrics-open", Title: "Metrics", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": "https://" + sentinelHost + ":8428", "auth": "none"},
	}
	record := createConnection(t, s, admin, request)
	require.Equal(t, auth.ProviderVictoriaMetrics, record.Provider)
	require.Equal(t, "none", record.Target["auth"])
	require.True(t, strings.HasPrefix(storedEnvelope(t, pool, record.ID), "v1:"))

	withSecret := request
	withSecret.Name, withSecret.Secret = "metrics-open-two", sentinelSecret
	_, err := s.CreateConnection(t.Context(), admin, withSecret, false)
	code(t, err, auth.InvalidArgument)
	require.NotContains(t, hintOf(t, err), sentinelSecret)
	require.Equal(t, 1, countRows(t, pool, "connections"))
}

func TestConnectionOperationsRejectUnknownReferences(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	events := countRows(t, pool, "auth_events")
	for _, ref := range []string{"missing-connection", randomTestID(t), "Not A Ref"} {
		_, err := s.GetConnection(t.Context(), admin, ref)
		code(t, err, auth.ConnectionNotFound)
		require.Equal(t, hintConnectionNotFound, hintOf(t, err))
	}
	require.Equal(t, events, countRows(t, pool, "auth_events"), "an unknown get records no event")

	for action, operation := range connectionOperations(t.Context(), s, admin, "missing-connection", false) {
		if action == "connection.create" || action == "connections.list" || action == "connection.get" {
			continue
		}
		code(t, operation(), auth.ConnectionNotFound)
		require.Equal(t, 1, eventCount(t, pool, action, "connection_not_found"), action)
		actor, target, sessionID := lastEvent(t, pool, action, "connection_not_found")
		require.Equal(t, []string{admin.User.ID, "", admin.ID}, []string{actor, target, sessionID}, action)
	}
	require.Equal(t, 1, countRows(t, pool, "connections"))
}

func TestCreateConnectionRefusesDuplicateNames(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	createConnection(t, s, admin, connectionRequest("payments-prod"))
	second := createConnection(t, s, admin, connectionRequest("metrics-prod"))

	_, err := s.CreateConnection(t.Context(), admin, connectionRequest("payments-prod"), false)
	code(t, err, auth.ConnectionExists)
	require.Equal(t, hintConnectionExists, hintOf(t, err))
	require.Equal(t, 1, eventCount(t, pool, "connection.create", "connection_exists"))
	actor, target, _ := lastEvent(t, pool, "connection.create", "connection_exists")
	require.Equal(t, admin.User.ID, actor)
	require.Empty(t, target, "an unwritten connection has no verified identifier")

	taken := "payments-prod"
	_, err = s.UpdateConnection(t.Context(), admin, second.ID, auth.UpdateConnectionRequest{Name: &taken}, false)
	code(t, err, auth.ConnectionExists)
	require.Equal(t, 1, eventCount(t, pool, "connection.update", "connection_exists"))
	_, target, _ = lastEvent(t, pool, "connection.update", "connection_exists")
	require.Equal(t, second.ID, target)
	require.Equal(t, 2, countRows(t, pool, "connections"))
	unchanged, err := s.GetConnection(t.Context(), admin, second.ID)
	require.NoError(t, err)
	require.Equal(t, second, unchanged)

	// Renaming a connection to the name it already has is not a collision.
	own := second.Name
	_, err = s.UpdateConnection(t.Context(), admin, second.ID, auth.UpdateConnectionRequest{Name: &own}, false)
	require.NoError(t, err)
}

func TestCreateConnectionMapsUniqueViolationUnderRace(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	// Simulates a row committed outside the connection lock: the existence
	// check passes and the unique index wins.
	racer, err := pool.Begin(t.Context())
	require.NoError(t, err)
	// A failed assertion must not leave the transaction holding a pooled
	// connection, which would stall the fixture's close.
	defer func() { _ = racer.Rollback(context.Background()) }()
	_, err = racer.Exec(t.Context(), `INSERT INTO connections(id,name,title,provider,target,labels,secret_envelope)
		VALUES(gen_random_uuid(),'racer-connection','racer','postgresql','{}'::jsonb,'{}'::jsonb,'v1:fixture')`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateConnection(t.Context(), admin, connectionRequest("racer-connection"), false)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '-- name: InsertConnection :one%'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&n)
		return err == nil && n > 0
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, racer.Commit(t.Context()))
	code(t, <-done, auth.ConnectionExists)
	require.Equal(t, 1, eventCount(t, pool, "connection.create", "connection_exists"))
	require.Equal(t, 1, countRows(t, pool, "connections"))
}

func TestCreateConnectionValidatesEveryBound(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	labels := map[string]string{}
	for index := range auth.MaxLabels + 1 {
		labels["key"+string(rune('a'+index))] = "value"
	}
	events := countRows(t, pool, "auth_events")
	for name, mutate := range map[string]func(*auth.CreateConnectionRequest){
		"uuid-shaped name": func(r *auth.CreateConnectionRequest) { r.Name = randomTestID(t) },
		"upper-case name":  func(r *auth.CreateConnectionRequest) { r.Name = "Payments" },
		"short name":       func(r *auth.CreateConnectionRequest) { r.Name = "ab" },
		"long title":       func(r *auth.CreateConnectionRequest) { r.Title = strings.Repeat("t", auth.MaxTitleLength+1) },
		"control title":    func(r *auth.CreateConnectionRequest) { r.Title = "line\nbreak" },
		"long description": func(r *auth.CreateConnectionRequest) {
			r.Description = strings.Repeat("d", auth.MaxDescriptionLength+1)
		},
		"long scope":       func(r *auth.CreateConnectionRequest) { r.Scope = strings.Repeat("s", auth.MaxDescriptionLength+1) },
		"too many labels":  func(r *auth.CreateConnectionRequest) { r.Labels = labels },
		"bad label key":    func(r *auth.CreateConnectionRequest) { r.Labels = map[string]string{"Env": "prod"} },
		"bad label value":  func(r *auth.CreateConnectionRequest) { r.Labels = map[string]string{"env": "PROD"} },
		"unknown provider": func(r *auth.CreateConnectionRequest) { r.Provider = auth.ProviderType("mysql") },
		"timeout ceiling": func(r *auth.CreateConnectionRequest) {
			r.StatementTimeoutMS = int(auth.MaxStatementTimeout/time.Millisecond) + 1
		},
		"timeout floor": func(r *auth.CreateConnectionRequest) {
			r.StatementTimeoutMS = int(auth.MinStatementTimeout/time.Millisecond) - 1
		},
		"rows ceiling": func(r *auth.CreateConnectionRequest) { r.MaxRows = auth.MaxMaxRows + 1 },
		"rows floor":   func(r *auth.CreateConnectionRequest) { r.MaxRows = -1 },
		"bytes ceiling": func(r *auth.CreateConnectionRequest) {
			r.MaxBytes = auth.MaxMaxBytes + 1
		},
		"bytes floor": func(r *auth.CreateConnectionRequest) { r.MaxBytes = auth.MinMaxBytes - 1 },
		"password in url": func(r *auth.CreateConnectionRequest) {
			r.Target = map[string]string{"url": "postgres://reader:" + sentinelSecret + "@" + sentinelHost + "/ledger"}
		},
		"unknown target setting": func(r *auth.CreateConnectionRequest) {
			r.Target = map[string]string{"url": "postgres://reader@" + sentinelHost + "/ledger", "options": "-c x"}
		},
		"no target":     func(r *auth.CreateConnectionRequest) { r.Target = nil },
		"empty secret":  func(r *auth.CreateConnectionRequest) { r.Secret = "" },
		"secret breaks": func(r *auth.CreateConnectionRequest) { r.Secret = auth.Secret(sentinelSecret + "\n") },
	} {
		request := connectionRequest("payments-prod")
		mutate(&request)
		_, err := s.CreateConnection(t.Context(), admin, request, false)
		code(t, err, auth.InvalidArgument)
		hint := hintOf(t, err)
		require.NotEmpty(t, hint, name)
		require.NotContains(t, hint, sentinelSecret, name)
		require.NotContains(t, hint, sentinelHost, name)
		require.LessOrEqual(t, len(hint), 512, name)
		for _, b := range []byte(hint) {
			require.True(t, b >= 0x20 && b < 0x7f, name)
		}
	}
	unknown := connectionRequest("payments-prod")
	unknown.Provider = auth.ProviderType("mysql")
	_, err := s.CreateConnection(t.Context(), admin, unknown, false)
	require.Contains(t, hintOf(t, err), string(auth.ProviderPostgreSQL))
	require.Contains(t, hintOf(t, err), string(auth.ProviderVictoriaMetrics))
	require.Zero(t, countRows(t, pool, "connections"))
	require.Equal(t, events, countRows(t, pool, "auth_events"), "rejected input records no event")
}

func TestUpdateConnectionChangesOnlySuppliedFields(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	execSQL(t, pool, `UPDATE connections SET last_check_outcome='reachable', last_check_at=clock_timestamp() WHERE id=$1`, record.ID)
	envelope := storedEnvelope(t, pool, record.ID)

	timeout := 60000
	result, err := s.UpdateConnection(t.Context(), admin, record.Name,
		auth.UpdateConnectionRequest{StatementTimeoutMS: &timeout}, false)
	require.NoError(t, err)
	updated := result.Connection
	require.False(t, result.DryRun)
	require.Equal(t, 60000, updated.StatementTimeoutMS)
	require.Equal(t, record.ID, updated.ID)
	require.Equal(t, record.Name, updated.Name)
	require.Equal(t, record.Title, updated.Title)
	require.Equal(t, record.Description, updated.Description)
	require.Equal(t, record.Scope, updated.Scope)
	require.Equal(t, record.Target, updated.Target)
	require.Equal(t, record.Labels, updated.Labels)
	require.Equal(t, record.MaxRows, updated.MaxRows)
	require.Equal(t, record.MaxBytes, updated.MaxBytes)
	require.NotNil(t, updated.LastCheck)
	require.Equal(t, auth.CheckReachable, updated.LastCheck.Outcome)
	require.Equal(t, envelope, storedEnvelope(t, pool, record.ID))
	require.True(t, updated.UpdatedAt.After(record.UpdatedAt))
	require.Equal(t, 1, eventCount(t, pool, "connection.update", "success"))
	_, target, _ := lastEvent(t, pool, "connection.update", "success")
	require.Equal(t, record.ID, target)

	// A rename keeps the identity; labels are replaced as a whole set.
	name, title := "payments-prod-reporting", "Reporting"
	replaced := map[string]string{"team": "sre"}
	retarget := map[string]string{"url": "postgres://reader@" + sentinelHost + ":6433/ledger"}
	result, err = s.UpdateConnection(t.Context(), admin, record.ID, auth.UpdateConnectionRequest{
		Name: &name, Title: &title, Labels: &replaced, Target: &retarget,
	}, false)
	require.NoError(t, err)
	require.Equal(t, record.ID, result.Connection.ID)
	require.Equal(t, name, result.Connection.Name)
	require.Equal(t, title, result.Connection.Title)
	require.Equal(t, replaced, result.Connection.Labels)
	require.Equal(t, "6433", result.Connection.Target["port"])
	require.Equal(t, "prefer", result.Connection.Target["sslmode"])
	require.NotNil(t, result.Connection.LastCheck, "a target change keeps the check history")
	require.Equal(t, envelope, storedEnvelope(t, pool, record.ID))

	// An emptied title returns to the name rather than failing the column.
	empty := ""
	result, err = s.UpdateConnection(t.Context(), admin, record.ID, auth.UpdateConnectionRequest{Title: &empty}, false)
	require.NoError(t, err)
	require.Equal(t, name, result.Connection.Title)

	// Input a body can only reject after reading the row is still a rejection.
	events := countRows(t, pool, "auth_events")
	bad := map[string]string{"url": "postgres://reader:" + sentinelSecret + "@" + sentinelHost + "/ledger"}
	_, err = s.UpdateConnection(t.Context(), admin, record.ID, auth.UpdateConnectionRequest{Target: &bad}, false)
	code(t, err, auth.InvalidArgument)
	require.NotContains(t, hintOf(t, err), sentinelSecret)
	long := strings.Repeat("t", auth.MaxTitleLength+1)
	_, err = s.UpdateConnection(t.Context(), admin, record.ID, auth.UpdateConnectionRequest{Title: &long}, false)
	code(t, err, auth.InvalidArgument)
	require.Equal(t, events, countRows(t, pool, "auth_events"))
}

func TestSetConnectionCredentialsReplacesEnvelopeAndClearsCheck(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	execSQL(t, pool, `UPDATE connections SET last_check_outcome='reachable', last_check_at=clock_timestamp() WHERE id=$1`, record.ID)
	before := storedEnvelope(t, pool, record.ID)

	result, err := s.SetConnectionCredentials(t.Context(), admin, record.Name, auth.Secret(sentinelSecret+"-next"), false)
	require.NoError(t, err)
	require.Nil(t, result.Connection.LastCheck, "replacing credentials clears the last check")
	require.Equal(t, record.ID, result.Connection.ID)
	after := storedEnvelope(t, pool, record.ID)
	require.NotEqual(t, before, after)
	require.True(t, strings.HasPrefix(after, "v1:"))
	require.NotContains(t, after, sentinelSecret)
	require.Empty(t, storedOutcome(t, pool, record.ID))
	require.Equal(t, 1, eventCount(t, pool, "connection.set_credentials", "success"))
	_, target, _ := lastEvent(t, pool, "connection.set_credentials", "success")
	require.Equal(t, record.ID, target)

	events := countRows(t, pool, "auth_events")
	_, err = s.SetConnectionCredentials(t.Context(), admin, record.Name, auth.Secret("with\nbreak"), false)
	code(t, err, auth.InvalidArgument)
	require.Equal(t, events, countRows(t, pool, "auth_events"))
	require.Equal(t, after, storedEnvelope(t, pool, record.ID))
}

func TestConnectionEnableIsIdempotentAndDeleteIsGuarded(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))

	_, err := s.DeleteConnection(t.Context(), admin, record.Name, false)
	code(t, err, auth.ConnectionInUse)
	require.Equal(t, hintConnectionInUse, hintOf(t, err))
	require.Equal(t, 1, eventCount(t, pool, "connection.delete", "connection_in_use"))
	_, target, _ := lastEvent(t, pool, "connection.delete", "connection_in_use")
	require.Equal(t, record.ID, target, "a verified connection names itself in its denial")
	require.Equal(t, 1, countRows(t, pool, "connections"))

	for range 2 {
		result, err := s.SetConnectionEnabled(t.Context(), admin, record.Name, false, false)
		require.NoError(t, err)
		require.False(t, result.Connection.Enabled)
	}
	require.Equal(t, 2, eventCount(t, pool, "connection.disable", "success"))
	enabled, err := s.SetConnectionEnabled(t.Context(), admin, record.ID, true, false)
	require.NoError(t, err)
	require.True(t, enabled.Connection.Enabled)
	require.Equal(t, 1, eventCount(t, pool, "connection.enable", "success"))

	_, err = s.SetConnectionEnabled(t.Context(), admin, record.ID, false, false)
	require.NoError(t, err)
	deletion, err := s.DeleteConnection(t.Context(), admin, record.Name, false)
	require.NoError(t, err)
	require.Equal(t, auth.ConnectionDeletion{ID: record.ID, Name: record.Name, Deleted: true}, deletion)
	require.Zero(t, countRows(t, pool, "connections"))
	require.Equal(t, 1, eventCount(t, pool, "connection.delete", "success"))
	_, target, _ = lastEvent(t, pool, "connection.delete", "success")
	require.Equal(t, record.ID, target)
	_, err = s.GetConnection(t.Context(), admin, record.Name)
	code(t, err, auth.ConnectionNotFound)
}

func TestCheckConnectionStoresEveryOutcome(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	target, password := testDatabaseTarget(t)
	request := connectionRequest("ledger-probe")
	request.Target, request.Secret = target, password
	record := createConnection(t, s, admin, request)

	result, err := s.CheckConnection(t.Context(), admin, record.Name)
	require.NoError(t, err)
	require.Equal(t, auth.CheckReachable, result.Check.Outcome)
	require.NotNil(t, result.Connection.LastCheck)
	require.Equal(t, result.Check, *result.Connection.LastCheck)
	require.Equal(t, time.UTC, result.Check.CheckedAt.Location())
	require.WithinDuration(t, time.Now(), result.Check.CheckedAt, 30*time.Second)
	require.Equal(t, "reachable", storedOutcome(t, pool, record.ID))
	require.Equal(t, 1, eventCount(t, pool, "connection.check", "success"))
	_, eventTarget, _ := lastEvent(t, pool, "connection.check", "success")
	require.Equal(t, record.ID, eventTarget)

	_, err = s.SetConnectionCredentials(t.Context(), admin, record.ID, password+"-wrong", false)
	require.NoError(t, err)
	result, err = s.CheckConnection(t.Context(), admin, record.ID)
	require.NoError(t, err, "a failed check is a result, not an error")
	require.Equal(t, auth.CheckAuthRejected, result.Check.Outcome)
	require.Equal(t, "auth_rejected", storedOutcome(t, pool, record.ID))
	require.Equal(t, 1, eventCount(t, pool, "connection.check", "check_failed"))

	host, port, err := net.SplitHostPort(closedPort(t))
	require.NoError(t, err)
	closed := map[string]string{"url": "postgres://reader@" + net.JoinHostPort(host, port) + "/ledger?sslmode=disable"}
	_, err = s.UpdateConnection(t.Context(), admin, record.ID, auth.UpdateConnectionRequest{Target: &closed}, false)
	require.NoError(t, err)
	result, err = s.CheckConnection(t.Context(), admin, record.ID)
	require.NoError(t, err)
	require.Equal(t, auth.CheckUnreachable, result.Check.Outcome)
	require.Equal(t, "unreachable", storedOutcome(t, pool, record.ID))
	require.Equal(t, 2, eventCount(t, pool, "connection.check", "check_failed"))

	token := auth.Secret("bearer-" + sentinelSecret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+string(token) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	metrics := auth.CreateConnectionRequest{
		Name: "metrics-probe", Title: "Metrics", Provider: auth.ProviderVictoriaMetrics,
		Target: map[string]string{"url": server.URL, "auth": "bearer"}, Secret: token,
	}
	monitoring := createConnection(t, s, admin, metrics)
	result, err = s.CheckConnection(t.Context(), admin, monitoring.Name)
	require.NoError(t, err)
	require.Equal(t, auth.CheckReachable, result.Check.Outcome)
	_, err = s.SetConnectionCredentials(t.Context(), admin, monitoring.Name, "wrong-"+token, false)
	require.NoError(t, err)
	result, err = s.CheckConnection(t.Context(), admin, monitoring.Name)
	require.NoError(t, err)
	require.Equal(t, auth.CheckAuthRejected, result.Check.Outcome)
	require.Equal(t, "auth_rejected", storedOutcome(t, pool, monitoring.ID))

	// No result, projection or event ever carries the secret or the host.
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), sentinelSecret)
	var events string
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT coalesce(string_agg(action||' '||outcome, ' '), '') FROM auth_events`).Scan(&events))
	require.NotContains(t, events, sentinelSecret)
	require.NotContains(t, events, sentinelHost)
}

func TestCheckConnectionFailsClosedWithoutTheKey(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	second := createConnection(t, s, admin, connectionRequest("metrics-prod"))

	other, err := NewLocalAuth(pool, s.checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	_, err = other.WithKeyring(newTestKeyring(t)).CheckConnection(t.Context(), admin, record.Name)
	code(t, err, auth.CredentialsUnavailable)
	require.Equal(t, hintCredentials, hintOf(t, err))
	require.NotContains(t, err.Error(), sentinelSecret)
	require.Equal(t, "credentials_unavailable", storedOutcome(t, pool, record.ID))
	require.Equal(t, 1, eventCount(t, pool, "connection.check", "credentials_unavailable"))
	_, target, _ := lastEvent(t, pool, "connection.check", "credentials_unavailable")
	require.Equal(t, record.ID, target)

	// An envelope is bound to its row and cannot be moved to another.
	execSQL(t, pool, `UPDATE connections SET secret_envelope=(SELECT secret_envelope FROM connections WHERE id=$1) WHERE id=$2`,
		record.ID, second.ID)
	_, err = s.CheckConnection(t.Context(), admin, second.ID)
	code(t, err, auth.CredentialsUnavailable)
	require.Equal(t, "credentials_unavailable", storedOutcome(t, pool, second.ID))
	require.Equal(t, 2, eventCount(t, pool, "connection.check", "credentials_unavailable"))

	// Without a keyring at all the service fails closed the same way.
	bare, err := NewLocalAuth(pool, s.checker, auth.DefaultSessionTTL)
	require.NoError(t, err)
	_, err = bare.CheckConnection(t.Context(), admin, record.Name)
	code(t, err, auth.CredentialsUnavailable)
	_, err = bare.CreateConnection(t.Context(), admin, connectionRequest("keyless-connection"), false)
	code(t, err, auth.ServiceUnavailable)
	require.Equal(t, 2, countRows(t, pool, "connections"))
}

func TestConnectionOperationsDenyMembersAndRevokedSessions(t *testing.T) {
	pool, s, admin, input := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	member, memberInput := createMember(t, s, admin, "plain-member")
	memberSession := session(t, s, login(t, s, memberInput), auth.CLI)
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	connections := countRows(t, pool, "connections")

	for action, operation := range connectionOperations(t.Context(), s, memberSession, record.Name, false) {
		code(t, operation(), auth.Forbidden)
		require.Equal(t, 1, eventCount(t, pool, action, "forbidden"), action)
		actor, target, sessionID := lastEvent(t, pool, action, "forbidden")
		require.Equal(t, []string{member.ID, "", memberSession.ID}, []string{actor, target, sessionID}, action)
	}
	for action, operation := range connectionOperations(t.Context(), s, revoked, record.Name, false) {
		code(t, operation(), auth.Unauthenticated)
		require.Equal(t, 1, eventCount(t, pool, action, "unauthenticated"), action)
		actor, _, sessionID := lastEvent(t, pool, action, "unauthenticated")
		require.Equal(t, []string{admin.User.ID, revoked.ID}, []string{actor, sessionID}, action)
	}
	events := countRows(t, pool, "auth_events")
	for _, operation := range connectionOperations(t.Context(), s, auth.Session{}, record.Name, false) {
		code(t, operation(), auth.Unauthenticated)
	}
	require.Equal(t, events, countRows(t, pool, "auth_events"), "a caller without a session is not an attempt")
	require.Equal(t, connections, countRows(t, pool, "connections"))
	after, err := s.GetConnection(t.Context(), admin, record.Name)
	require.NoError(t, err)
	require.Equal(t, record, after)
}

func TestConnectionDryRunLeavesNoTrace(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	spare := createConnection(t, s, admin, connectionRequest("spare-connection"))
	_, err := s.SetConnectionEnabled(t.Context(), admin, spare.ID, false, false)
	require.NoError(t, err)
	execSQL(t, pool, `UPDATE connections SET last_check_outcome='reachable', last_check_at=clock_timestamp() WHERE id=$1`, record.ID)
	_, memberInput := createMember(t, s, admin, "watching-member")
	memberSession := session(t, s, login(t, s, memberInput), auth.CLI)
	envelope := storedEnvelope(t, pool, record.ID)
	connections, events := countRows(t, pool, "connections"), countRows(t, pool, "auth_events")

	created, err := s.CreateConnection(t.Context(), admin, connectionRequest("metrics-prod"), true)
	require.NoError(t, err)
	require.True(t, created.DryRun)
	require.Equal(t, "metrics-prod", created.Connection.Name)
	require.True(t, auth.ValidUserID(created.Connection.ID))

	title := "Renamed in a dry run"
	updated, err := s.UpdateConnection(t.Context(), admin, record.Name, auth.UpdateConnectionRequest{Title: &title}, true)
	require.NoError(t, err)
	require.True(t, updated.DryRun)
	require.Equal(t, title, updated.Connection.Title)

	credentials, err := s.SetConnectionCredentials(t.Context(), admin, record.Name, "other-secret", true)
	require.NoError(t, err)
	require.True(t, credentials.DryRun)
	require.Nil(t, credentials.Connection.LastCheck)

	disabled, err := s.SetConnectionEnabled(t.Context(), admin, record.Name, false, true)
	require.NoError(t, err)
	require.True(t, disabled.DryRun)
	require.False(t, disabled.Connection.Enabled)
	enabled, err := s.SetConnectionEnabled(t.Context(), admin, spare.Name, true, true)
	require.NoError(t, err)
	require.True(t, enabled.Connection.Enabled)

	deletion, err := s.DeleteConnection(t.Context(), admin, spare.Name, true)
	require.NoError(t, err)
	require.Equal(t, auth.ConnectionDeletion{ID: spare.ID, Name: spare.Name, Deleted: true, DryRun: true}, deletion)

	// Every denial answers the same way and still leaves nothing behind.
	_, err = s.CreateConnection(t.Context(), admin, connectionRequest("payments-prod"), true)
	code(t, err, auth.ConnectionExists)
	require.Equal(t, hintConnectionExists, hintOf(t, err))
	_, err = s.DeleteConnection(t.Context(), admin, record.Name, true)
	code(t, err, auth.ConnectionInUse)
	_, err = s.UpdateConnection(t.Context(), admin, "missing-connection", auth.UpdateConnectionRequest{Title: &title}, true)
	code(t, err, auth.ConnectionNotFound)
	_, err = s.SetConnectionEnabled(t.Context(), memberSession, record.Name, false, true)
	code(t, err, auth.Forbidden)
	_, err = s.CreateConnection(t.Context(), admin, auth.CreateConnectionRequest{Name: "bad"}, true)
	code(t, err, auth.InvalidArgument)

	require.Equal(t, connections, countRows(t, pool, "connections"))
	require.Equal(t, events, countRows(t, pool, "auth_events"))
	require.Equal(t, envelope, storedEnvelope(t, pool, record.ID))
	require.Equal(t, "reachable", storedOutcome(t, pool, record.ID))
	after, err := s.GetConnection(t.Context(), admin, record.Name)
	require.NoError(t, err)
	require.Equal(t, "Payments", after.Title)
	require.True(t, after.Enabled)
	untouched, err := s.GetConnection(t.Context(), admin, spare.Name)
	require.NoError(t, err)
	require.False(t, untouched.Enabled)
}

func TestListConnectionsOrdersFiltersAndBounds(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	for name, labels := range map[string]map[string]string{
		"payments-prod":  {"env": "prod", "service": "payments"},
		"payments-stage": {"env": "stage", "service": "payments"},
		"metrics-prod":   {"env": "prod", "team": "sre"},
	} {
		request := connectionRequest(name)
		request.Labels = labels
		createConnection(t, s, admin, request)
	}
	all, err := s.ListConnections(t.Context(), admin, nil, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"metrics-prod", "payments-prod", "payments-stage"}, connectionNames(all))
	require.False(t, all.Truncated)
	require.Nil(t, all.Connections[0].LastCheck)
	require.Equal(t, map[string]string{"env": "prod", "team": "sre"}, all.Connections[0].Labels)
	encoded, err := json.Marshal(all)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), sentinelSecret)

	for value, want := range map[string][]string{
		"":                                 {"metrics-prod", "payments-prod", "payments-stage"},
		"env=prod":                         {"metrics-prod", "payments-prod"},
		"env=prod,service!=payments,team":  {"metrics-prod"},
		"service":                          {"payments-prod", "payments-stage"},
		"env=prod,env=stage":               {},
		"env!=prod":                        {"payments-stage"},
		"env=prod,service=payments":        {"payments-prod"},
		"team,service":                     {},
		"env=missing":                      {},
		"service!=payments,service!=other": {"metrics-prod"},
	} {
		list, err := s.ListConnections(t.Context(), admin, selector(t, value), 0)
		require.NoError(t, err, value)
		require.Equal(t, want, connectionNames(list), value)
		require.False(t, list.Truncated, value)
	}
	require.Equal(t, 0, eventCount(t, pool, "connections.list", "success"))
	var recorded int
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth_events WHERE action='connections.list'`).Scan(&recorded))
	require.Zero(t, recorded)

	// Fixture rows only; the listing bound and its flag are the subject.
	execSQL(t, pool, `INSERT INTO connections(id,name,title,provider,target,labels,secret_envelope)
		SELECT gen_random_uuid(), 'bulk-'||lpad(n::text,5,'0'), 'bulk', 'postgresql',
			'{}'::jsonb, '{}'::jsonb, 'v1:fixture' FROM generate_series(1,$1) n`, auth.MaxConnectionListing)
	bounded, err := s.ListConnections(t.Context(), admin, nil, 0)
	require.NoError(t, err)
	require.True(t, bounded.Truncated)
	require.Len(t, bounded.Connections, auth.MaxConnectionListing)
	require.Equal(t, "bulk-00001", bounded.Connections[0].Name)
	for index := 1; index < len(bounded.Connections); index++ {
		require.Less(t, bounded.Connections[index-1].Name, bounded.Connections[index].Name)
	}
	small, err := s.ListConnections(t.Context(), admin, nil, 2)
	require.NoError(t, err)
	require.True(t, small.Truncated)
	require.Len(t, small.Connections, 2)
	over, err := s.ListConnections(t.Context(), admin, nil, auth.MaxConnectionListing*10)
	require.NoError(t, err)
	require.Len(t, over.Connections, auth.MaxConnectionListing)
}

func TestConnectionAuditFailureRollsBack(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	request := connectionRequest("payments-prod")
	request.Target = map[string]string{"url": "postgres://reader@" + closedPort(t) + "/ledger?sslmode=disable"}
	record := createConnection(t, s, admin, request)
	envelope := storedEnvelope(t, pool, record.ID)
	connections, events := countRows(t, pool, "connections"), countRows(t, pool, "auth_events")
	execSQL(t, pool, `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SENTINEL_PRIVATE_DRIVER'; END $$;
		CREATE TRIGGER reject_event BEFORE INSERT ON auth_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)
	for action, operation := range connectionOperations(t.Context(), s, admin, record.Name, false) {
		if action == "connections.list" || action == "connection.get" {
			continue
		}
		err := operation()
		code(t, err, auth.ServiceUnavailable)
		require.NotContains(t, err.Error(), "SENTINEL", action)
	}
	// Reads write no success event, so they keep working.
	list, err := s.ListConnections(t.Context(), admin, nil, 0)
	require.NoError(t, err)
	require.Len(t, list.Connections, 1)
	current, err := s.GetConnection(t.Context(), admin, record.Name)
	require.NoError(t, err)
	require.Equal(t, record, current)
	require.Equal(t, connections, countRows(t, pool, "connections"))
	require.Equal(t, events, countRows(t, pool, "auth_events"))
	require.Equal(t, envelope, storedEnvelope(t, pool, record.ID))
	require.Empty(t, storedOutcome(t, pool, record.ID), "a rolled back check stores no outcome")
	execSQL(t, pool, `DROP TRIGGER reject_event ON auth_events`)
	_, err = s.SetConnectionEnabled(t.Context(), admin, record.Name, false, false)
	require.NoError(t, err)
}

func TestConnectionMutationsSerializeOnTheirAdvisoryKey(t *testing.T) {
	pool, s, admin, _ := connectionFixture(t)
	record := createConnection(t, s, admin, connectionRequest("payments-prod"))
	blocker, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback(context.Background()) }()
	_, err = blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, connectionMutationLock)
	require.NoError(t, err)

	bounded, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancel()
	_, err = s.SetConnectionEnabled(bounded, admin, record.Name, false, false)
	code(t, err, auth.ServiceUnavailable)
	// Reads never take the key, so they answer while a mutation waits.
	list, err := s.ListConnections(t.Context(), admin, nil, 0)
	require.NoError(t, err)
	require.Len(t, list.Connections, 1)
	require.True(t, list.Connections[0].Enabled)

	require.NoError(t, blocker.Rollback(t.Context()))
	result, err := s.SetConnectionEnabled(t.Context(), admin, record.Name, false, false)
	require.NoError(t, err)
	require.False(t, result.Connection.Enabled)
}
