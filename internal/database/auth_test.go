package database

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file is fixture setup, fault injection, or independent
// assertions against persisted state. Application operations use LocalAuth.
func authFixture(t *testing.T) (*pgxpool.Pool, *LocalAuth, auth.LoginInput) {
	t.Helper()
	pool := testPool(t)
	path, password := testSecret(t)
	i := NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	service, err := NewLocalAuth(pool, i, auth.DefaultSessionTTL)
	require.NoError(t, err)
	return pool, service, auth.LoginInput{Username: "personal-admin", Password: password, Kind: auth.CLI, Peer: netip.MustParseAddr("127.0.0.1")}
}

func login(t *testing.T, s *LocalAuth, input auth.LoginInput) auth.LoginResponse {
	t.Helper()
	response, err := s.Login(t.Context(), input)
	require.NoError(t, err)
	require.True(t, auth.ValidToken(response.Token))
	return response
}

func session(t *testing.T, s *LocalAuth, response auth.LoginResponse, kind auth.Kind) auth.Session {
	t.Helper()
	result, err := s.Authenticate(t.Context(), response.Token, kind)
	require.NoError(t, err)
	return result
}

func code(t *testing.T, err error, want string) {
	t.Helper()
	require.Error(t, err)
	_, result := auth.FailureFor(err)
	require.Equal(t, want, result.Error.Code)
}

func TestSessionKindsExpiryCurrentAccountAndRevocation(t *testing.T) {
	pool, s, input := authFixture(t)
	cli := login(t, s, input)
	input.Kind = auth.Browser
	browser := login(t, s, input)
	require.NotEqual(t, cli.Token, browser.Token)
	require.WithinDuration(t, time.Now().Add(8*time.Hour), cli.ExpiresAt, 2*time.Second)
	actor := session(t, s, cli, auth.CLI)
	_, err := s.Authenticate(t.Context(), cli.Token, auth.Browser)
	code(t, err, auth.Unauthenticated)
	_, err = s.Authenticate(t.Context(), browser.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	var digest []byte
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT token_digest FROM sessions WHERE id=$1`, actor.ID).Scan(&digest))
	want := sha256.Sum256([]byte(cli.Token))
	require.Equal(t, want[:], digest)
	execSQL(t, pool, `UPDATE users SET role='member' WHERE id=$1`, actor.User.ID)
	current := session(t, s, cli, auth.CLI)
	require.Equal(t, auth.Member, current.User.Role)
	code(t, s.RevokeUserSessions(t.Context(), actor, actor.User.ID), auth.Forbidden)
	execSQL(t, pool, `UPDATE users SET disabled=true WHERE id=$1`, actor.User.ID)
	_, err = s.Authenticate(t.Context(), cli.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	execSQL(t, pool, `UPDATE users SET disabled=false,role='admin' WHERE id=$1`, actor.User.ID)
	require.NoError(t, s.Logout(t.Context(), actor))
	_, err = s.Authenticate(t.Context(), cli.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	session(t, s, browser, auth.Browser)
	code(t, s.Logout(t.Context(), actor), auth.Unauthenticated)
	input.Kind = auth.CLI
	newCLI := login(t, s, input)
	actor = session(t, s, newCLI, auth.CLI)
	code(t, s.RevokeUserSessions(t.Context(), actor, randomTestID(t)), auth.UserNotFound)
	require.NoError(t, s.RevokeUserSessions(t.Context(), actor, actor.User.ID))
	for _, issued := range []struct {
		response auth.LoginResponse
		kind     auth.Kind
	}{{newCLI, auth.CLI}, {browser, auth.Browser}} {
		_, err = s.Authenticate(t.Context(), issued.response.Token, issued.kind)
		code(t, err, auth.Unauthenticated)
	}
	later := login(t, s, input)
	session(t, s, later, auth.CLI)
	execSQL(t, pool, `UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE revoked_at IS NULL`)
	_, err = s.Authenticate(t.Context(), later.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
}

func TestAuthenticationAuditAtomicityAndRedaction(t *testing.T) {
	pool, s, input := authFixture(t)
	issued := login(t, s, input)
	actor := session(t, s, issued, auth.CLI)
	beforeSessions := countRows(t, pool, "sessions")
	beforeEvents := countRows(t, pool, "auth_events")
	execSQL(t, pool, `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SENTINEL_PRIVATE_DRIVER'; END $$;
		CREATE TRIGGER reject_event BEFORE INSERT ON auth_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)
	_, err := s.Login(t.Context(), input)
	code(t, err, auth.ServiceUnavailable)
	require.NotContains(t, err.Error(), "SENTINEL")
	code(t, s.Logout(t.Context(), actor), auth.ServiceUnavailable)
	code(t, s.RevokeUserSessions(t.Context(), actor, actor.User.ID), auth.ServiceUnavailable)
	require.Equal(t, beforeSessions, countRows(t, pool, "sessions"))
	require.Equal(t, beforeEvents, countRows(t, pool, "auth_events"))
	session(t, s, issued, auth.CLI)
	execSQL(t, pool, `DROP TRIGGER reject_event ON auth_events`)
	input.Username = "unknown-user"
	input.Password = "SENTINEL_PRIVATE_PASSWORD"
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	require.NoError(t, s.RecordEvent(t.Context(), auth.Event{Action: auth.EventLogin, Outcome: auth.OutcomeInvalidArgument}))
	var events string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT json_agg(auth_events)::text FROM auth_events`).Scan(&events))
	require.NotContains(t, events, "SENTINEL")
	require.NotContains(t, events, "unknown-user")
	require.NotContains(t, events, string(input.Password))
	require.NotContains(t, events, string(issued.Token))
	var anonymous int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_events WHERE actor_id IS NULL AND target_id IS NULL AND session_id IS NULL AND action='login'`).Scan(&anonymous))
	require.Equal(t, 2, anonymous)
	code(t, s.RecordEvent(t.Context(), auth.Event{Action: "PRIVATE", Outcome: auth.OutcomeForbidden}), auth.InvalidArgument)
}

func TestSharedThrottleExpiresAndBoundsState(t *testing.T) {
	pool, s, input := authFixture(t)
	replica, err := NewLocalAuth(pool, s.checker, s.ttl)
	require.NoError(t, err)
	input.Password = "not the account password"
	for index := 0; index < 10; index++ {
		service := s
		if index%2 == 1 {
			service = replica
		}
		_, err := service.Login(t.Context(), input)
		code(t, err, auth.InvalidCredentials)
	}
	start := time.Now()
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.RateLimited)
	require.Less(t, time.Since(start), 100*time.Millisecond)
	var failure *auth.Error
	require.ErrorAs(t, err, &failure)
	require.Positive(t, failure.RetryAfter)
	execSQL(t, pool, `UPDATE login_limits SET expires_at=clock_timestamp()-interval '1 second'`)
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	peerKey := sha256.Sum256([]byte("peer:" + input.Peer.String()))
	execSQL(t, pool, `UPDATE login_limits SET failures=50 WHERE key=$1`, peerKey[:])
	input.Username = "different-user"
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.RateLimited)
	execSQL(t, pool, `TRUNCATE login_limits`)
	// Generate deterministic 32-byte keys in SQL, never account credentials.
	execSQL(t, pool, `INSERT INTO login_limits(key,failures,expires_at)
		SELECT decode(lpad(to_hex(n),64,'0'),'hex'),1,clock_timestamp()+interval '5 minutes' FROM generate_series(1,$1) n`, maxLimitRows)
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.RateLimited)
	require.Equal(t, maxLimitRows, countRows(t, pool, "login_limits"))
	execSQL(t, pool, `UPDATE login_limits SET expires_at=clock_timestamp()-interval '1 second'`)
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	require.Equal(t, maxLimitRows-100+2, countRows(t, pool, "login_limits"))
}

func TestAuthLockDeadlinesRollbackAndRecovery(t *testing.T) {
	pool, s, input := authFixture(t)
	issued := login(t, s, input)
	actor := session(t, s, issued, auth.CLI)
	for _, operation := range []string{"login", "logout", "revoke", "authenticate", "audit", "pool"} {
		t.Run(operation, func(t *testing.T) {
			lock, err := pool.Begin(t.Context())
			require.NoError(t, err)
			switch operation {
			case "authenticate":
				_, err = lock.Exec(t.Context(), `LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE`)
			case "audit":
				_, err = lock.Exec(t.Context(), `LOCK TABLE auth_events IN ACCESS EXCLUSIVE MODE`)
			default:
				_, err = lock.Exec(t.Context(), `SELECT id FROM users WHERE id=$1 FOR UPDATE`, actor.User.ID)
			}
			require.NoError(t, err)
			var held []*pgxpool.Conn
			if operation == "pool" {
				for pool.Stat().AcquiredConns() < pool.Config().MaxConns {
					conn, err := pool.Acquire(t.Context())
					require.NoError(t, err)
					held = append(held, conn)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			start := time.Now()
			switch operation {
			case "login", "pool":
				_, err = s.Login(ctx, input)
			case "logout":
				err = s.Logout(ctx, actor)
			case "revoke":
				err = s.RevokeUserSessions(ctx, actor, actor.User.ID)
			case "authenticate":
				_, err = s.Authenticate(ctx, issued.Token, auth.CLI)
			case "audit":
				err = s.RecordEvent(ctx, auth.Event{Action: auth.EventLogin, Outcome: auth.OutcomeForbidden})
			}
			cancel()
			code(t, err, auth.ServiceUnavailable)
			require.Less(t, time.Since(start), time.Second)
			for _, conn := range held {
				conn.Release()
			}
			require.NoError(t, lock.Rollback(t.Context()))
			session(t, s, issued, auth.CLI)
		})
	}
	require.Equal(t, 1, countRows(t, pool, "sessions"))
	require.NoError(t, s.Logout(t.Context(), actor))
}

func TestIssuanceSerializesWithRevocation(t *testing.T) {
	pool, s, input := authFixture(t)
	issued := login(t, s, input)
	actor := session(t, s, issued, auth.CLI)
	lock, err := pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = lock.Exec(t.Context(), `SELECT id FROM users WHERE id=$1 FOR UPDATE`, actor.User.ID)
	require.NoError(t, err)
	type result struct {
		response auth.LoginResponse
		err      error
	}
	done := make(chan result, 1)
	go func() { response, err := s.Login(t.Context(), input); done <- result{response, err} }()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '-- name: LockLoginUser :one%'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&n)
		return err == nil && n > 0
	}, 3*time.Second, 10*time.Millisecond)
	// Simulates an administrator revocation already holding the target row:
	// earlier sessions are revoked; the waiting login commits a distinct session.
	_, err = lock.Exec(t.Context(), `UPDATE sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, actor.User.ID)
	require.NoError(t, err)
	require.NoError(t, audit(t.Context(), lock, actor.User.ID, actor.User.ID, actor.ID, "revoke", "success"))
	require.NoError(t, lock.Commit(t.Context()))
	later := <-done
	require.NoError(t, later.err)
	session(t, s, later.response, auth.CLI)
	_, err = s.Authenticate(t.Context(), issued.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	// And the inverse order: all sessions committed before the real service
	// revoke are denied afterward, including the acting session.
	newActor := session(t, s, later.response, auth.CLI)
	require.NoError(t, s.RevokeUserSessions(t.Context(), newActor, newActor.User.ID))
	_, err = s.Authenticate(t.Context(), later.response.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
}

func TestEscapedMaximumPasswordAgainstRealStore(t *testing.T) {
	pool := testPool(t)
	path, _ := testSecret(t)
	password := auth.Secret(strings.Repeat("\x01", 1024))
	// Generated only inside the test's private temporary secret file.
	require.NoError(t, os.WriteFile(path, []byte(password), 0600))
	i := NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	s, err := NewLocalAuth(pool, i, auth.DefaultSessionTTL)
	require.NoError(t, err)
	data, err := json.Marshal(auth.LoginRequest{Username: "personal-admin", Password: password})
	require.NoError(t, err)
	require.Greater(t, len(data), 4096)
	require.Less(t, len(data), auth.MaxCredentialBody)
	var request auth.LoginRequest
	require.NoError(t, json.Unmarshal(data, &request))
	login(t, s, auth.LoginInput{Username: request.Username, Password: request.Password, Kind: auth.CLI, Peer: netip.MustParseAddr("127.0.0.1")})
}
