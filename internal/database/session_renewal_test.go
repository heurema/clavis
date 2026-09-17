package database

import (
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file moves stored expiries to simulate elapsed time and
// reads them back as independent assertions; sessions are issued and used only
// through LocalAuth.

type storedSession struct {
	idle, cap time.Time
	version   string
	revoked   bool
}

func stored(t *testing.T, pool *pgxpool.Pool, id string) storedSession {
	t.Helper()
	var row storedSession
	// xmin changes with every write to the row, so it proves a write happened
	// even when the written value equals the previous one.
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT expires_at, max_expires_at, xmin::text, revoked_at IS NOT NULL
		FROM sessions WHERE id=$1`, id).Scan(&row.idle, &row.cap, &row.version, &row.revoked))
	return row
}

// place sets the idle expiry to now plus idleIn and the cap to now plus capIn.
func place(t *testing.T, pool *pgxpool.Pool, id string, idleIn, capIn time.Duration) {
	t.Helper()
	execSQL(t, pool, `UPDATE sessions SET expires_at=clock_timestamp()+$2::double precision*interval '1 second',
		max_expires_at=clock_timestamp()+$3::double precision*interval '1 second' WHERE id=$1`,
		id, idleIn.Seconds(), capIn.Seconds())
}

func renewalFixture(t *testing.T) (*pgxpool.Pool, *LocalAuth, auth.LoginResponse, auth.Session) {
	t.Helper()
	pool, s, input := authFixture(t)
	issued := login(t, s, input)
	return pool, s, issued, session(t, s, issued, auth.CLI)
}

const day = 24 * time.Hour

func TestSessionIssuedWithIdleAndAbsoluteExpiry(t *testing.T) {
	pool, _, issued, current := renewalFixture(t)
	row := stored(t, pool, current.ID)
	require.Equal(t, auth.DefaultSessionMaxLifetime-auth.DefaultSessionIdleTimeout, row.cap.Sub(row.idle))
	require.True(t, issued.ExpiresAt.Equal(row.cap))
	require.True(t, issued.IdleExpiresAt.Equal(row.idle))
	require.True(t, current.ExpiresAt.Equal(row.cap), "the absolute expiry is reported as expiresAt")
	require.True(t, current.IdleExpiresAt.Equal(row.idle))
	require.Equal(t, time.UTC, current.ExpiresAt.Location())
	require.Equal(t, time.UTC, current.IdleExpiresAt.Location())
}

// Scenario: a used session renews.
func TestUsedSessionRenewsWithCapUnchanged(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	// Four days after its last renewal, three days of a seven-day window remain.
	place(t, pool, current.ID, 3*day, 26*day)
	before := stored(t, pool, current.ID)
	start := time.Now()
	renewed := session(t, s, issued, auth.CLI)
	after := stored(t, pool, current.ID)
	require.NotEqual(t, before.version, after.version)
	require.WithinDuration(t, start.Add(auth.DefaultSessionIdleTimeout), after.idle, 2*time.Second)
	require.True(t, after.cap.Equal(before.cap), "the absolute expiry never changes")
	require.True(t, renewed.IdleExpiresAt.Equal(after.idle), "the result reports the renewed idle expiry")
	require.True(t, renewed.ExpiresAt.Equal(before.cap))
	require.Equal(t, current.ID, renewed.ID)
	require.Equal(t, current.User, renewed.User)
}

// Scenario: frequent use does not write on every request.
func TestFrequentUseDoesNotWrite(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	for name, remaining := range map[string]time.Duration{
		"an hour after renewal": auth.DefaultSessionIdleTimeout - time.Hour,
		// Just over half the window remains: the half-window guard still holds.
		"just before half the window": auth.DefaultSessionIdleTimeout/2 + time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			place(t, pool, current.ID, remaining, 20*day)
			before := stored(t, pool, current.ID)
			for range 3 {
				used := session(t, s, issued, auth.CLI)
				require.True(t, used.IdleExpiresAt.Equal(before.idle))
			}
			require.Equal(t, before, stored(t, pool, current.ID))
		})
	}
}

// Scenario: renewal stops at the cap.
func TestRenewalStopsAtTheCap(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	place(t, pool, current.ID, day, 2*day)
	before := stored(t, pool, current.ID)
	renewed := session(t, s, issued, auth.CLI)
	capped := stored(t, pool, current.ID)
	require.True(t, capped.idle.Equal(before.cap), "the idle expiry becomes the absolute expiry")
	require.True(t, capped.cap.Equal(before.cap))
	require.True(t, renewed.IdleExpiresAt.Equal(renewed.ExpiresAt))
	// A session at its cap is not rewritten on every request.
	for range 3 {
		session(t, s, issued, auth.CLI)
	}
	require.Equal(t, capped, stored(t, pool, current.ID))
	// Once the cap passes the session is denied, however often it is used.
	execSQL(t, pool, `UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second',
		max_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, current.ID)
	expired := stored(t, pool, current.ID)
	for range 3 {
		_, err := s.Authenticate(t.Context(), issued.Token, auth.CLI)
		code(t, err, auth.Unauthenticated)
	}
	require.Equal(t, expired, stored(t, pool, current.ID))
}

// Scenario: an unused session expires before its cap.
func TestUnusedSessionExpiresBeforeItsCap(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	place(t, pool, current.ID, -time.Second, 20*day)
	before := stored(t, pool, current.ID)
	_, err := s.Authenticate(t.Context(), issued.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	require.Equal(t, before, stored(t, pool, current.ID), "an expired session is never renewed")
}

// A disabled account's session is denied and never renewed, even when renewal
// is due; enabling the account again makes the untouched session usable.
func TestDisabledUserIsNeverRenewed(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	place(t, pool, current.ID, time.Hour, 20*day)
	execSQL(t, pool, `UPDATE users SET disabled=true WHERE id=$1`, current.User.ID)
	before := stored(t, pool, current.ID)
	_, err := s.Authenticate(t.Context(), issued.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	require.Equal(t, before, stored(t, pool, current.ID))
	execSQL(t, pool, `UPDATE users SET disabled=false WHERE id=$1`, current.User.ID)
	session(t, s, issued, auth.CLI)
	require.NotEqual(t, before.version, stored(t, pool, current.ID).version)
}

// A revoked session due for renewal is denied and its expiry is not written.
func TestRevokedSessionIsNeverRenewed(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	place(t, pool, current.ID, time.Hour, 20*day)
	execSQL(t, pool, `UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1`, current.ID)
	before := stored(t, pool, current.ID)
	_, err := s.Authenticate(t.Context(), issued.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	require.Equal(t, before, stored(t, pool, current.ID))
	// Another kind never renews the session either.
	execSQL(t, pool, `UPDATE sessions SET revoked_at=NULL WHERE id=$1`, current.ID)
	before = stored(t, pool, current.ID)
	_, err = s.Authenticate(t.Context(), issued.Token, auth.Browser)
	code(t, err, auth.Unauthenticated)
	require.Equal(t, before, stored(t, pool, current.ID))
}

// Scenario: revocation races a renewal. The revocation holds the session row
// while the renewal waits on it; once the revocation commits, the waiting
// update re-evaluates the row, skips it, and the session stays revoked.
func TestRevocationCommittedWhileRenewalWaits(t *testing.T) {
	pool, s, issued, current := renewalFixture(t)
	place(t, pool, current.ID, time.Hour, 20*day)
	before := stored(t, pool, current.ID)
	revocation, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer rollback(t.Context(), revocation)
	_, err = revocation.Exec(t.Context(), `UPDATE sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, current.User.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := s.Authenticate(t.Context(), issued.Token, auth.CLI); done <- err }()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '-- name: RenewSession :one%'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&n)
		return err == nil && n > 0
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, revocation.Commit(t.Context()))
	code(t, <-done, auth.Unauthenticated)
	after := stored(t, pool, current.ID)
	require.True(t, after.revoked)
	require.True(t, after.idle.Equal(before.idle), "the waiting renewal wrote nothing")
	require.True(t, after.cap.Equal(before.cap))
	for range 3 {
		_, err := s.Authenticate(t.Context(), issued.Token, auth.CLI)
		code(t, err, auth.Unauthenticated)
	}
}

// Scenario: expired sessions are cleaned up. A sign-in deletes at most 100
// expired sessions, oldest first, and keeps every session still in its idle
// window, revoked or not.
func TestLoginCleansUpBoundedBatchOfOldestExpiredSessions(t *testing.T) {
	pool, s, input := authFixture(t)
	issued := login(t, s, input)
	owner := session(t, s, issued, auth.CLI).User.ID
	// Deterministic 32-byte digests generated in SQL, never real tokens. Session
	// n expired n minutes ago, so the largest n are the oldest.
	execSQL(t, pool, `INSERT INTO sessions (id, token_digest, user_id, kind, expires_at, max_expires_at)
		SELECT gen_random_uuid(), decode(lpad(to_hex(n),64,'0'),'hex'), $1, 'cli',
			clock_timestamp()-n*interval '1 minute', clock_timestamp()-n*interval '1 minute'
		FROM generate_series(1,150) n`, owner)
	execSQL(t, pool, `INSERT INTO sessions (id, token_digest, user_id, kind, expires_at, max_expires_at, revoked_at)
		SELECT gen_random_uuid(), decode(lpad(to_hex(n),64,'0'),'hex'), $1, 'browser',
			clock_timestamp()+interval '1 hour', clock_timestamp()+interval '1 day', clock_timestamp()
		FROM generate_series(1001,1005) n`, owner)
	before := countRows(t, pool, "sessions")
	later := browserLogin(t, s, input)
	session(t, s, later, auth.Browser)
	session(t, s, issued, auth.CLI)
	require.Equal(t, before-100+1, countRows(t, pool, "sessions"))
	var remaining, newest, oldest, revoked int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*),
			coalesce(min(get_byte(token_digest, 31)), 0), coalesce(max(get_byte(token_digest, 31)), 0),
			(SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL AND expires_at > clock_timestamp())
		FROM sessions WHERE expires_at <= clock_timestamp()`).Scan(&remaining, &newest, &oldest, &revoked))
	require.Equal(t, 50, remaining)
	require.Equal(t, 1, newest)
	require.Equal(t, 50, oldest, "the 100 oldest expired sessions were deleted")
	require.Equal(t, 5, revoked, "revoked sessions still in their idle window are kept")
}

// A refused sign-in still commits the bounded cleanup it ran first.
func TestRefusedLoginStillCleansUpExpiredSessions(t *testing.T) {
	pool, s, input := authFixture(t)
	issued := browserLogin(t, s, input)
	owner := session(t, s, issued, auth.Browser).User.ID
	execSQL(t, pool, `INSERT INTO sessions (id, token_digest, user_id, kind, expires_at, max_expires_at)
		SELECT gen_random_uuid(), decode(lpad(to_hex(n),64,'0'),'hex'), $1, 'cli',
			clock_timestamp()-interval '1 minute', clock_timestamp()-interval '1 minute'
		FROM generate_series(1,3) n`, owner)
	input.Password = "not the account password"
	_, err := s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	require.Equal(t, 1, countRows(t, pool, "sessions"))
}

func TestLocalAuthRejectsInvalidSessionDurations(t *testing.T) {
	checker := NewInitializer(nil, "", "")
	for _, tc := range []struct{ idle, lifetime time.Duration }{
		{240 * time.Hour, 168 * time.Hour},
		{auth.MinSessionDuration - time.Second, time.Hour},
		{time.Hour, auth.MaxSessionDuration + time.Second},
		{0, 0},
	} {
		_, err := NewLocalAuth(nil, checker, tc.idle, tc.lifetime)
		code(t, err, auth.InvalidArgument, "%v %v", tc.idle, tc.lifetime)
	}
	_, err := NewLocalAuth(nil, nil, auth.DefaultSessionIdleTimeout, auth.DefaultSessionMaxLifetime)
	code(t, err, auth.InvalidArgument)
	service, err := NewLocalAuth(nil, checker, auth.MinSessionDuration, auth.MinSessionDuration)
	require.NoError(t, err)
	require.Equal(t, auth.MinSessionDuration, service.lifetime)
}

// Scenario: upgrade revokes existing sessions. Migration 008 runs on an
// initialized installation holding sessions from the fixed lifetime: every
// one of them is refused afterwards, the new column satisfies its check, and a
// new sign-in succeeds.
func TestSessionRenewalMigrationRevokesExistingSessions(t *testing.T) {
	pool := testPool(t)
	previous := embeddedMapFS(t)
	delete(previous, "008_session_renewal_and_cli_authorization.sql")
	require.NoError(t, migrateFS(t.Context(), pool, previous))
	path, password := testSecret(t)
	hash, err := auth.HashPassword(t.Context(), password)
	require.NoError(t, err)
	admin := randomTestID(t)
	execSQL(t, pool, `INSERT INTO users(id,username,password_hash,role) VALUES ($1,'personal-admin',$2,'admin')`, admin, hash)
	execSQL(t, pool, `INSERT INTO installation(singleton,initialized_at) VALUES (true, clock_timestamp())`)
	// Valid-looking tokens whose digests the previous release stored.
	tokens := map[auth.Kind]auth.Secret{}
	for _, kind := range []auth.Kind{auth.CLI, auth.Browser} {
		_, secret := testSecret(t)
		token := secret
		tokens[kind] = token
		require.True(t, auth.ValidToken(token))
		digest := sha256.Sum256([]byte(token))
		execSQL(t, pool, `INSERT INTO sessions (id, token_digest, user_id, kind, expires_at)
			VALUES ($1, $2, $3, $4, clock_timestamp()+interval '8 hours')`, randomTestID(t), digest[:], admin, string(kind))
	}
	revokedEarlier := randomTestID(t)
	execSQL(t, pool, `INSERT INTO sessions (id, token_digest, user_id, kind, expires_at, revoked_at)
		VALUES ($1, decode(repeat('ab',32),'hex'), $2, 'cli', clock_timestamp()+interval '1 hour', '2026-01-01T00:00:00Z')`, revokedEarlier, admin)

	i := NewInitializer(pool, "personal-admin", path)
	require.Equal(t, platform.Initializing, i.Check(t.Context()).State)
	require.Equal(t, platform.Ready, i.Attempt(t.Context()).State)
	require.Equal(t, platform.Ready, i.Check(t.Context()).State)
	require.Equal(t, appliedLedgerRows(), countRows(t, pool, "goose_db_version"))

	var unrevoked, uncapped int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE revoked_at IS NULL),
		count(*) FILTER (WHERE max_expires_at <> expires_at) FROM sessions`).Scan(&unrevoked, &uncapped))
	require.Zero(t, unrevoked, "every existing session is revoked")
	require.Zero(t, uncapped, "the cap is backfilled from the old expiry")
	var revokedAt time.Time
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT revoked_at FROM sessions WHERE id=$1`, revokedEarlier).Scan(&revokedAt))
	require.True(t, revokedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), "an earlier revocation keeps its time")

	var refused *pgconn.PgError
	_, err = pool.Exec(t.Context(), `UPDATE sessions SET expires_at=max_expires_at+interval '1 second' WHERE id=$1`, revokedEarlier)
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "23514", refused.Code, "the idle expiry may not pass the cap")
	var indexed, authorizations, authorizationsIndexed bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('sessions_expires_at') IS NOT NULL,
		to_regclass('cli_authorizations') IS NOT NULL, to_regclass('cli_authorizations_expiry') IS NOT NULL`).
		Scan(&indexed, &authorizations, &authorizationsIndexed))
	require.True(t, indexed)
	require.True(t, authorizations)
	require.True(t, authorizationsIndexed)
	_, err = pool.Exec(t.Context(), `INSERT INTO cli_authorizations (code_digest, user_id, challenge, expires_at)
		VALUES (decode(repeat('01',31),'hex'), $1, decode(repeat('02',32),'hex'), clock_timestamp())`, admin)
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "23514", refused.Code, "a code digest is 32 bytes")

	s, err := NewLocalAuth(pool, i, auth.DefaultSessionIdleTimeout, auth.DefaultSessionMaxLifetime)
	require.NoError(t, err)
	for kind, token := range tokens {
		_, err := s.Authenticate(t.Context(), token, kind)
		code(t, err, auth.Unauthenticated, kind)
	}
	fresh := login(t, s, auth.LoginInput{Username: "personal-admin", Password: password, Peer: netip.MustParseAddr("127.0.0.1")})
	session(t, s, fresh, auth.CLI)
}
