package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file moves stored expiries, blocks or deletes users,
// seeds expired rows and reads persisted rows as independent assertions;
// approvals and redemptions go through LocalAuth.

func randomText(t *testing.T) string {
	t.Helper()
	var data [32]byte
	_, err := rand.Read(data[:])
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(data[:])
}

// pkce returns a random verifier and an authorization link carrying its
// challenge, the way a CLI builds them.
func pkce(t *testing.T) (auth.Secret, auth.CLIAuthorization) {
	t.Helper()
	verifier := auth.Secret(randomText(t))
	digest := sha256.Sum256([]byte(verifier))
	return verifier, auth.CLIAuthorization{Port: 49152, Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), State: randomText(t)}
}

// memberBrowser creates a member and signs them in with a browser session,
// the only kind that can approve.
func memberBrowser(t *testing.T, username string) (*pgxpool.Pool, *LocalAuth, auth.Session, auth.Session) {
	t.Helper()
	pool, s, admin, _ := adminFixture(t)
	return pool, s, admin, browserMember(t, s, admin, username)
}

func browserMember(t *testing.T, s *LocalAuth, admin auth.Session, username string) auth.Session {
	t.Helper()
	_, input := createMember(t, s, admin, username)
	input.Kind = auth.Browser
	return session(t, s, login(t, s, input), auth.Browser)
}

func approve(t *testing.T, s *LocalAuth, browser auth.Session, link auth.CLIAuthorization) auth.Secret {
	t.Helper()
	issued, err := s.ApproveCLI(t.Context(), browser, link)
	require.NoError(t, err)
	require.True(t, auth.ValidToken(issued))
	return issued
}

func redeem(t *testing.T, s *LocalAuth, oneTime, verifier auth.Secret) (auth.LoginResponse, error) {
	t.Helper()
	return s.ExchangeCLICode(t.Context(), auth.TokenRequest{Code: oneTime, Verifier: verifier})
}

// Scenario: a member approves a CLI sign-in.
func TestApprovedCodeRedeemsForACLISession(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	verifier, link := pkce(t)
	start := time.Now()
	oneTime := approve(t, s, browser, link)
	var digest, challenge []byte
	var owner string
	var expires time.Time
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT code_digest, user_id::text, challenge, expires_at FROM cli_authorizations`).
		Scan(&digest, &owner, &challenge, &expires))
	want := sha256.Sum256([]byte(oneTime))
	require.Equal(t, want[:], digest, "only the code's digest is stored")
	require.Equal(t, browser.User.ID, owner)
	decoded, err := base64.RawURLEncoding.DecodeString(link.Challenge)
	require.NoError(t, err)
	require.Equal(t, decoded, challenge)
	require.WithinDuration(t, start.Add(auth.CLIAuthorizationLifetime), expires, 2*time.Second)

	issued, err := redeem(t, s, oneTime, verifier)
	require.NoError(t, err)
	require.Equal(t, browser.User, issued.User)
	require.WithinDuration(t, time.Now().Add(auth.DefaultSessionMaxLifetime), issued.ExpiresAt, 2*time.Second)
	require.WithinDuration(t, time.Now().Add(auth.DefaultSessionIdleTimeout), issued.IdleExpiresAt, 2*time.Second)
	cli := session(t, s, issued, auth.CLI)
	require.Equal(t, auth.Member, cli.User.Role)
	_, err = s.Authenticate(t.Context(), issued.Token, auth.Browser)
	code(t, err, auth.Unauthenticated)
	require.Zero(t, countRows(t, pool, "cli_authorizations"))
}

// Only a current browser session approves: a CLI session, a revoked browser
// session and a blocked account store nothing.
func TestApprovalNeedsACurrentBrowserSession(t *testing.T) {
	pool, s, admin, browser := memberBrowser(t, "member-user")
	_, link := pkce(t)
	_, err := s.ApproveCLI(t.Context(), admin, link)
	code(t, err, auth.InvalidArgument)
	require.NoError(t, s.Logout(t.Context(), browser))
	_, err = s.ApproveCLI(t.Context(), browser, link)
	code(t, err, auth.Unauthenticated)
	other := browserMember(t, s, admin, "other-member")
	execSQL(t, pool, `UPDATE users SET disabled = true WHERE id = $1`, other.User.ID)
	_, err = s.ApproveCLI(t.Context(), other, link)
	code(t, err, auth.Unauthenticated)
	require.Zero(t, countRows(t, pool, "cli_authorizations"))
}

// Scenario: code replay.
func TestRedeemedCodeCannotBeReplayed(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	verifier, link := pkce(t)
	oneTime := approve(t, s, browser, link)
	_, err := redeem(t, s, oneTime, verifier)
	require.NoError(t, err)
	sessions := countRows(t, pool, "sessions")
	_, err = redeem(t, s, oneTime, verifier)
	code(t, err, auth.InvalidCredentials)
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
}

// Scenario: a wrong verifier consumes the code.
func TestWrongVerifierConsumesTheCode(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	verifier, link := pkce(t)
	other, _ := pkce(t)
	oneTime := approve(t, s, browser, link)
	sessions := countRows(t, pool, "sessions")
	_, err := redeem(t, s, oneTime, other)
	code(t, err, auth.InvalidCredentials)
	require.Zero(t, countRows(t, pool, "cli_authorizations"), "the refusal is committed")
	_, err = redeem(t, s, oneTime, verifier)
	code(t, err, auth.InvalidCredentials)
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
	// The challenge itself is not a verifier: the comparison hashes first.
	_, link = pkce(t)
	oneTime = approve(t, s, browser, link)
	_, err = redeem(t, s, oneTime, auth.Secret(link.Challenge))
	code(t, err, auth.InvalidCredentials)
}

// Scenario: expired code. A code still inside its lifetime redeems. A hundred
// older expired rows keep the bounded cleanup from reaching the expired code,
// so the redemption's own expiry check is what refuses it.
func TestExpiredCodeIsRefused(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	verifier, link := pkce(t)
	oneTime := approve(t, s, browser, link)
	execSQL(t, pool, `UPDATE cli_authorizations SET expires_at = clock_timestamp() - interval '1 second'`)
	execSQL(t, pool, `INSERT INTO cli_authorizations (code_digest, user_id, challenge, expires_at)
		SELECT decode(lpad(to_hex(n),64,'0'),'hex'), $1, decode(lpad(to_hex(n),64,'0'),'hex'),
			clock_timestamp()-n*interval '1 hour'
		FROM generate_series(1,100) n`, browser.User.ID)
	sessions := countRows(t, pool, "sessions")
	_, err := redeem(t, s, oneTime, verifier)
	code(t, err, auth.InvalidCredentials)
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
	require.Equal(t, 1, countRows(t, pool, "cli_authorizations"), "the expired code outlived the cleanup and was still refused")

	verifier, link = pkce(t)
	oneTime = approve(t, s, browser, link)
	execSQL(t, pool, `UPDATE cli_authorizations SET expires_at = clock_timestamp() + interval '2 seconds'`)
	_, err = redeem(t, s, oneTime, verifier)
	require.NoError(t, err)
}

// Scenario: user blocked after approval. A deleted user's approvals go with
// the account.
func TestBlockedOrDeletedUserCannotRedeem(t *testing.T) {
	pool, s, admin, browser := memberBrowser(t, "member-user")
	verifier, link := pkce(t)
	oneTime := approve(t, s, browser, link)
	execSQL(t, pool, `UPDATE users SET disabled = true WHERE id = $1`, browser.User.ID)
	sessions := countRows(t, pool, "sessions")
	_, err := redeem(t, s, oneTime, verifier)
	code(t, err, auth.InvalidCredentials)
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
	require.Zero(t, countRows(t, pool, "cli_authorizations"), "a refused redemption still consumes the code")

	doomed := browserMember(t, s, admin, "doomed-member")
	verifier, link = pkce(t)
	oneTime = approve(t, s, doomed, link)
	execSQL(t, pool, `DELETE FROM users WHERE id = $1`, doomed.User.ID)
	_, err = redeem(t, s, oneTime, verifier)
	code(t, err, auth.InvalidCredentials)
}

// Malformed input is refused before the database is touched.
func TestExchangeRefusesMalformedInput(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	verifier, link := pkce(t)
	oneTime := approve(t, s, browser, link)
	for _, input := range []auth.TokenRequest{
		{Code: oneTime[:42], Verifier: verifier},
		{Code: oneTime, Verifier: verifier + "A"},
		{Code: "", Verifier: verifier},
	} {
		_, err := s.ExchangeCLICode(t.Context(), input)
		code(t, err, auth.InvalidArgument)
	}
	require.Equal(t, 1, countRows(t, pool, "cli_authorizations"))
}

// seedExpiredAuthorizations inserts count expired rows; row n expired n
// minutes ago, so the largest n are the oldest.
func seedExpiredAuthorizations(t *testing.T, pool *pgxpool.Pool, owner string, count int) {
	t.Helper()
	execSQL(t, pool, `INSERT INTO cli_authorizations (code_digest, user_id, challenge, expires_at)
		SELECT decode(lpad(to_hex(n),64,'0'),'hex'), $1, decode(lpad(to_hex(n),64,'0'),'hex'),
			clock_timestamp()-n*interval '1 minute'
		FROM generate_series(1,$2::int) n`, owner, count)
}

func expiredAuthorizationRange(t *testing.T, pool *pgxpool.Pool) (remaining, newest, oldest int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*),
			coalesce(min(get_byte(code_digest, 31)), 0), coalesce(max(get_byte(code_digest, 31)), 0)
		FROM cli_authorizations WHERE expires_at <= clock_timestamp()`).Scan(&remaining, &newest, &oldest))
	return remaining, newest, oldest
}

// Approval deletes at most 100 expired authorizations, oldest first.
func TestApprovalCleansUpBoundedBatchOfOldestExpiredAuthorizations(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	seedExpiredAuthorizations(t, pool, browser.User.ID, 150)
	_, link := pkce(t)
	approve(t, s, browser, link)
	remaining, newest, oldest := expiredAuthorizationRange(t, pool)
	require.Equal(t, 50, remaining)
	require.Equal(t, 1, newest)
	require.Equal(t, 50, oldest)
	require.Equal(t, 51, countRows(t, pool, "cli_authorizations"))
}

// Redemption deletes a bounded batch of expired authorizations even when it is
// refused, and a successful one also deletes a bounded batch of the oldest
// expired sessions.
func TestExchangeCleansUpAuthorizationsAndSessions(t *testing.T) {
	pool, s, _, browser := memberBrowser(t, "member-user")
	seedExpiredAuthorizations(t, pool, browser.User.ID, 150)
	_, err := redeem(t, s, auth.Secret(randomText(t)), auth.Secret(randomText(t)))
	code(t, err, auth.InvalidCredentials)
	remaining, newest, oldest := expiredAuthorizationRange(t, pool)
	require.Equal(t, []int{50, 1, 50}, []int{remaining, newest, oldest})

	execSQL(t, pool, `INSERT INTO sessions (id, token_digest, user_id, kind, expires_at, max_expires_at)
		SELECT gen_random_uuid(), decode(lpad(to_hex(n),64,'0'),'hex'), $1, 'cli',
			clock_timestamp()-n*interval '1 minute', clock_timestamp()-n*interval '1 minute'
		FROM generate_series(1,150) n`, browser.User.ID)
	verifier, link := pkce(t)
	oneTime := approve(t, s, browser, link)
	sessions := countRows(t, pool, "sessions")
	_, err = redeem(t, s, oneTime, verifier)
	require.NoError(t, err)
	require.Equal(t, sessions-100+1, countRows(t, pool, "sessions"))
	var expired, newestSession int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*), coalesce(max(get_byte(token_digest, 31)), 0)
		FROM sessions WHERE expires_at <= clock_timestamp()`).Scan(&expired, &newestSession))
	require.Equal(t, 50, expired)
	require.Equal(t, 50, newestSession, "the 100 oldest expired sessions were deleted")
}
