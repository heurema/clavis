package database

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Direct SQL in this file is fixture setup, fault injection, or independent
// assertions against persisted state. Application operations use LocalAuth.
func adminFixture(t *testing.T) (*pgxpool.Pool, *LocalAuth, auth.Session, auth.LoginInput) {
	t.Helper()
	pool, s, input := authFixture(t)
	return pool, s, session(t, s, login(t, s, input), auth.CLI), input
}

func randomPassword(t *testing.T) auth.Secret {
	t.Helper()
	var data [24]byte
	_, err := rand.Read(data[:])
	require.NoError(t, err)
	return auth.Secret(base64.RawURLEncoding.EncodeToString(data[:]))
}

func createMember(t *testing.T, s *LocalAuth, actor auth.Session, username string) (auth.UserRecord, auth.LoginInput) {
	t.Helper()
	password := randomPassword(t)
	record, err := s.CreateUser(t.Context(), actor, auth.CreateUserRequest{Username: username, Password: password})
	require.NoError(t, err)
	input := auth.LoginInput{Username: username, Password: password, Kind: auth.CLI, Peer: actorPeer}
	return record, input
}

var actorPeer = netip.MustParseAddr("127.0.0.1")

func enabledAdmins(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled`).Scan(&count))
	return count
}

func userState(t *testing.T, pool *pgxpool.Pool, id string) (role string, disabled bool) {
	t.Helper()
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT role, disabled FROM users WHERE id=$1`, id).Scan(&role, &disabled))
	return role, disabled
}

func TestCreateUserSignsInOnBothTransports(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	before := countRows(t, pool, "users")
	for _, invalid := range []auth.CreateUserRequest{
		{Username: "Bad", Password: "a valid test password"},
		{Username: "valid-name", Password: "short"},
		{Username: "valid-name", Password: auth.Secret("line\nbreak password!")},
	} {
		_, err := s.CreateUser(t.Context(), admin, invalid)
		code(t, err, auth.InvalidArgument)
	}
	require.Equal(t, before, countRows(t, pool, "users"))
	record, input := createMember(t, s, admin, "member-one")
	require.True(t, auth.ValidUserID(record.ID))
	require.Equal(t, "member-one", record.Username)
	require.Equal(t, auth.Member, record.Role)
	require.False(t, record.Disabled)
	require.Equal(t, time.UTC, record.CreatedAt.Location())
	require.WithinDuration(t, time.Now(), record.CreatedAt, 5*time.Second)
	cli := login(t, s, input)
	require.Equal(t, record.ID, cli.User.ID)
	require.Equal(t, auth.Member, cli.User.Role)
	input.Kind = auth.Browser
	browser := login(t, s, input)
	session(t, s, cli, auth.CLI)
	session(t, s, browser, auth.Browser)
	input.Password = "not the member password"
	_, err := s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	users := countRows(t, pool, "users")
	_, err = s.CreateUser(t.Context(), admin, auth.CreateUserRequest{Username: "member-one", Password: randomPassword(t)})
	code(t, err, auth.UsernameTaken)
	require.Equal(t, users, countRows(t, pool, "users"))
}

func TestCreateUserMapsUniqueViolationUnderRace(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	// Simulates a row committed outside the administration lock (fixture or
	// bootstrap): the existence check passes, the unique index wins.
	racer, err := pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = racer.Exec(t.Context(), `INSERT INTO users(id,username,password_hash,role) VALUES(gen_random_uuid(),'racer',$1,'member')`, auth.DummyPasswordHash())
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateUser(t.Context(), admin, auth.CreateUserRequest{Username: "racer", Password: randomPassword(t)})
		done <- err
	}()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '-- name: InsertUser :one%'`,
			pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&n)
		return err == nil && n > 0
	}, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, racer.Commit(t.Context()))
	code(t, <-done, auth.UsernameTaken)
	var n int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE username='racer'`).Scan(&n))
	require.Equal(t, 1, n)
}

func TestAdministrationDeniesMembersRevokedSessionsAndUnknownTargets(t *testing.T) {
	pool, s, admin, input := adminFixture(t)
	member, memberInput := createMember(t, s, admin, "plain-member")
	memberSession := session(t, s, login(t, s, memberInput), auth.CLI)
	revoked := session(t, s, login(t, s, input), auth.CLI)
	require.NoError(t, s.Logout(t.Context(), revoked))
	operations := func(actor auth.Session, target string) map[string]func() error {
		return map[string]func() error{
			"users.list": func() error { _, err := s.ListUsers(t.Context(), actor); return err },
			"user.create": func() error {
				_, err := s.CreateUser(t.Context(), actor, auth.CreateUserRequest{Username: "denied-user", Password: randomPassword(t)})
				return err
			},
			"user.block":          func() error { _, err := s.SetUserDisabled(t.Context(), actor, target, true); return err },
			"user.unblock":        func() error { _, err := s.SetUserDisabled(t.Context(), actor, target, false); return err },
			"user.reset_password": func() error { _, err := s.ResetPassword(t.Context(), actor, target, randomPassword(t)); return err },
			"user.promote":        func() error { _, err := s.SetRole(t.Context(), actor, target, auth.Admin); return err },
			"user.demote":         func() error { _, err := s.SetRole(t.Context(), actor, target, auth.Member); return err },
		}
	}
	users, sessions := countRows(t, pool, "users"), countRows(t, pool, "sessions")
	for action, operation := range operations(memberSession, admin.User.ID) {
		code(t, operation(), auth.Forbidden, action)
	}
	for action, operation := range operations(revoked, member.ID) {
		code(t, operation(), auth.Unauthenticated, action)
	}
	unknown := randomTestID(t)
	for action, operation := range operations(admin, unknown) {
		if action == "users.list" || action == "user.create" {
			continue
		}
		code(t, operation(), auth.UserNotFound, action)
	}
	for _, operation := range operations(auth.Session{}, member.ID) {
		code(t, operation(), auth.Unauthenticated)
	}
	// A reference that is neither a UUID nor a username is refused before the
	// transaction, so it is not an attempt and changes nothing.
	_, err := s.SetUserDisabled(t.Context(), admin, "Not A Ref", true)
	code(t, err, auth.InvalidArgument)
	_, err = s.SetRole(t.Context(), admin, member.ID, auth.Role("owner"))
	code(t, err, auth.InvalidArgument)
	_, err = s.ResetPassword(t.Context(), admin, member.ID, "short")
	code(t, err, auth.InvalidArgument)
	require.Equal(t, users, countRows(t, pool, "users"))
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
	role, disabled := userState(t, pool, admin.User.ID)
	require.Equal(t, "admin", role)
	require.False(t, disabled)
	role, disabled = userState(t, pool, member.ID)
	require.Equal(t, "member", role)
	require.False(t, disabled)
	require.Equal(t, 1, enabledAdmins(t, pool))
}

func TestUserMutationsAcceptUsernameReferences(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	member, input := createMember(t, s, admin, "named-member")
	cli := session(t, s, login(t, s, input), auth.CLI)

	blocked, err := s.SetUserDisabled(t.Context(), admin, "named-member", true)
	require.NoError(t, err)
	require.Equal(t, member.ID, blocked.User.ID)
	require.True(t, blocked.User.Disabled)
	require.True(t, blocked.SessionsRevoked)
	blockedRole, blockedDisabled := userState(t, pool, member.ID)
	require.Equal(t, "member", blockedRole)
	require.True(t, blockedDisabled)
	_, err = s.ListUsers(t.Context(), cli)
	code(t, err, auth.Unauthenticated)

	_, err = s.SetUserDisabled(t.Context(), admin, "named-member", false)
	require.NoError(t, err)
	promoted, err := s.SetRole(t.Context(), admin, "named-member", auth.Admin)
	require.NoError(t, err)
	require.Equal(t, auth.Admin, promoted.User.Role)
	require.Equal(t, member.ID, promoted.User.ID)
	_, err = s.SetRole(t.Context(), admin, "named-member", auth.Member)
	require.NoError(t, err)
	newPassword := randomPassword(t)
	reset, err := s.ResetPassword(t.Context(), admin, "named-member", newPassword)
	require.NoError(t, err)
	require.Equal(t, member.ID, reset.User.ID)
	input.Password = newPassword
	renewed := login(t, s, input)
	session(t, s, renewed, auth.CLI)
	require.NoError(t, s.RevokeUserSessions(t.Context(), admin, "named-member"))
	// The username resolved to the member: their session is gone while the
	// administrator's own session is untouched.
	_, err = s.Authenticate(t.Context(), renewed.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	_, err = s.ListUsers(t.Context(), admin)
	require.NoError(t, err)
	role, disabled := userState(t, pool, member.ID)
	require.Equal(t, "member", role)
	require.False(t, disabled)

	// An unknown username is the denial an unknown UUID has always produced.
	unknown := map[string]func(string) error{
		"user.block": func(ref string) error { _, err := s.SetUserDisabled(t.Context(), admin, ref, true); return err },
		"user.reset_password": func(ref string) error {
			_, err := s.ResetPassword(t.Context(), admin, ref, randomPassword(t))
			return err
		},
		"user.promote": func(ref string) error { _, err := s.SetRole(t.Context(), admin, ref, auth.Admin); return err },
		"revoke":       func(ref string) error { return s.RevokeUserSessions(t.Context(), admin, ref) },
	}
	for action, operation := range unknown {
		code(t, operation("nobody-here"), auth.UserNotFound, action)
	}
	// A reference that is neither form is refused before the transaction, so
	// it is not an attempt and changes nothing.
	for _, operation := range unknown {
		code(t, operation("Not A Ref"), auth.InvalidArgument)
	}
	require.Equal(t, 2, countRows(t, pool, "users"))
}

func TestBlockRevokesSessionsAndUnblockRestoresLogin(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	member, input := createMember(t, s, admin, "blocked-member")
	cli := login(t, s, input)
	input.Kind = auth.Browser
	browser := login(t, s, input)
	blocked, err := s.SetUserDisabled(t.Context(), admin, member.ID, true)
	require.NoError(t, err)
	require.True(t, blocked.SessionsRevoked)
	require.True(t, blocked.User.Disabled)
	require.Equal(t, member.ID, blocked.User.ID)
	denied := func() {
		t.Helper()
		_, err := s.Authenticate(t.Context(), cli.Token, auth.CLI)
		code(t, err, auth.Unauthenticated)
		_, err = s.Authenticate(t.Context(), browser.Token, auth.Browser)
		code(t, err, auth.Unauthenticated)
	}
	denied()
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	again, err := s.SetUserDisabled(t.Context(), admin, member.ID, true)
	require.NoError(t, err)
	require.True(t, again.SessionsRevoked)
	require.True(t, again.User.Disabled)
	// The repeated block is a no-op on the row it already wrote.
	role, disabled := userState(t, pool, member.ID)
	require.Equal(t, "member", role)
	require.True(t, disabled)
	unblocked, err := s.SetUserDisabled(t.Context(), admin, member.ID, false)
	require.NoError(t, err)
	require.False(t, unblocked.SessionsRevoked)
	require.False(t, unblocked.User.Disabled)
	denied()
	later := login(t, s, input)
	session(t, s, later, auth.Browser)
	idempotent, err := s.SetUserDisabled(t.Context(), admin, member.ID, false)
	require.NoError(t, err)
	require.False(t, idempotent.SessionsRevoked)
	require.False(t, idempotent.User.Disabled)
	role, disabled = userState(t, pool, member.ID)
	require.Equal(t, "member", role)
	require.False(t, disabled)
	session(t, s, later, auth.Browser)
}

func TestResetPasswordRevokesSessionsAndRedacts(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	created, err := s.CreateUser(t.Context(), admin, auth.CreateUserRequest{Username: "reset-member", Password: "SENTINEL_PRIVATE_CREATE_PASSWORD"})
	require.NoError(t, err)
	old := auth.LoginInput{Username: "reset-member", Password: "SENTINEL_PRIVATE_CREATE_PASSWORD", Kind: auth.CLI, Peer: actorPeer}
	cli := login(t, s, old)
	old.Kind = auth.Browser
	browser := login(t, s, old)
	newPassword := auth.Secret("SENTINEL_PRIVATE_NEW_PASSWORD")
	reset, err := s.ResetPassword(t.Context(), admin, created.ID, newPassword)
	require.NoError(t, err)
	require.True(t, reset.SessionsRevoked)
	require.Equal(t, created, reset.User)
	encoded, err := json.Marshal(reset)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "$clavis$")
	require.NotContains(t, string(encoded), "SENTINEL")
	require.NotContains(t, strings.ToLower(string(encoded)), "password")
	_, err = s.Authenticate(t.Context(), cli.Token, auth.CLI)
	code(t, err, auth.Unauthenticated)
	_, err = s.Authenticate(t.Context(), browser.Token, auth.Browser)
	code(t, err, auth.Unauthenticated)
	_, err = s.Login(t.Context(), old)
	code(t, err, auth.InvalidCredentials)
	old.Password = newPassword
	session(t, s, login(t, s, old), auth.Browser)
	_, err = s.ResetPassword(t.Context(), admin, randomTestID(t), newPassword)
	code(t, err, auth.UserNotFound)
	require.NotContains(t, err.Error(), "SENTINEL")
	var users string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT json_agg(users)::text FROM users`).Scan(&users))
	require.NotContains(t, users, "SENTINEL")
	var hash string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`, created.ID).Scan(&hash))
	require.True(t, strings.HasPrefix(hash, "$clavis$1$argon2id$"))
}

func TestRoleChangesApplyToExistingSessions(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	member, input := createMember(t, s, admin, "rising-member")
	memberSession := session(t, s, login(t, s, input), auth.CLI)
	_, err := s.ListUsers(t.Context(), memberSession)
	code(t, err, auth.Forbidden)
	promoted, err := s.SetRole(t.Context(), admin, member.ID, auth.Admin)
	require.NoError(t, err)
	require.False(t, promoted.SessionsRevoked)
	require.Equal(t, auth.Admin, promoted.User.Role)
	// The same session is authorized now: authority is read from the account.
	list, err := s.ListUsers(t.Context(), memberSession)
	require.NoError(t, err)
	require.Len(t, list.Users, 2)
	again, err := s.SetRole(t.Context(), admin, member.ID, auth.Admin)
	require.NoError(t, err)
	require.Equal(t, auth.Admin, again.User.Role)
	// The repeated promotion is a no-op on the row it already wrote.
	role, disabled := userState(t, pool, member.ID)
	require.Equal(t, "admin", role)
	require.False(t, disabled)
	demoted, err := s.SetRole(t.Context(), admin, member.ID, auth.Member)
	require.NoError(t, err)
	require.False(t, demoted.SessionsRevoked)
	require.Equal(t, auth.Member, demoted.User.Role)
	_, err = s.ListUsers(t.Context(), memberSession)
	code(t, err, auth.Forbidden)
	_, err = s.SetRole(t.Context(), memberSession, admin.User.ID, auth.Member)
	code(t, err, auth.Forbidden)
	identity, err := s.Authenticate(t.Context(), login(t, s, input).Token, auth.CLI)
	require.NoError(t, err)
	require.Equal(t, auth.Member, identity.User.Role)
	role, disabled = userState(t, pool, member.ID)
	require.Equal(t, "member", role)
	require.False(t, disabled)
}

func TestSelfTargetingIsRefusedExceptPasswordReset(t *testing.T) {
	pool, s, admin, input := adminFixture(t)
	other, _ := createMember(t, s, admin, "second-admin")
	_, err := s.SetRole(t.Context(), admin, other.ID, auth.Admin)
	require.NoError(t, err)
	sessions := countRows(t, pool, "sessions")
	// Even with another enabled administrator present, nobody removes themself,
	// whichever spelling of their own reference they use.
	for _, self := range []string{admin.User.ID, admin.User.Username} {
		_, err = s.SetUserDisabled(t.Context(), admin, self, true)
		code(t, err, auth.SelfTarget)
		_, err = s.SetRole(t.Context(), admin, self, auth.Member)
		code(t, err, auth.SelfTarget)
	}
	role, disabled := userState(t, pool, admin.User.ID)
	require.Equal(t, "admin", role)
	require.False(t, disabled)
	require.Equal(t, 2, enabledAdmins(t, pool))
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
	// Idempotent self promotion and self unblock are not removals.
	promoted, err := s.SetRole(t.Context(), admin, admin.User.ID, auth.Admin)
	require.NoError(t, err)
	require.Equal(t, auth.Admin, promoted.User.Role)
	unblocked, err := s.SetUserDisabled(t.Context(), admin, admin.User.ID, false)
	require.NoError(t, err)
	require.False(t, unblocked.SessionsRevoked)
	list, err := s.ListUsers(t.Context(), admin)
	require.NoError(t, err)
	require.Len(t, list.Users, 2)
	// Self password reset stays allowed and revokes the actor's own session.
	newPassword := randomPassword(t)
	reset, err := s.ResetPassword(t.Context(), admin, admin.User.ID, newPassword)
	require.NoError(t, err)
	require.True(t, reset.SessionsRevoked)
	_, err = s.ListUsers(t.Context(), admin)
	code(t, err, auth.Unauthenticated)
	_, err = s.Login(t.Context(), input)
	code(t, err, auth.InvalidCredentials)
	input.Password = newPassword
	admin = session(t, s, login(t, s, input), auth.CLI)
	// Administrators are peers: the other one can still be demoted.
	demoted, err := s.SetRole(t.Context(), admin, other.ID, auth.Member)
	require.NoError(t, err)
	require.Equal(t, auth.Member, demoted.User.Role)
	require.Equal(t, 1, enabledAdmins(t, pool))
}

func TestLastAdministratorGuard(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	// The only enabled administrator can be targeted only by itself, which
	// the self-target guard refuses first; the serialized count guard stays as
	// the safety net the specification requires and is exercised directly.
	_, err := s.SetRole(t.Context(), admin, admin.User.ID, auth.Member)
	code(t, err, auth.SelfTarget)
	_, err = s.SetUserDisabled(t.Context(), admin, admin.User.ID, true)
	code(t, err, auth.SelfTarget)
	require.Equal(t, 1, enabledAdmins(t, pool))
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	code(t, guardLastAdministrator(t.Context(), sqlc.New(tx)), auth.LastAdministrator)
	require.NoError(t, tx.Rollback(t.Context()))
	other, _ := createMember(t, s, admin, "other-admin")
	_, err = s.SetRole(t.Context(), admin, other.ID, auth.Admin)
	require.NoError(t, err)
	require.Equal(t, 2, enabledAdmins(t, pool))
	tx, err = pool.Begin(t.Context())
	require.NoError(t, err)
	require.NoError(t, guardLastAdministrator(t.Context(), sqlc.New(tx)))
	require.NoError(t, tx.Rollback(t.Context()))
	// Peers remove each other while another enabled administrator remains.
	blocked, err := s.SetUserDisabled(t.Context(), admin, other.ID, true)
	require.NoError(t, err)
	require.True(t, blocked.User.Disabled)
	require.Equal(t, 1, enabledAdmins(t, pool))
	// A blocked administrator is not counted; demoting one changes nothing.
	demoted, err := s.SetRole(t.Context(), admin, other.ID, auth.Member)
	require.NoError(t, err)
	require.Equal(t, auth.Member, demoted.User.Role)
	require.True(t, demoted.User.Disabled)
	_, err = s.SetUserDisabled(t.Context(), admin, other.ID, false)
	require.NoError(t, err)
	require.Equal(t, 1, enabledAdmins(t, pool))
	_, err = s.ListUsers(t.Context(), admin)
	require.NoError(t, err)
}

func TestConcurrentMutualDemotionAndBlock(t *testing.T) {
	pool, s, admin, input := adminFixture(t)
	other, otherInput := createMember(t, s, admin, "rival-admin")
	_, err := s.SetRole(t.Context(), admin, other.ID, auth.Admin)
	require.NoError(t, err)
	type peer struct {
		session auth.Session
		input   auth.LoginInput
	}
	peers := [2]*peer{{admin, input}, {session(t, s, login(t, s, otherInput), auth.CLI), otherInput}}
	// With self-targeting refused, every pair of concurrent guard-relevant
	// mutations shares the actor or target row and is already serialized by
	// LockMutationUsers; the advisory key is belt-and-braces, and
	// TestAdministrationHeldLockTimeout proves it is taken. The loser here is
	// serialized behind the winner and rechecks authority the winner removed.
	const iterations = 3
	for _, mode := range []struct {
		name  string
		apply func(actor auth.Session, target string) error
		loser string
	}{
		{"demote", func(actor auth.Session, target string) error {
			_, err := s.SetRole(t.Context(), actor, target, auth.Member)
			return err
		}, auth.Forbidden},
		{"block", func(actor auth.Session, target string) error {
			_, err := s.SetUserDisabled(t.Context(), actor, target, true)
			return err
		}, auth.Unauthenticated},
	} {
		for iteration := 0; iteration < iterations; iteration++ {
			require.Equal(t, 2, enabledAdmins(t, pool), mode.name)
			var wg sync.WaitGroup
			results := make([]error, 2)
			for index := range peers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[index] = mode.apply(peers[index].session, peers[1-index].session.User.ID)
				}()
			}
			wg.Wait()
			require.Equal(t, 1, enabledAdmins(t, pool), mode.name)
			winner := 0
			if results[0] != nil {
				winner = 1
			}
			require.NoError(t, results[winner], mode.name)
			code(t, results[1-winner], mode.loser)
			loser := peers[1-winner]
			if mode.name == "demote" {
				_, err = s.SetRole(t.Context(), peers[winner].session, loser.session.User.ID, auth.Admin)
			} else {
				_, err = s.SetUserDisabled(t.Context(), peers[winner].session, loser.session.User.ID, false)
			}
			require.NoError(t, err)
			if mode.name == "block" {
				// Unblocking never restores the revoked session.
				_, err = s.ListUsers(t.Context(), loser.session)
				code(t, err, auth.Unauthenticated)
				loser.session = session(t, s, login(t, s, loser.input), auth.CLI)
			}
		}
	}
	require.Equal(t, 2, enabledAdmins(t, pool))
}

func TestListUsersOrderFieldsAndTruncation(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	zeta, _ := createMember(t, s, admin, "zeta")
	alpha, _ := createMember(t, s, admin, "alpha")
	_, err := s.SetUserDisabled(t.Context(), admin, zeta.ID, true)
	require.NoError(t, err)
	list, err := s.ListUsers(t.Context(), admin)
	require.NoError(t, err)
	require.False(t, list.Truncated)
	require.Len(t, list.Users, 3)
	require.Equal(t, alpha, list.Users[0])
	require.Equal(t, admin.User.ID, list.Users[1].ID)
	require.Equal(t, auth.UserRecord{ID: admin.User.ID, Username: "personal-admin", Role: auth.Admin, Disabled: false, CreatedAt: list.Users[1].CreatedAt}, list.Users[1])
	require.Equal(t, time.UTC, list.Users[1].CreatedAt.Location())
	require.Equal(t, zeta.ID, list.Users[2].ID)
	require.True(t, list.Users[2].Disabled)
	encoded, err := json.Marshal(list)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "$clavis$")
	// Fixture rows only: the placeholder hash is not an account credential.
	execSQL(t, pool, `INSERT INTO users(id,username,password_hash,role)
		SELECT gen_random_uuid(), 'bulk-'||lpad(n::text,5,'0'), $1, 'member' FROM generate_series(1,$2) n`,
		auth.DummyPasswordHash(), auth.MaxUserListing+1)
	list, err = s.ListUsers(t.Context(), admin)
	require.NoError(t, err)
	require.True(t, list.Truncated)
	require.Len(t, list.Users, auth.MaxUserListing)
	require.Equal(t, "alpha", list.Users[0].Username)
	require.Equal(t, "bulk-00001", list.Users[1].Username)
	require.Equal(t, "bulk-00999", list.Users[auth.MaxUserListing-1].Username)
	// Fixture names are lowercase ASCII, so Go byte order matches collation.
	for index := 1; index < len(list.Users); index++ {
		require.Less(t, list.Users[index-1].Username, list.Users[index].Username)
	}
}

// The hashing budget lives in package auth; from here it is filled the way
// production fills it, by two concurrent derivations.
func fillHashBudget(t *testing.T) func() {
	t.Helper()
	started := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			_, _ = auth.HashPassword(context.Background(), "budget filler password")
		}()
	}
	<-started
	<-started
	time.Sleep(10 * time.Millisecond)
	return wg.Wait
}

func TestAdministrationHonorsHashingBudget(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	member, input := createMember(t, s, admin, "budget-member")
	users, sessions := countRows(t, pool, "users"), countRows(t, pool, "sessions")
	for name, operation := range map[string]func() error{
		"create": func() error {
			_, err := s.CreateUser(t.Context(), admin, auth.CreateUserRequest{Username: "budget-user", Password: randomPassword(t)})
			return err
		},
		"reset": func() error { _, err := s.ResetPassword(t.Context(), admin, member.ID, randomPassword(t)); return err },
	} {
		wait := fillHashBudget(t)
		start := time.Now()
		err := operation()
		elapsed := time.Since(start)
		wait()
		require.Error(t, err, name)
		code(t, err, auth.RateLimited)
		var failure *auth.Error
		require.ErrorAs(t, err, &failure)
		require.Positive(t, failure.RetryAfter)
		require.Less(t, elapsed, time.Second, name)
	}
	// A rejected budget is a denied attempt: no account is created, no hash is
	// replaced and no session is touched.
	require.Equal(t, users, countRows(t, pool, "users"))
	require.Equal(t, sessions, countRows(t, pool, "sessions"))
	login(t, s, input)
	// A canceled context never commits, even though hashing is not cancelable.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := s.CreateUser(ctx, admin, auth.CreateUserRequest{Username: "budget-user", Password: randomPassword(t)})
	code(t, err, auth.ServiceUnavailable)
	require.Equal(t, users, countRows(t, pool, "users"))
}

func TestAdministrationHeldLockTimeout(t *testing.T) {
	pool, s, admin, _ := adminFixture(t)
	member, input := createMember(t, s, admin, "locked-member")
	holder, err := pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = holder.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, adminMutationLock)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	start := time.Now()
	_, err = s.SetRole(ctx, admin, member.ID, auth.Admin)
	cancel()
	code(t, err, auth.ServiceUnavailable)
	require.Less(t, time.Since(start), time.Second)
	// Listing and login never wait on the administration key.
	list, err := s.ListUsers(t.Context(), admin)
	require.NoError(t, err)
	require.Len(t, list.Users, 2)
	login(t, s, input)
	require.NoError(t, holder.Rollback(t.Context()))
	// The timed-out mutation left the target row as it was.
	role, _ := userState(t, pool, member.ID)
	require.Equal(t, "member", role)
	promoted, err := s.SetRole(t.Context(), admin, member.ID, auth.Admin)
	require.NoError(t, err)
	require.Equal(t, auth.Admin, promoted.User.Role)
	var held int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted
		AND ((classid::bigint << 32) | objid::bigint) = $1`, adminMutationLock).Scan(&held))
	require.Equal(t, 0, held)
}
