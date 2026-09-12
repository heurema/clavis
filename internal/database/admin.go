package database

import (
	"context"
	"errors"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// adminMutationLock serializes every user-administration mutation across
// instances so the last-administrator guard cannot race. It is distinct from
// MigrationLock and limitLock; listing and login never take it.
const adminMutationLock int64 = 0x434c415649530003

var _ auth.Administration = (*LocalAuth)(nil)

// Every generated users query returns this same safe projection.
func userRecord(row sqlc.FindUserRow) auth.UserRecord {
	return auth.UserRecord{
		ID: row.ID, Username: row.Username, Role: auth.Role(row.Role),
		Disabled: row.Disabled, CreatedAt: row.CreatedAt.UTC(),
	}
}

func validSession(session auth.Session) bool {
	return auth.ValidUserID(session.ID) && auth.ValidUserID(session.User.ID)
}

// lockMutationUsers locks the actor and, when one is named, the target, in
// identifier order. The target reference is a UUID or a username and both are
// matched by the same statement, so resolving a name never splits the ordered
// acquisition into two waits that opposing mutations could deadlock on.
func lockMutationUsers(ctx context.Context, queries *sqlc.Queries, actor, ref string) error {
	params := sqlc.LockMutationUsersParams{ActorID: actor}
	if auth.ValidUserID(ref) {
		params.TargetID = ref
	} else {
		params.TargetUsername = ref
	}
	return queries.LockMutationUsers(ctx, params)
}

// lockUser resolves a user reference inside the transaction, trying UUID
// syntax first and falling back to the unique username, and returns the target
// row under its lock. A username can never be UUID-shaped, so the two forms
// cannot collide, and every unresolvable reference is USER_NOT_FOUND, which is
// the same answer an unknown UUID has always produced.
func lockUser(ctx context.Context, queries *sqlc.Queries, ref string) (sqlc.FindUserRow, error) {
	var row sqlc.FindUserRow
	if !auth.ValidUserRef(ref) {
		return row, &auth.Error{Code: auth.UserNotFound}
	}
	id := ref
	if !auth.ValidUserID(ref) {
		found, err := queries.FindUserIDByUsername(ctx, ref)
		if errors.Is(err, pgx.ErrNoRows) {
			return row, &auth.Error{Code: auth.UserNotFound}
		}
		if err != nil {
			return row, err
		}
		id = found
	}
	locked, err := queries.LockUser(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, &auth.Error{Code: auth.UserNotFound}
	}
	return sqlc.FindUserRow(locked), err
}

// authorize rechecks the actor inside tx and refuses a missing session or a
// non-administrator. Its error is final.
func authorize(ctx context.Context, tx pgx.Tx, previous auth.Session) (auth.Session, error) {
	current, err := recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			return current, &auth.Error{Code: auth.Unauthenticated}
		}
		return current, unavailable()
	}
	if current.User.Role != auth.Admin {
		return current, &auth.Error{Code: auth.Forbidden}
	}
	return current, nil
}

// denial distinguishes service-owned target denials, which answer the caller
// with their code, from driver failures, which never escape unwrapped.
func denial(err error) (string, bool) {
	var failure *auth.Error
	if !errors.As(err, &failure) {
		return "", false
	}
	switch failure.Code {
	case auth.UserNotFound, auth.UsernameTaken, auth.SelfTarget, auth.LastAdministrator,
		auth.ConnectionExists, auth.ConnectionNotFound, auth.ConnectionInUse:
		return failure.Code, true
	}
	return "", false
}

// administer runs one mutation in the design's transaction shape: deadline,
// readiness, pre-transaction work (hashing), the caller's advisory key, ordered
// row locks, session and role recheck, body and commit. Each family of
// mutations passes its own key, so connections do not serialize behind user
// administration. targetRef is the UUID or username the ordered row lock
// covers, empty when the mutation names no user. The body receives the
// rechecked actor; a denial rolls the transaction back and answers with its
// code alone, which the caller re-hints. A dry run runs the whole operation and
// then rolls it back, leaving no trace.
func (s *LocalAuth) administer(ctx context.Context, previous auth.Session, lock int64, targetRef string, dryRun bool,
	prepare func(context.Context) error, body func(context.Context, pgx.Tx, auth.Session) error) error {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	if !validSession(previous) {
		return &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return err
	}
	// Hashing runs before the transaction so no lock is held during Argon2;
	// a member with a valid session therefore spends a hash slot before
	// being denied, by design. A rejected hashing budget is a denied attempt:
	// it answers with RATE_LIMITED and its retry hint, having opened no
	// transaction and touched no row.
	if prepare != nil {
		if err := prepare(ctx); err != nil {
			return err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return unavailable()
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	if err := queries.LockTransaction(ctx, lock); err != nil {
		return unavailable()
	}
	if err := lockMutationUsers(ctx, queries, previous.User.ID, targetRef); err != nil {
		return unavailable()
	}
	// A dry run is a question, not an attempt. It runs the whole operation
	// inside a savepoint of a transaction that is never committed, so even a
	// denial leaves no trace.
	work := tx
	if dryRun {
		nested, err := tx.Begin(ctx)
		if err != nil {
			return unavailable()
		}
		work = nested
	}
	current, err := authorize(ctx, work, previous)
	if err != nil {
		return err
	}
	if err := body(ctx, work, current); err != nil {
		if code, ok := denial(err); ok {
			return &auth.Error{Code: code}
		}
		// Input a body can only reject once it has read the row, such as a
		// provider-specific target, is answered like the validators that run
		// before the transaction.
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.InvalidArgument {
			return failure
		}
		return unavailable()
	}
	if dryRun {
		return nil
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable()
	}
	return nil
}

func hashInto(hash *string, password auth.Secret) func(context.Context) error {
	return func(ctx context.Context) (err error) {
		*hash, err = auth.HashPassword(ctx, password)
		return err
	}
}

func enabledAdministrator(row sqlc.FindUserRow) bool {
	return row.Role == string(auth.Admin) && !row.Disabled
}

// guardRemoval applies the block/demote guards in the design's order under
// adminMutationLock: nobody removes themself (GitLab group-owner model), then
// the enabled administrator count, which includes the target, must not reach
// zero. The count is read only when the target is currently counted.
func guardRemoval(ctx context.Context, queries *sqlc.Queries, actor auth.Session, target sqlc.FindUserRow) error {
	if target.ID == actor.User.ID {
		return &auth.Error{Code: auth.SelfTarget}
	}
	if !enabledAdministrator(target) {
		return nil
	}
	return guardLastAdministrator(ctx, queries)
}

// guardLastAdministrator is unreachable through a rechecked actor that cannot
// target itself, because that actor is always counted; it stays as the
// serialized safety net the specification requires.
func guardLastAdministrator(ctx context.Context, queries *sqlc.Queries) error {
	count, err := queries.CountEnabledAdministrators(ctx)
	if err != nil {
		return err
	}
	if count <= 1 {
		return &auth.Error{Code: auth.LastAdministrator}
	}
	return nil
}

func (s *LocalAuth) ListUsers(ctx context.Context, previous auth.Session) (auth.UserList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var list auth.UserList
	if !validSession(previous) {
		return list, &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return list, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return list, unavailable()
	}
	defer rollback(ctx, tx)
	if _, err := authorize(ctx, tx, previous); err != nil {
		return list, err
	}
	rows, err := sqlc.New(tx).ListUsers(ctx, auth.MaxUserListing+1)
	if err != nil {
		return list, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	list.Users = make([]auth.UserRecord, 0, min(len(rows), auth.MaxUserListing))
	for index, row := range rows {
		if index == auth.MaxUserListing {
			list.Truncated = true
			break
		}
		list.Users = append(list.Users, userRecord(sqlc.FindUserRow(row)))
	}
	return list, nil
}

func (s *LocalAuth) CreateUser(ctx context.Context, session auth.Session, request auth.CreateUserRequest) (auth.UserRecord, error) {
	var record auth.UserRecord
	if !auth.ValidUsername(request.Username) {
		return record, &auth.Error{Code: auth.InvalidArgument, Hint: auth.UsernameHint}
	}
	if !auth.ValidPassword(request.Password) {
		return record, &auth.Error{Code: auth.InvalidArgument}
	}
	var hash string
	err := s.administer(ctx, session, adminMutationLock, "", false, hashInto(&hash, request.Password),
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			exists, err := queries.UsernameExists(ctx, request.Username)
			if err != nil {
				return err
			}
			if exists {
				return &auth.Error{Code: auth.UsernameTaken}
			}
			id, err := bootstrapID()
			if err != nil {
				return err
			}
			// A row committed outside the advisory lock can still win the
			// unique index; the savepoint keeps this transaction usable after
			// the constraint fires.
			savepoint, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			row, err := sqlc.New(savepoint).InsertUser(ctx, sqlc.InsertUserParams{
				ID: id, Username: request.Username, PasswordHash: hash,
			})
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				if err := savepoint.Rollback(ctx); err != nil {
					return err
				}
				return &auth.Error{Code: auth.UsernameTaken}
			}
			if err != nil {
				return err
			}
			if err := savepoint.Commit(ctx); err != nil {
				return err
			}
			record = userRecord(sqlc.FindUserRow(row))
			return nil
		})
	if err != nil {
		return auth.UserRecord{}, err
	}
	return record, nil
}

// SetUserDisabled and its neighbours address the target by UUID or username.
// The reference is resolved and locked inside the transaction, so both forms
// produce the same outcome and the same mutation.
func (s *LocalAuth) SetUserDisabled(ctx context.Context, session auth.Session, userRef string, disabled bool) (auth.UserMutation, error) {
	var result auth.UserMutation
	if !auth.ValidUserRef(userRef) {
		return result, &auth.Error{Code: auth.InvalidArgument}
	}
	err := s.administer(ctx, session, adminMutationLock, userRef, false, nil,
		func(ctx context.Context, tx pgx.Tx, actor auth.Session) error {
			queries := sqlc.New(tx)
			found, err := lockUser(ctx, queries, userRef)
			if err != nil {
				return err
			}
			if disabled {
				if err := guardRemoval(ctx, queries, actor, found); err != nil {
					return err
				}
			}
			row, err := queries.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{Disabled: disabled, ID: found.ID})
			if err != nil {
				return err
			}
			if disabled {
				if err := queries.RevokeUserSessions(ctx, found.ID); err != nil {
					return err
				}
			}
			result = auth.UserMutation{User: userRecord(sqlc.FindUserRow(row)), SessionsRevoked: disabled}
			return nil
		})
	if err != nil {
		return auth.UserMutation{}, err
	}
	return result, nil
}

func (s *LocalAuth) ResetPassword(ctx context.Context, session auth.Session, userRef string, password auth.Secret) (auth.UserMutation, error) {
	var result auth.UserMutation
	if !auth.ValidUserRef(userRef) || !auth.ValidPassword(password) {
		return result, &auth.Error{Code: auth.InvalidArgument}
	}
	var hash string
	err := s.administer(ctx, session, adminMutationLock, userRef, false, hashInto(&hash, password),
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			found, err := lockUser(ctx, queries, userRef)
			if err != nil {
				return err
			}
			if err := queries.SetUserPasswordHash(ctx, sqlc.SetUserPasswordHashParams{PasswordHash: hash, ID: found.ID}); err != nil {
				return err
			}
			if err := queries.RevokeUserSessions(ctx, found.ID); err != nil {
				return err
			}
			result = auth.UserMutation{User: userRecord(found), SessionsRevoked: true}
			return nil
		})
	if err != nil {
		return auth.UserMutation{}, err
	}
	return result, nil
}

func (s *LocalAuth) SetRole(ctx context.Context, session auth.Session, userRef string, role auth.Role) (auth.UserMutation, error) {
	var result auth.UserMutation
	if !auth.ValidUserRef(userRef) || (role != auth.Admin && role != auth.Member) {
		return result, &auth.Error{Code: auth.InvalidArgument}
	}
	err := s.administer(ctx, session, adminMutationLock, userRef, false, nil,
		func(ctx context.Context, tx pgx.Tx, actor auth.Session) error {
			queries := sqlc.New(tx)
			found, err := lockUser(ctx, queries, userRef)
			if err != nil {
				return err
			}
			if role == auth.Member {
				if err := guardRemoval(ctx, queries, actor, found); err != nil {
					return err
				}
			}
			row, err := queries.SetUserRole(ctx, sqlc.SetUserRoleParams{Role: string(role), ID: found.ID})
			if err != nil {
				return err
			}
			result = auth.UserMutation{User: userRecord(sqlc.FindUserRow(row)), SessionsRevoked: false}
			return nil
		})
	if err != nil {
		return auth.UserMutation{}, err
	}
	return result, nil
}
