package database

import (
	"context"
	"errors"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/jackc/pgx/v5"
)

// grantMutationLock serializes grant creation and revocation across instances,
// so a grant cannot race the block, the rename or the delete of either party.
// It is distinct from MigrationLock, limitLock, adminMutationLock and
// connectionMutationLock; listing and authorization never take it.
const grantMutationLock int64 = 0x434c415649530005

var _ auth.Grants = (*LocalAuth)(nil)

// hintConnectionDisabled names the only action that restores a disabled
// connection; the caller cannot enable it themselves.
const hintConnectionDisabled = "The connection is disabled; ask an administrator to enable it."

// grantRecord is the safe projection of a joined grant row: both parties by
// UUID and name, and the administrator who granted it.
func grantRecord(row sqlc.FindGrantRow) auth.Grant {
	return auth.Grant{
		User:       auth.GrantParty{ID: row.UserID, Name: row.Username},
		Connection: auth.GrantParty{ID: row.ConnectionID, Name: row.ConnectionName},
		CreatedAt:  row.CreatedAt.UTC(),
		CreatedBy:  auth.GrantParty{ID: row.CreatedBy, Name: row.CreatedByUsername},
	}
}

// grantParties resolves and locks both sides of a grant inside the mutation's
// transaction, so a concurrent block, rename or delete serializes behind it.
// The user is reported to the caller even when the connection lookup fails, so
// the committed denial can still name the verified party.
func grantParties(ctx context.Context, queries *sqlc.Queries,
	request auth.GrantRequest) (sqlc.FindUserRow, sqlc.Connection, error) {
	user, err := lockUser(ctx, queries, request.User)
	if err != nil {
		return user, sqlc.Connection{}, err
	}
	connection, err := lockConnection(ctx, queries, request.Connection)
	return user, connection, err
}

// CreateGrant is idempotent: a grant that already exists is returned with
// Created false and records no second event, so a retrying agent leaves one
// trace for one decision.
func (s *LocalAuth) CreateGrant(ctx context.Context, session auth.Session,
	request auth.GrantRequest, dryRun bool) (auth.GrantMutation, error) {
	var result auth.GrantMutation
	err := s.administer(ctx, session, grantMutationLock, request.User, string(auth.EventGrantCreate), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, actor auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			user, connection, err := grantParties(ctx, queries, request)
			if err != nil {
				return mutation{target: user.ID}, err
			}
			_, err = queries.InsertGrant(ctx, sqlc.InsertGrantParams{
				UserID: user.ID, ConnectionID: connection.ID, CreatedBy: actor.User.ID,
			})
			// The insert declines a conflict rather than failing, so no row
			// means the pair was already granted.
			existed := errors.Is(err, pgx.ErrNoRows)
			if err != nil && !existed {
				return mutation{}, err
			}
			row, err := queries.FindGrant(ctx, sqlc.FindGrantParams{
				UserID: user.ID, ConnectionID: connection.ID,
			})
			if err != nil {
				return mutation{}, err
			}
			result = auth.GrantMutation{Grant: grantRecord(row), Created: !existed, DryRun: dryRun}
			event := mutation{target: user.ID, connection: connection.ID}
			if existed {
				event.outcome = outcomeNone
			}
			return event, nil
		})
	if err != nil {
		return auth.GrantMutation{}, hinted(err)
	}
	return result, nil
}

// RevokeGrant succeeds whether or not a grant was there; removing nothing
// reports Revoked false and records no event.
func (s *LocalAuth) RevokeGrant(ctx context.Context, session auth.Session,
	request auth.GrantRequest, dryRun bool) (auth.GrantRevocation, error) {
	var result auth.GrantRevocation
	err := s.administer(ctx, session, grantMutationLock, request.User, string(auth.EventGrantRevoke), dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) (mutation, error) {
			queries := sqlc.New(tx)
			user, connection, err := grantParties(ctx, queries, request)
			if err != nil {
				return mutation{target: user.ID}, err
			}
			removed, err := queries.DeleteGrant(ctx, sqlc.DeleteGrantParams{
				UserID: user.ID, ConnectionID: connection.ID,
			})
			if err != nil {
				return mutation{}, err
			}
			result = auth.GrantRevocation{
				User:       auth.GrantParty{ID: user.ID, Name: user.Username},
				Connection: auth.GrantParty{ID: connection.ID, Name: connection.Name},
				Revoked:    removed > 0, DryRun: dryRun,
			}
			event := mutation{target: user.ID, connection: connection.ID}
			if removed == 0 {
				event.outcome = outcomeNone
			}
			return event, nil
		})
	if err != nil {
		return auth.GrantRevocation{}, hinted(err)
	}
	return result, nil
}

// filterID resolves one listing filter to an identifier. found false means the
// reference names nothing, which narrows the listing to no rows rather than
// failing: a filter is a question about grants, not about the named party.
func filterID(ctx context.Context, queries *sqlc.Queries, ref string, user bool) (id string, found bool, err error) {
	if ref == "" {
		return "", false, nil
	}
	if user {
		if !auth.ValidUserRef(ref) {
			return "", false, nil
		}
		if auth.ValidUserID(ref) {
			return ref, true, nil
		}
		id, err = queries.FindUserIDByUsername(ctx, ref)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return id, err == nil, err
	}
	row, err := findConnection(ctx, queries, ref, false)
	var failure *auth.Error
	if errors.As(err, &failure) && failure.Code == auth.ConnectionNotFound {
		return "", false, nil
	}
	return row.ID, err == nil, err
}

// ListGrants is a read: no advisory key and no success event. Administrators
// see every grant and may filter by either party; a member sees only their own
// and naming another user is refused with a recorded denial.
func (s *LocalAuth) ListGrants(ctx context.Context, previous auth.Session,
	filter auth.GrantFilter) (auth.GrantList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	list := auth.GrantList{Grants: []auth.Grant{}}
	if !validSession(previous) {
		return list, &auth.Error{Code: auth.Unauthenticated}
	}
	limit := filter.Limit
	if limit <= 0 || limit > auth.MaxGrantListing {
		limit = auth.MaxGrantListing
	}
	if err := s.ready(ctx); err != nil {
		return list, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return list, unavailable()
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	action := string(auth.EventGrantsList)
	current, err := recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			return list, deny(ctx, tx, previous.User.ID, "", previous.ID, action, auth.Unauthenticated)
		}
		return list, unavailable()
	}
	params := sqlc.ListGrantsParams{LimitRows: int32(limit) + 1}
	scoped := true
	if current.User.Role == auth.Admin {
		if id, found, err := filterID(ctx, queries, filter.User, true); err != nil {
			return list, unavailable()
		} else if filter.User != "" {
			params.UserID, scoped = &id, found
		}
	} else {
		// A member's listing is their own. Naming somebody else is an attempt
		// to read another account's access, not a narrower question.
		if filter.User != "" && filter.User != current.User.ID && filter.User != current.User.Username {
			return list, deny(ctx, tx, current.User.ID, "", current.ID, action, auth.Forbidden)
		}
		params.UserID = &current.User.ID
	}
	if scoped {
		if id, found, err := filterID(ctx, queries, filter.Connection, false); err != nil {
			return list, unavailable()
		} else if filter.Connection != "" {
			params.ConnectionID, scoped = &id, found
		}
	}
	var rows []sqlc.ListGrantsRow
	if scoped {
		if rows, err = queries.ListGrants(ctx, params); err != nil {
			return list, unavailable()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	for index, row := range rows {
		if index == limit {
			list.Truncated = true
			break
		}
		list.Grants = append(list.Grants, grantRecord(sqlc.FindGrantRow(row)))
	}
	return list, nil
}

// grantedConnection resolves a reference among the connections one user holds
// a grant on. An ungranted connection answers exactly like an unknown one, so
// a member cannot learn that a connection exists by asking for it.
func grantedConnection(ctx context.Context, queries *sqlc.Queries, userID, ref string) (sqlc.Connection, error) {
	var row sqlc.Connection
	if !auth.ValidConnectionRef(ref) {
		return row, connectionNotFound()
	}
	var err error
	if auth.ValidUserID(ref) {
		row, err = queries.FindGrantedConnectionByID(ctx, sqlc.FindGrantedConnectionByIDParams{
			UserID: userID, ID: ref,
		})
	} else {
		row, err = queries.FindGrantedConnectionByName(ctx, sqlc.FindGrantedConnectionByNameParams{
			UserID: userID, Name: ref,
		})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return row, connectionNotFound()
	}
	return row, err
}

// AuthorizeConnection is the single answer to "may this session use this
// connection now": it rechecks the session and the current role, requires a
// grant of members, lets administrators through without one and refuses a
// disabled connection. Success records no event, and neither does a member's
// not-found, which must stay indistinguishable from an unknown reference.
func (s *LocalAuth) AuthorizeConnection(ctx context.Context, previous auth.Session, ref string) (auth.Connection, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var record auth.Connection
	if !validSession(previous) {
		return record, &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return record, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return record, unavailable()
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	action := string(auth.EventConnectionGet)
	current, err := recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			return record, deny(ctx, tx, previous.User.ID, "", previous.ID, action, auth.Unauthenticated)
		}
		return record, unavailable()
	}
	var row sqlc.Connection
	if current.User.Role == auth.Admin {
		row, err = findConnection(ctx, queries, ref, false)
	} else {
		row, err = grantedConnection(ctx, queries, current.User.ID, ref)
	}
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.ConnectionNotFound {
			return record, failure
		}
		return record, unavailable()
	}
	if !row.Enabled {
		return record, &auth.Error{Code: auth.ConnectionDisabled, Hint: hintConnectionDisabled}
	}
	if err := tx.Commit(ctx); err != nil {
		return record, unavailable()
	}
	if record, err = connectionRecord(row); err != nil {
		return auth.Connection{}, unavailable()
	}
	return record, nil
}

// memberRead opens the bounded read transaction every member-scoped connection
// read shares: recheck with a recorded denial for a revoked session, and no
// success event. The caller runs its query against the returned transaction.
func (s *LocalAuth) memberRead(ctx context.Context, previous auth.Session,
	action string) (pgx.Tx, auth.Session, error) {
	var current auth.Session
	if !validSession(previous) {
		return nil, current, &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return nil, current, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, current, unavailable()
	}
	current, err = recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			err = deny(ctx, tx, previous.User.ID, "", previous.ID, action, auth.Unauthenticated)
		} else {
			err = unavailable()
		}
		rollback(ctx, tx)
		return nil, current, err
	}
	return tx, current, nil
}

// ListGrantedConnections is the member listing: the connections the caller
// holds a grant on, in the reduced projection, with the selector, ordering and
// bounds of the administrator listing and no success event. Disabled
// connections are listed with Enabled false; an administrator reads the
// grants they happen to hold, which is normally none.
func (s *LocalAuth) ListGrantedConnections(ctx context.Context, previous auth.Session,
	terms []auth.SelectorTerm, limit int) (auth.ConnectionSummaryList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	list := auth.ConnectionSummaryList{Connections: []auth.ConnectionSummary{}}
	if !validSession(previous) {
		return list, &auth.Error{Code: auth.Unauthenticated}
	}
	filter, satisfiable, err := compileSelector(terms)
	if err != nil {
		return list, err
	}
	if limit <= 0 || limit > auth.MaxConnectionListing {
		limit = auth.MaxConnectionListing
	}
	tx, current, err := s.memberRead(ctx, previous, string(auth.EventConnectionsList))
	if err != nil {
		return list, err
	}
	defer rollback(ctx, tx)
	var rows []sqlc.Connection
	if satisfiable {
		if rows, err = sqlc.New(tx).ListGrantedConnections(ctx, sqlc.ListGrantedConnectionsParams{
			UserID:   current.User.ID,
			Contains: filter.Contains, Excludes: filter.Excludes, Keys: filter.Keys,
			LimitRows: int32(limit) + 1,
		}); err != nil {
			return list, unavailable()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	for index, row := range rows {
		if index == limit {
			list.Truncated = true
			break
		}
		record, err := connectionRecord(row)
		if err != nil {
			return auth.ConnectionSummaryList{Connections: []auth.ConnectionSummary{}}, unavailable()
		}
		list.Connections = append(list.Connections, record.Summary())
	}
	return list, nil
}

// GetGrantedConnection returns one granted connection in the reduced
// projection. An ungranted or unknown reference is CONNECTION_NOT_FOUND and
// records no event, so absence discloses nothing either way.
func (s *LocalAuth) GetGrantedConnection(ctx context.Context, previous auth.Session,
	ref string) (auth.ConnectionSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var summary auth.ConnectionSummary
	tx, current, err := s.memberRead(ctx, previous, string(auth.EventConnectionGet))
	if err != nil {
		return summary, err
	}
	defer rollback(ctx, tx)
	row, err := grantedConnection(ctx, sqlc.New(tx), current.User.ID, ref)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.ConnectionNotFound {
			return summary, failure
		}
		return summary, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return summary, unavailable()
	}
	record, err := connectionRecord(row)
	if err != nil {
		return auth.ConnectionSummary{}, unavailable()
	}
	return record.Summary(), nil
}

// ListGrantedConnectionNames answers the identity question "what may I use",
// bounded like the listing. An administrator needs no grant to use anything,
// so their list is empty and never truncated rather than misleadingly partial.
func (s *LocalAuth) ListGrantedConnectionNames(ctx context.Context, previous auth.Session,
	limit int) (names []string, truncated bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	names = []string{}
	if limit <= 0 || limit > auth.MaxConnectionListing {
		limit = auth.MaxConnectionListing
	}
	tx, current, err := s.memberRead(ctx, previous, string(auth.EventConnectionsList))
	if err != nil {
		return names, false, err
	}
	defer rollback(ctx, tx)
	var rows []string
	if current.User.Role != auth.Admin {
		if rows, err = sqlc.New(tx).ListGrantedConnectionNames(ctx, sqlc.ListGrantedConnectionNamesParams{
			UserID: current.User.ID, LimitRows: int32(limit) + 1,
		}); err != nil {
			return names, false, unavailable()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return names, false, unavailable()
	}
	for index, name := range rows {
		if index == limit {
			truncated = true
			break
		}
		names = append(names, name)
	}
	return names, truncated, nil
}
