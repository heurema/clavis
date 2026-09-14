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

// hintAccessSubject names the missing argument: an administrator's own access
// comes from their role rather than from grants, so there is no subject to
// default to and the caller has to name one.
const hintAccessSubject = "Name the user whose access to explain with `--user`; an administrator needs no grant, so there is no default subject."

// denied reports whether err is the service's own failure with this code, the
// question every caller that forwards a target denial and swallows a driver
// failure has to ask.
func denied(err error, code string) bool {
	var failure *auth.Error
	return errors.As(err, &failure) && failure.Code == code
}

// deref reads an optional column. Every recipient identifier is joined to its
// name, so a set identifier always carries one; the empty string is the safe
// answer to a row that somehow carries neither.
func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// grantRecipient projects the recipient columns of a joined grant row. The
// table's check guarantees exactly one of the two identifiers is set, so the
// row itself says which namespace the name belongs to.
func grantRecipient(userID, username, groupID, groupName *string) auth.Recipient {
	if userID != nil {
		return auth.Recipient{Kind: auth.RecipientUser, ID: *userID, Name: deref(username)}
	}
	return auth.Recipient{Kind: auth.RecipientGroup, ID: deref(groupID), Name: deref(groupName)}
}

// grantRecord is the safe projection of a joined grant row: the recipient and
// the connection by UUID and name, and the administrator who granted it.
func grantRecord(row sqlc.FindGrantRow) auth.Grant {
	return auth.Grant{
		Recipient:  grantRecipient(row.UserID, row.Username, row.GroupID, row.GroupName),
		Connection: auth.GrantParty{ID: row.ConnectionID, Name: row.ConnectionName},
		CreatedAt:  row.CreatedAt.UTC(),
		CreatedBy:  auth.GrantParty{ID: row.CreatedBy, Name: row.CreatedByUsername},
	}
}

// recipientParams turns a resolved recipient into the nullable pair every
// recipient-keyed query takes: exactly one side is set, which is what the
// table's check and its two partial unique indexes expect.
func recipientParams(recipient auth.Recipient) (userID, groupID *string) {
	if recipient.Kind == auth.RecipientUser {
		return &recipient.ID, nil
	}
	return nil, &recipient.ID
}

// findGroup resolves a UUID or a name, exactly as findConnection does: a valid
// group name can never parse as a UUID, so UUID syntax decides which lookup
// runs. Mutations lock the row; reads do not.
func findGroup(ctx context.Context, queries *sqlc.Queries, ref string, lock bool) (sqlc.Group, error) {
	var row sqlc.Group
	if !auth.ValidGroupRef(ref) {
		return row, groupNotFound()
	}
	id := ref
	if !auth.ValidUserID(ref) {
		named, err := queries.FindGroupByName(ctx, ref)
		if errors.Is(err, pgx.ErrNoRows) {
			return row, groupNotFound()
		}
		if err != nil {
			return row, err
		}
		if !lock {
			return named, nil
		}
		id = named.ID
	}
	var err error
	if lock {
		row, err = queries.LockGroup(ctx, id)
	} else {
		row, err = queries.FindGroupByID(ctx, id)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return row, groupNotFound()
	}
	return row, err
}

func lockGroup(ctx context.Context, queries *sqlc.Queries, ref string) (sqlc.Group, error) {
	return findGroup(ctx, queries, ref, true)
}

// grantParties resolves and locks both sides of a grant inside the mutation's
// transaction, so a concurrent block, rename or delete serializes behind it.
// The recipient decides which row is locked, and the recorded lock order puts
// it before the connection: the user rows administer already took, then the
// group row, then the connection.
func grantParties(ctx context.Context, queries *sqlc.Queries,
	request auth.GrantRequest) (auth.Recipient, sqlc.Connection, error) {
	var recipient auth.Recipient
	kind, ref, ok := request.RecipientRef()
	if !ok {
		return recipient, sqlc.Connection{}, invalidArgument(auth.RecipientHint)
	}
	if kind == auth.RecipientUser {
		user, err := lockUser(ctx, queries, ref)
		if err != nil {
			return recipient, sqlc.Connection{}, err
		}
		recipient = auth.Recipient{Kind: auth.RecipientUser, ID: user.ID, Name: user.Username}
	} else {
		group, err := lockGroup(ctx, queries, ref)
		if err != nil {
			return recipient, sqlc.Connection{}, err
		}
		recipient = auth.Recipient{Kind: auth.RecipientGroup, ID: group.ID, Name: group.Name}
	}
	connection, err := lockConnection(ctx, queries, request.Connection)
	return recipient, connection, err
}

// CreateGrant is idempotent: a grant that already exists is returned with
// Created false and leaves its row untouched, so a retrying agent changes
// nothing.
func (s *LocalAuth) CreateGrant(ctx context.Context, session auth.Session,
	request auth.GrantRequest, dryRun bool) (auth.GrantMutation, error) {
	var result auth.GrantMutation
	err := s.administer(ctx, session, grantMutationLock, request.User, dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, actor auth.Session) error {
			queries := sqlc.New(tx)
			recipient, connection, err := grantParties(ctx, queries, request)
			if err != nil {
				return err
			}
			userID, groupID := recipientParams(recipient)
			_, err = queries.InsertGrant(ctx, sqlc.InsertGrantParams{
				UserID: userID, GroupID: groupID, ConnectionID: connection.ID, CreatedBy: actor.User.ID,
			})
			// The insert declines a conflict rather than failing, so no row
			// means the pair was already granted.
			existed := errors.Is(err, pgx.ErrNoRows)
			if err != nil && !existed {
				return err
			}
			row, err := queries.FindGrant(ctx, sqlc.FindGrantParams{
				UserID: userID, GroupID: groupID, ConnectionID: connection.ID,
			})
			if err != nil {
				return err
			}
			result = auth.GrantMutation{Grant: grantRecord(row), Created: !existed, DryRun: dryRun}
			return nil
		})
	if err != nil {
		return auth.GrantMutation{}, hinted(err)
	}
	return result, nil
}

// RevokeGrant succeeds whether or not a grant was there; removing nothing
// reports Revoked false and changes no row.
func (s *LocalAuth) RevokeGrant(ctx context.Context, session auth.Session,
	request auth.GrantRequest, dryRun bool) (auth.GrantRevocation, error) {
	var result auth.GrantRevocation
	err := s.administer(ctx, session, grantMutationLock, request.User, dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			recipient, connection, err := grantParties(ctx, queries, request)
			if err != nil {
				return err
			}
			userID, groupID := recipientParams(recipient)
			removed, err := queries.DeleteGrant(ctx, sqlc.DeleteGrantParams{
				UserID: userID, GroupID: groupID, ConnectionID: connection.ID,
			})
			if err != nil {
				return err
			}
			result = auth.GrantRevocation{
				Recipient:  recipient,
				Connection: auth.GrantParty{ID: connection.ID, Name: connection.Name},
				Revoked:    removed > 0, DryRun: dryRun,
			}
			return nil
		})
	if err != nil {
		return auth.GrantRevocation{}, hinted(err)
	}
	return result, nil
}

// The three namespaces a listing filter can name; each reference is resolved
// by the lookup of its own table.
type filterNamespace int

const (
	filterUser filterNamespace = iota
	filterGroup
	filterConnection
)

// filterID resolves one listing filter to an identifier. found false means the
// reference names nothing, which narrows the listing to no rows rather than
// failing: a filter is a question about grants, not about the named party.
func filterID(ctx context.Context, queries *sqlc.Queries, ref string,
	namespace filterNamespace) (id string, found bool, err error) {
	if ref == "" {
		return "", false, nil
	}
	switch namespace {
	case filterUser:
		if !auth.ValidUserRef(ref) {
			return "", false, nil
		}
		// A UUID needs no lookup: a listing filtered on one that names nobody
		// matches no grant anyway.
		if auth.ValidUserID(ref) {
			return ref, true, nil
		}
		id, err = queries.FindUserIDByUsername(ctx, ref)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return id, err == nil, err
	case filterGroup:
		group, err := findGroup(ctx, queries, ref, false)
		if denied(err, auth.GroupNotFound) {
			return "", false, nil
		}
		return group.ID, err == nil, err
	}
	connection, err := findConnection(ctx, queries, ref, false)
	if denied(err, auth.ConnectionNotFound) {
		return "", false, nil
	}
	return connection.ID, err == nil, err
}

// findUser resolves a user reference without locking the row, the read
// counterpart of lockUser: a listing asks who the subject is, it does not
// serialize against that account's administration.
func findUser(ctx context.Context, queries *sqlc.Queries, ref string) (sqlc.FindUserRow, error) {
	var row sqlc.FindUserRow
	if !auth.ValidUserRef(ref) {
		return row, userNotFound()
	}
	id := ref
	if !auth.ValidUserID(ref) {
		found, err := queries.FindUserIDByUsername(ctx, ref)
		if errors.Is(err, pgx.ErrNoRows) {
			return row, userNotFound()
		}
		if err != nil {
			return row, err
		}
		id = found
	}
	row, err := queries.FindUser(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, userNotFound()
	}
	return row, err
}

func userNotFound() error {
	return &auth.Error{Code: auth.UserNotFound, Hint: hintUserNotFound}
}

// ListGrants is a read: no advisory key and no mutation. Administrators see
// every grant and may filter by recipient, user or group, and by connection;
// naming both recipients matches nothing, because a grant has exactly one. A
// member sees only their own direct grants, and any other reference is
// refused.
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
	current, err := recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			return list, &auth.Error{Code: auth.Unauthenticated}
		}
		return list, unavailable()
	}
	params := sqlc.ListGrantsParams{LimitRows: int32(limit) + 1}
	scoped := true
	if current.User.Role == auth.Admin {
		if id, found, err := filterID(ctx, queries, filter.User, filterUser); err != nil {
			return list, unavailable()
		} else if filter.User != "" {
			params.UserID, scoped = &id, found
		}
		if scoped {
			if id, found, err := filterID(ctx, queries, filter.Group, filterGroup); err != nil {
				return list, unavailable()
			} else if filter.Group != "" {
				params.GroupID, scoped = &id, found
			}
		}
	} else {
		// A group filter asks about access configured for a set of people, so
		// it is refused before any group is looked up: whether the group
		// exists is not a member's to learn. Naming another user is the same
		// attempt to read another account's access, not a narrower question.
		if filter.Group != "" {
			return list, &auth.Error{Code: auth.Forbidden}
		}
		if filter.User != "" && filter.User != current.User.ID && filter.User != current.User.Username {
			return list, &auth.Error{Code: auth.Forbidden}
		}
		// A member's listing is their own direct grants; the group grants they
		// inherit are not records that name them.
		params.UserID = &current.User.ID
	}
	if scoped {
		if id, found, err := filterID(ctx, queries, filter.Connection, filterConnection); err != nil {
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

// accessEntry projects one configured path. The group columns are set only on
// an inherited grant, which is what separates the two sources; a connection
// reached twice is two entries, because provenance is the question.
func accessEntry(row sqlc.ListEffectiveAccessRow) auth.AccessEntry {
	entry := auth.AccessEntry{
		Connection: auth.GrantParty{ID: row.ConnectionID, Name: row.ConnectionName},
		Source:     auth.AccessDirect,
		CreatedAt:  row.CreatedAt.UTC(),
	}
	if row.GroupID != nil {
		entry.Source = auth.AccessGroup
		entry.Group = &auth.GrantParty{ID: *row.GroupID, Name: deref(row.GroupName)}
	}
	return entry
}

// accessSubject applies the role rule the server owns rather than the client:
// a member asks about themselves, by no reference or by either spelling of
// their own, and any other user is another account's business; an
// administrator has no subject to default to, because their own access comes
// from their role rather than from grants.
func accessSubject(ctx context.Context, queries *sqlc.Queries,
	current auth.Session, ref string) (auth.UserRecord, error) {
	if current.User.Role != auth.Admin {
		if ref != "" && ref != current.User.ID && ref != current.User.Username {
			return auth.UserRecord{}, &auth.Error{Code: auth.Forbidden}
		}
		ref = current.User.ID
	} else if ref == "" {
		return auth.UserRecord{}, invalidArgument(hintAccessSubject)
	}
	row, err := findUser(ctx, queries, ref)
	if err != nil {
		if denied(err, auth.UserNotFound) {
			return auth.UserRecord{}, err
		}
		return auth.UserRecord{}, unavailable()
	}
	return userRecord(row), nil
}

// ListEffectiveAccess reports the grant paths that reach one subject, never
// whether they can use a connection now: only AuthorizeConnection answers
// that, which is why the subject's own record travels with the entries. An
// administrator subject lists whatever grants happen to name them or their
// groups, and role: admin on the record explains that their access does not
// depend on those grants.
func (s *LocalAuth) ListEffectiveAccess(ctx context.Context, previous auth.Session,
	userRef, connectionRef string, limit int) (auth.AccessList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	list := auth.AccessList{Entries: []auth.AccessEntry{}}
	if limit <= 0 || limit > auth.MaxAccessListing {
		limit = auth.MaxAccessListing
	}
	tx, current, err := s.memberRead(ctx, previous)
	if err != nil {
		return list, err
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	// The subject is resolved after the recheck, so a demotion in flight
	// decides which rule applies.
	subject, err := accessSubject(ctx, queries, current, userRef)
	if err != nil {
		return list, err
	}
	params := sqlc.ListEffectiveAccessParams{UserID: subject.ID, LimitRows: int32(limit) + 1}
	scoped := true
	if id, found, err := filterID(ctx, queries, connectionRef, filterConnection); err != nil {
		return list, unavailable()
	} else if connectionRef != "" {
		params.ConnectionID, scoped = &id, found
	}
	var rows []sqlc.ListEffectiveAccessRow
	if scoped {
		if rows, err = queries.ListEffectiveAccess(ctx, params); err != nil {
			return list, unavailable()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	list.User = subject
	for index, row := range rows {
		if index == limit {
			list.Truncated = true
			break
		}
		list.Entries = append(list.Entries, accessEntry(row))
	}
	return list, nil
}

// ListGroupNames answers the identity question "which groups am I in",
// bounded like every listing. Unlike the connection names it is filled for
// every caller: an administrator belongs to groups like anybody else, and
// membership is a fact about them even when their access does not depend on
// it.
func (s *LocalAuth) ListGroupNames(ctx context.Context, previous auth.Session,
	limit int) (names []string, truncated bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	names = []string{}
	if limit <= 0 || limit > auth.MaxGroupListing {
		limit = auth.MaxGroupListing
	}
	tx, current, err := s.memberRead(ctx, previous)
	if err != nil {
		return names, false, err
	}
	defer rollback(ctx, tx)
	rows, err := sqlc.New(tx).ListGroupNames(ctx, sqlc.ListGroupNamesParams{
		UserID: current.User.ID, LimitRows: int32(limit) + 1,
	})
	if err != nil {
		return names, false, unavailable()
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
// disabled connection. A member's not-found stays indistinguishable from an
// unknown reference.
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
	current, err := recheck(ctx, tx, previous)
	if err != nil {
		var failure *auth.Error
		if errors.As(err, &failure) && failure.Code == auth.Unauthenticated {
			return record, &auth.Error{Code: auth.Unauthenticated}
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
// read shares: a recheck that refuses a revoked session, and no mutation. The
// caller runs its query against the returned transaction.
func (s *LocalAuth) memberRead(ctx context.Context, previous auth.Session) (pgx.Tx, auth.Session, error) {
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
			err = &auth.Error{Code: auth.Unauthenticated}
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
// bounds of the administrator listing. Disabled
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
	tx, current, err := s.memberRead(ctx, previous)
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
// projection. An ungranted or unknown reference is CONNECTION_NOT_FOUND, so
// absence discloses nothing either way.
func (s *LocalAuth) GetGrantedConnection(ctx context.Context, previous auth.Session,
	ref string) (auth.ConnectionSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var summary auth.ConnectionSummary
	tx, current, err := s.memberRead(ctx, previous)
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
	tx, current, err := s.memberRead(ctx, previous)
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
