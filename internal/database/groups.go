package database

import (
	"context"
	"errors"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/database/sqlc"
	"github.com/jackc/pgx/v5"
)

// groupMutationLock serializes group and membership mutations across
// instances, so a group name cannot be taken twice and a membership cannot
// race the delete of its group. It is distinct from MigrationLock, limitLock,
// adminMutationLock, connectionMutationLock and grantMutationLock; listing,
// get and the member listing never take it, and no transaction holds it
// together with the grant key. A group delete and a group grant therefore
// serialize on the group row rather than on an advisory key.
const groupMutationLock int64 = 0x434c415649530006

var _ auth.Groups = (*LocalAuth)(nil)

// Hints are fixed application text: they name the next action or the valid
// range and never echo a submitted value.
const (
	hintGroupName        = "A group name is 3 to 64 characters: a lowercase letter followed by lowercase letters, digits, '.', '_' or '-', and never UUID-shaped."
	hintGroupDescription = "A group description is at most 2000 characters without control characters."
	hintGroupUpdate      = "Supply a new name, a new description, or both."
)

func groupExists() error {
	return &auth.Error{Code: auth.GroupExists, Hint: hintGroupExists}
}

// groupFailure answers a read's resolver failure: the group's own not-found
// keeps its code and hint, and a driver failure never escapes unwrapped.
func groupFailure(err error) error {
	if denied(err, auth.GroupNotFound) {
		return err
	}
	return unavailable()
}

// groupParty identifies a group by both its UUID and its name, the projection
// every membership and deletion result carries.
func groupParty(row sqlc.Group) auth.GrantParty {
	return auth.GrantParty{ID: row.ID, Name: row.Name}
}

// groupRecord is the safe projection of a group row with the two counts an
// administrator needs before deleting it.
func groupRecord(row sqlc.Group, members, grants int64) auth.Group {
	return auth.Group{
		ID: row.ID, Name: row.Name, Description: row.Description,
		CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC(),
		Members: int(members), Grants: int(grants),
	}
}

// groupCounts reads the counts the listing computes in one statement, for the
// single-row paths that have no listing to read them from.
func groupCounts(ctx context.Context, queries *sqlc.Queries, row sqlc.Group) (auth.Group, error) {
	members, err := queries.CountGroupMembers(ctx, row.ID)
	if err != nil {
		return auth.Group{}, err
	}
	grants, err := queries.CountGroupGrants(ctx, row.ID)
	if err != nil {
		return auth.Group{}, err
	}
	return groupRecord(row, members, grants), nil
}

// groupMember is a listed member: the safe user record plus how the membership
// came about. Members never read this listing; it is administrator-only.
func groupMember(row sqlc.ListGroupMembersRow) auth.GroupMember {
	return auth.GroupMember{
		UserRecord: userRecord(sqlc.FindUserRow{
			ID: row.ID, Username: row.Username, Role: row.Role,
			Disabled: row.Disabled, CreatedAt: row.CreatedAt,
		}),
		AddedAt: row.AddedAt.UTC(),
		AddedBy: auth.GrantParty{ID: row.AddedBy, Name: row.AddedByUsername},
	}
}

// membershipRecord projects a joined membership row: both parties by UUID and
// name, and the administrator who added the member.
func membershipRecord(row sqlc.FindGroupMemberRow) auth.Membership {
	return auth.Membership{
		Group:     auth.GrantParty{ID: row.GroupID, Name: row.GroupName},
		User:      auth.GrantParty{ID: row.UserID, Name: row.Username},
		CreatedAt: row.CreatedAt.UTC(),
		CreatedBy: auth.GrantParty{ID: row.CreatedBy, Name: row.CreatedByUsername},
	}
}

// administerRead opens the administrator read transaction the administrator
// reads share (users, connections, groups): readiness, a recheck that refuses
// a revoked session, and the role check, with no advisory key and no
// mutation. The caller owns the deadline and rolls the transaction back.
// ListConnections keeps its own copy because its selector check sits between
// the session check and readiness.
func (s *LocalAuth) administerRead(ctx context.Context, previous auth.Session) (pgx.Tx, error) {
	if !validSession(previous) {
		return nil, &auth.Error{Code: auth.Unauthenticated}
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, unavailable()
	}
	if _, err := authorize(ctx, tx, previous); err != nil {
		rollback(ctx, tx)
		return nil, err
	}
	return tx, nil
}

// membershipParties resolves both sides of a membership inside the mutation's
// transaction. The group row is locked here; the user row was already locked
// in identifier order by administer, which is what makes a membership change
// and a block of the same user serialize instead of racing. A blocked user may
// be added, exactly as a blocked user keeps their grants: the account's state
// gates signing in, not what has been configured for it.
func membershipParties(ctx context.Context, queries *sqlc.Queries,
	groupRef, userRef string) (sqlc.Group, sqlc.FindUserRow, error) {
	group, err := lockGroup(ctx, queries, groupRef)
	if err != nil {
		return group, sqlc.FindUserRow{}, err
	}
	user, err := lockUser(ctx, queries, userRef)
	return group, user, err
}

// ListGroups is a read: no advisory key and no mutation. Every group operation
// is administrator-only, so a member is refused by the role check.
func (s *LocalAuth) ListGroups(ctx context.Context, previous auth.Session, limit int) (auth.GroupList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	list := auth.GroupList{Groups: []auth.Group{}}
	if limit <= 0 || limit > auth.MaxGroupListing {
		limit = auth.MaxGroupListing
	}
	tx, err := s.administerRead(ctx, previous)
	if err != nil {
		return list, err
	}
	defer rollback(ctx, tx)
	rows, err := sqlc.New(tx).ListGroups(ctx, int32(limit)+1)
	if err != nil {
		return list, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	for index, row := range rows {
		if index == limit {
			list.Truncated = true
			break
		}
		list.Groups = append(list.Groups, groupRecord(sqlc.Group{
			ID: row.ID, Name: row.Name, Description: row.Description,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		}, row.Members, row.Grants))
	}
	return list, nil
}

// GetGroup reads one group by UUID or name, with the counts the listing
// carries, so a caller can read the delete guard before attempting a delete.
func (s *LocalAuth) GetGroup(ctx context.Context, previous auth.Session, ref string) (auth.Group, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	var record auth.Group
	tx, err := s.administerRead(ctx, previous)
	if err != nil {
		return record, err
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	row, err := findGroup(ctx, queries, ref, false)
	if err != nil {
		return record, groupFailure(err)
	}
	if record, err = groupCounts(ctx, queries, row); err != nil {
		return auth.Group{}, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.Group{}, unavailable()
	}
	return record, nil
}

// ListMembers is the administrator's roster of one group. Members never read
// it: a group tells its members nothing about who else belongs to it.
func (s *LocalAuth) ListMembers(ctx context.Context, previous auth.Session,
	ref string, limit int) (auth.MemberList, error) {
	ctx, cancel := context.WithTimeout(ctx, auth.OperationTimeout)
	defer cancel()
	list := auth.MemberList{Members: []auth.GroupMember{}}
	if limit <= 0 || limit > auth.MaxMemberListing {
		limit = auth.MaxMemberListing
	}
	tx, err := s.administerRead(ctx, previous)
	if err != nil {
		return list, err
	}
	defer rollback(ctx, tx)
	queries := sqlc.New(tx)
	group, err := findGroup(ctx, queries, ref, false)
	if err != nil {
		return list, groupFailure(err)
	}
	rows, err := queries.ListGroupMembers(ctx, sqlc.ListGroupMembersParams{
		GroupID: group.ID, LimitRows: int32(limit) + 1,
	})
	if err != nil {
		return list, unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return list, unavailable()
	}
	for index, row := range rows {
		if index == limit {
			list.Truncated = true
			break
		}
		list.Members = append(list.Members, groupMember(row))
	}
	return list, nil
}

// CreateGroup writes one group under the group key. A name already in use is
// GROUP_EXISTS and nothing is written, whether the collision is seen by the
// existence check or by the unique index.
func (s *LocalAuth) CreateGroup(ctx context.Context, session auth.Session,
	request auth.GroupRequest, dryRun bool) (auth.GroupMutation, error) {
	var result auth.GroupMutation
	if !auth.ValidGroupName(request.Name) {
		return result, invalidArgument(hintGroupName)
	}
	// The description is bounded in characters, the way the column's
	// constraint counts them, by the validator connection descriptions use.
	if !validText(request.Description, auth.MaxDescriptionLength) {
		return result, invalidArgument(hintGroupDescription)
	}
	err := s.administer(ctx, session, groupMutationLock, "", dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			exists, err := queries.GroupNameExists(ctx, request.Name)
			if err != nil {
				return err
			}
			if exists {
				return groupExists()
			}
			id, err := bootstrapID()
			if err != nil {
				return err
			}
			row, err := nameGuarded(ctx, tx, groupExists(), func(q *sqlc.Queries) (sqlc.Group, error) {
				return q.InsertGroup(ctx, sqlc.InsertGroupParams{
					ID: id, Name: request.Name, Description: request.Description,
				})
			})
			if err != nil {
				return err
			}
			result = auth.GroupMutation{Group: groupRecord(row, 0, 0), DryRun: dryRun}
			return nil
		})
	if err != nil {
		return auth.GroupMutation{}, hinted(err)
	}
	return result, nil
}

// UpdateGroup changes only the supplied fields. A rename keeps the group's
// UUID, so its memberships and grants follow it; a colliding rename is refused
// before the statement runs and leaves every field, updated_at included, as it
// was.
func (s *LocalAuth) UpdateGroup(ctx context.Context, session auth.Session, ref string,
	update auth.GroupUpdate, dryRun bool) (auth.GroupMutation, error) {
	var result auth.GroupMutation
	if update.Name == nil && update.Description == nil {
		return result, invalidArgument(hintGroupUpdate)
	}
	if update.Name != nil && !auth.ValidGroupName(*update.Name) {
		return result, invalidArgument(hintGroupName)
	}
	if update.Description != nil && !validText(*update.Description, auth.MaxDescriptionLength) {
		return result, invalidArgument(hintGroupDescription)
	}
	err := s.administer(ctx, session, groupMutationLock, "", dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			row, err := lockGroup(ctx, queries, ref)
			if err != nil {
				return err
			}
			if update.Name != nil && *update.Name != row.Name {
				exists, err := queries.GroupNameExists(ctx, *update.Name)
				if err != nil {
					return err
				}
				if exists {
					return groupExists()
				}
			}
			updated, err := nameGuarded(ctx, tx, groupExists(), func(q *sqlc.Queries) (sqlc.Group, error) {
				return q.UpdateGroup(ctx, sqlc.UpdateGroupParams{
					ID: row.ID, Name: update.Name, Description: update.Description,
				})
			})
			if err != nil {
				return err
			}
			record, err := groupCounts(ctx, queries, updated)
			if err != nil {
				return err
			}
			result = auth.GroupMutation{Group: record, DryRun: dryRun}
			return nil
		})
	if err != nil {
		return auth.GroupMutation{}, hinted(err)
	}
	return result, nil
}

// DeleteGroup removes a group that holds no grants, taking its memberships
// with it: membership alone confers nothing, so cascading them is honest,
// while a grant is access somebody configured and has to be revoked first.
func (s *LocalAuth) DeleteGroup(ctx context.Context, session auth.Session, ref string,
	dryRun bool) (auth.GroupDeletion, error) {
	var result auth.GroupDeletion
	// The denial carries the code alone, so the counted hint is kept here and
	// re-attached to the error administer returns; a dry run answers with the
	// same count, which is the point of asking.
	var guard string
	err := s.administer(ctx, session, groupMutationLock, "", dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			row, err := lockGroup(ctx, queries, ref)
			if err != nil {
				return err
			}
			grants, err := queries.CountGroupGrants(ctx, row.ID)
			if err != nil {
				return err
			}
			if grants > 0 {
				guard = hintRemainingGrants(grants)
				return &auth.Error{Code: auth.GroupInUse, Hint: guard}
			}
			removed, err := queries.DeleteGroup(ctx, row.ID)
			if err != nil {
				return err
			}
			if removed != 1 {
				return unavailable()
			}
			result = auth.GroupDeletion{Group: groupParty(row), DryRun: dryRun}
			return nil
		})
	if err != nil {
		var failure *auth.Error
		if guard != "" && errors.As(err, &failure) && failure.Code == auth.GroupInUse {
			failure.Hint = guard
		}
		return auth.GroupDeletion{}, hinted(err)
	}
	return result, nil
}

// AddMember is idempotent: a user who already belongs is returned with Added
// false and their stored row untouched, so a retrying agent changes nothing.
func (s *LocalAuth) AddMember(ctx context.Context, session auth.Session, groupRef, userRef string,
	dryRun bool) (auth.MembershipMutation, error) {
	var result auth.MembershipMutation
	// The user reference is the ordered row lock administer takes, so a
	// membership change and a block of the same user serialize on that row.
	err := s.administer(ctx, session, groupMutationLock, userRef, dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, actor auth.Session) error {
			queries := sqlc.New(tx)
			group, user, err := membershipParties(ctx, queries, groupRef, userRef)
			if err != nil {
				return err
			}
			_, err = queries.InsertGroupMember(ctx, sqlc.InsertGroupMemberParams{
				GroupID: group.ID, UserID: user.ID, CreatedBy: actor.User.ID,
			})
			// The insert declines a conflict rather than failing, so no row
			// means the user was already a member.
			existed := errors.Is(err, pgx.ErrNoRows)
			if err != nil && !existed {
				return err
			}
			row, err := queries.FindGroupMember(ctx, sqlc.FindGroupMemberParams{
				GroupID: group.ID, UserID: user.ID,
			})
			if err != nil {
				return err
			}
			result = auth.MembershipMutation{
				Membership: membershipRecord(row), Added: !existed, DryRun: dryRun,
			}
			return nil
		})
	if err != nil {
		return auth.MembershipMutation{}, hinted(err)
	}
	return result, nil
}

// RemoveMember succeeds whether or not the user belonged; removing nothing
// reports Removed false and changes no row.
func (s *LocalAuth) RemoveMember(ctx context.Context, session auth.Session, groupRef, userRef string,
	dryRun bool) (auth.MembershipRemoval, error) {
	var result auth.MembershipRemoval
	err := s.administer(ctx, session, groupMutationLock, userRef, dryRun, nil,
		func(ctx context.Context, tx pgx.Tx, _ auth.Session) error {
			queries := sqlc.New(tx)
			group, user, err := membershipParties(ctx, queries, groupRef, userRef)
			if err != nil {
				return err
			}
			removed, err := queries.DeleteGroupMember(ctx, sqlc.DeleteGroupMemberParams{
				GroupID: group.ID, UserID: user.ID,
			})
			if err != nil {
				return err
			}
			result = auth.MembershipRemoval{
				Group:   groupParty(group),
				User:    auth.GrantParty{ID: user.ID, Name: user.Username},
				Removed: removed > 0, DryRun: dryRun,
			}
			return nil
		})
	if err != nil {
		return auth.MembershipRemoval{}, hinted(err)
	}
	return result, nil
}
