package auth

import (
	"context"
	"time"
)

// Group routes: GET GroupsPath lists, POST GroupsPath creates. {groupID}
// accepts a UUID or a group name, like {connectionID}.
const (
	GroupsPath            = "/api/admin/groups"
	GroupPath             = "/api/admin/groups/{groupID}"
	GroupUpdatePath       = "/api/admin/groups/{groupID}/update"
	GroupDeletePath       = "/api/admin/groups/{groupID}/delete"
	GroupMembersPath      = "/api/admin/groups/{groupID}/members"
	GroupMemberAddPath    = "/api/admin/groups/{groupID}/members/add"
	GroupMemberRemovePath = "/api/admin/groups/{groupID}/members/remove"
)

// Bounds shared by the service, the routes and the CLI.
const (
	MaxGroupListing  = 1000
	MaxMemberListing = 1000
)

// Group is the safe projection of a group: identity, descriptive text, times
// and the two counts an administrator needs before deleting it.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Members     int       `json:"members"`
	Grants      int       `json:"grants"`
}

type GroupList struct {
	Groups    []Group `json:"groups"`
	Truncated bool    `json:"truncated"`
}

type GroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// GroupUpdate changes only the fields that are present; at least one must be.
type GroupUpdate struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type GroupMutation struct {
	Group  Group `json:"group"`
	DryRun bool  `json:"dryRun"`
}

// GroupDeletion reports the group that was removed. A group that does not
// exist is GROUP_NOT_FOUND rather than a deletion reporting false, because a
// delete names one row and the guard, not idempotency, decides the outcome.
type GroupDeletion struct {
	Group  GrantParty `json:"group"`
	DryRun bool       `json:"dryRun"`
}

// Membership links one user to one group, recording who added them and when.
type Membership struct {
	Group     GrantParty `json:"group"`
	User      GrantParty `json:"user"`
	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy GrantParty `json:"createdBy"`
}

// MembershipMutation reports the membership after an add; Added is false when
// the user was already a member, in which case the stored row was untouched.
type MembershipMutation struct {
	Membership Membership `json:"membership"`
	Added      bool       `json:"added"`
	DryRun     bool       `json:"dryRun"`
}

// MembershipRemoval reports whether a membership was removed; Removed false
// means there was nothing to remove.
type MembershipRemoval struct {
	Group   GrantParty `json:"group"`
	User    GrantParty `json:"user"`
	Removed bool       `json:"removed"`
	DryRun  bool       `json:"dryRun"`
}

// GroupMember is a group's member: the safe user record plus how the
// membership came about. Members never read this listing; it is
// administrator-only. The name keeps the Member role constant unambiguous.
type GroupMember struct {
	UserRecord
	AddedAt time.Time  `json:"addedAt"`
	AddedBy GrantParty `json:"addedBy"`
}

type MemberList struct {
	Members   []GroupMember `json:"members"`
	Truncated bool          `json:"truncated"`
}

// Groups is the administrator-only group lifecycle and membership management.
// Every method rechecks the actor's current session and role inside its own
// transaction; a dry run performs validation, authorization and guards, then
// rolls back. Group and user references are UUIDs or names.
type Groups interface {
	ListGroups(ctx context.Context, session Session, limit int) (GroupList, error)
	GetGroup(ctx context.Context, session Session, ref string) (Group, error)
	CreateGroup(ctx context.Context, session Session, request GroupRequest, dryRun bool) (GroupMutation, error)
	UpdateGroup(ctx context.Context, session Session, ref string, update GroupUpdate, dryRun bool) (GroupMutation, error)
	DeleteGroup(ctx context.Context, session Session, ref string, dryRun bool) (GroupDeletion, error)
	ListMembers(ctx context.Context, session Session, ref string, limit int) (MemberList, error)
	AddMember(ctx context.Context, session Session, groupRef, userRef string, dryRun bool) (MembershipMutation, error)
	RemoveMember(ctx context.Context, session Session, groupRef, userRef string, dryRun bool) (MembershipRemoval, error)
}

// ValidGroupName shares the username grammar, which already refuses the UUID
// shape, so a group reference that is a UUID can never be a name. Group names
// live in their own namespace: a user and a group may share a name and --user
// and --group keep every reference unambiguous.
func ValidGroupName(value string) bool { return ValidUsername(value) }

// ValidGroupRef accepts a group UUID or a group name.
func ValidGroupRef(value string) bool {
	return ValidUserID(value) || ValidGroupName(value)
}
