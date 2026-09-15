package auth

import (
	"context"
	"time"
)

// Grant routes: GET GrantsPath lists, POST GrantsPath creates, POST
// GrantRevokePath revokes, GET GrantsEffectivePath reports where one user's
// access comes from. Users, groups and connections are referenced by UUID or
// name in request bodies and query parameters.
const (
	GrantsPath          = "/api/admin/grants"
	GrantRevokePath     = "/api/admin/grants/revoke"
	GrantsEffectivePath = "/api/admin/grants/effective"
	MaxGrantListing     = 1000
	MaxAccessListing    = 1000
)

// GrantParty identifies one side of a grant with both its stable UUID and its
// human name (username, group name or connection name), so agents never need a
// lookup.
type GrantParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RecipientKind names the namespace a recipient's name belongs to. It is
// explicit rather than implied by which field is filled, so one rendering and
// one strict decoder cover both kinds.
type RecipientKind string

const (
	RecipientUser  RecipientKind = "user"
	RecipientGroup RecipientKind = "group"
)

// Recipient is the side of a grant that holds the access: one user or one
// group, never both.
type Recipient struct {
	Kind RecipientKind `json:"kind"`
	ID   string        `json:"id"`
	Name string        `json:"name"`
}

type Grant struct {
	Recipient  Recipient  `json:"recipient"`
	Connection GrantParty `json:"connection"`
	CreatedAt  time.Time  `json:"createdAt"`
	CreatedBy  GrantParty `json:"createdBy"`
}

type GrantList struct {
	Grants    []Grant `json:"grants"`
	Truncated bool    `json:"truncated"`
}

// RecipientHint states the one rule a grant request cannot be repaired from:
// which recipient the grant is keyed on. It names no submitted value.
const RecipientHint = "Name exactly one recipient, a user or a group: never both and never neither"

// GrantRequest carries references, each a UUID or a name. Exactly one of User
// and Group names the recipient.
type GrantRequest struct {
	User       string `json:"user"`
	Group      string `json:"group"`
	Connection string `json:"connection"`
}

// RecipientRef applies the exactly-one rule before any lookup: a request that
// names both recipients or neither has no recipient at all, which is an
// argument failure rather than a missing row. The reference's own syntax is
// the adapter's and the resolver's business, so an unusable one stays the
// not-found it has always been.
func (r GrantRequest) RecipientRef() (kind RecipientKind, ref string, ok bool) {
	switch {
	case r.User != "" && r.Group == "":
		return RecipientUser, r.User, true
	case r.Group != "" && r.User == "":
		return RecipientGroup, r.Group, true
	}
	return "", "", false
}

// ValidRecipientRef checks one resolved recipient reference against the
// grammar of its own namespace.
func ValidRecipientRef(kind RecipientKind, ref string) bool {
	if kind == RecipientGroup {
		return ValidGroupRef(ref)
	}
	return ValidUserRef(ref)
}

// GrantFilter narrows a listing; empty fields mean no filter. At most one
// recipient filter is meaningful. Limit at or below zero or above
// MaxGrantListing means MaxGrantListing.
type GrantFilter struct {
	User       string
	Group      string
	Connection string
	Limit      int
}

// GrantMutation reports the grant after create; Created is false when the
// grant already existed, in which case the stored row was left untouched.
type GrantMutation struct {
	Grant   Grant `json:"grant"`
	Created bool  `json:"created"`
	DryRun  bool  `json:"dryRun"`
}

// GrantRevocation reports whether a grant was removed; Revoked false means
// there was nothing to remove.
type GrantRevocation struct {
	Recipient  Recipient  `json:"recipient"`
	Connection GrantParty `json:"connection"`
	Revoked    bool       `json:"revoked"`
	DryRun     bool       `json:"dryRun"`
}

// The two sources of effective access, as each entry reports them.
const (
	AccessDirect = "direct"
	AccessGroup  = "group"
)

// AccessEntry is one configured path to a connection, never a claim that the
// connection can be used now: only AuthorizeConnection answers that.
type AccessEntry struct {
	Connection GrantParty  `json:"connection"`
	Source     string      `json:"source"`
	Group      *GrantParty `json:"group,omitempty"`
	CreatedAt  time.Time   `json:"createdAt"`
}

// AccessList carries the subject's own record beside the paths, because the
// record is what explains an administrator's bypass or a blocked account.
type AccessList struct {
	User      UserRecord    `json:"user"`
	Entries   []AccessEntry `json:"entries"`
	Truncated bool          `json:"truncated"`
}

// Grants is the grant lifecycle plus the single authorization answer every
// later operation asks before forwarding anything to an external source.
// AuthorizeConnection returns the connection only when it is enabled and the
// caller is an administrator or holds effective access, the union of their
// direct grants and the grants of every group they belong to; it changes no
// state of its own.
//
// ListEffectiveAccess reports where a subject's access comes from: an empty
// user reference means the caller, and the role rule that resolves the subject
// is the server's, never the client's.
type Grants interface {
	ListGrants(context.Context, Session, GrantFilter) (GrantList, error)
	CreateGrant(context.Context, Session, GrantRequest, bool) (GrantMutation, error)
	RevokeGrant(context.Context, Session, GrantRequest, bool) (GrantRevocation, error)
	AuthorizeConnection(context.Context, Session, string) (Connection, error)
	ListEffectiveAccess(ctx context.Context, session Session, userRef, connectionRef string, limit int) (AccessList, error)
}

// ValidUserRef accepts a user UUID or a username. A username can never be
// UUID-shaped, so the two forms cannot collide.
func ValidUserRef(value string) bool {
	return ValidUserID(value) || ValidUsername(value)
}
