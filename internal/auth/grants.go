package auth

import (
	"context"
	"time"
)

// Grant routes: GET GrantsPath lists, POST GrantsPath creates, POST
// GrantRevokePath revokes. Users and connections are referenced by UUID or
// name in request bodies and query parameters.
const (
	GrantsPath      = "/api/admin/grants"
	GrantRevokePath = "/api/admin/grants/revoke"
	MaxGrantListing = 1000
)

// GrantParty identifies one side of a grant with both its stable UUID and its
// human name (username or connection name), so agents never need a lookup.
type GrantParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Grant struct {
	User       GrantParty `json:"user"`
	Connection GrantParty `json:"connection"`
	CreatedAt  time.Time  `json:"createdAt"`
	CreatedBy  GrantParty `json:"createdBy"`
}

type GrantList struct {
	Grants    []Grant `json:"grants"`
	Truncated bool    `json:"truncated"`
}

// GrantRequest carries references, each a UUID or a name.
type GrantRequest struct {
	User       string `json:"user"`
	Connection string `json:"connection"`
}

// GrantFilter narrows a listing; empty fields mean no filter. Limit at or
// below zero or above MaxGrantListing means MaxGrantListing.
type GrantFilter struct {
	User       string
	Connection string
	Limit      int
}

// GrantMutation reports the grant after create; Created is false when the
// grant already existed, in which case no event was recorded.
type GrantMutation struct {
	Grant   Grant `json:"grant"`
	Created bool  `json:"created"`
	DryRun  bool  `json:"dryRun"`
}

// GrantRevocation reports whether a grant was removed; Revoked false means
// there was nothing to remove and no event was recorded.
type GrantRevocation struct {
	User       GrantParty `json:"user"`
	Connection GrantParty `json:"connection"`
	Revoked    bool       `json:"revoked"`
	DryRun     bool       `json:"dryRun"`
}

// Grants is the grant lifecycle plus the single authorization answer every
// later operation asks before forwarding anything to an external source.
// AuthorizeConnection returns the connection only when it is enabled and the
// caller is an administrator or holds a grant; it records no event of its own.
type Grants interface {
	ListGrants(context.Context, Session, GrantFilter) (GrantList, error)
	CreateGrant(context.Context, Session, GrantRequest, bool) (GrantMutation, error)
	RevokeGrant(context.Context, Session, GrantRequest, bool) (GrantRevocation, error)
	AuthorizeConnection(context.Context, Session, string) (Connection, error)
}

// ValidUserRef accepts a user UUID or a username. A username can never be
// UUID-shaped, so the two forms cannot collide.
func ValidUserRef(value string) bool {
	return ValidUserID(value) || ValidUsername(value)
}
