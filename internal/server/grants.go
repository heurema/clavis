package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/heurema/clavis/internal/auth"
)

// MemberConnections is the member half of the connection read routes plus the
// two name listings the identity route fills. It is declared here rather than
// in auth because it exists only so this adapter can choose a projection from
// the caller's current role; the same service value satisfies it and
// auth.Connections. ListGroupNames is filled for every caller, unlike the
// connection names, because an administrator belongs to groups like anybody
// else even though their access does not depend on them.
type MemberConnections interface {
	ListGrantedConnections(ctx context.Context, session auth.Session, terms []auth.SelectorTerm, limit int) (auth.ConnectionSummaryList, error)
	GetGrantedConnection(ctx context.Context, session auth.Session, ref string) (auth.ConnectionSummary, error)
	ListGrantedConnectionNames(ctx context.Context, session auth.Session, limit int) (names []string, truncated bool, err error)
	// ListGroupNames fills the identity's groups for every caller, member and
	// administrator alike: a group is a fact about the account rather than a
	// grant, so it is reported whatever the role.
	ListGroupNames(ctx context.Context, session auth.Session, limit int) (names []string, truncated bool, err error)
}

// The grant service owns readiness and authority rechecks, exactly like user
// administration and connections; a composition without one must reject
// protected requests instead of invoking anything.
func (a *authHTTP) requireGrants() error {
	if a.grants == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

func (a *authHTTP) requireMembers() error {
	if a.members == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

// grant is the shared shape of every JSON grant route and mirrors connections:
// bounded query and body handling first, then a bearer-only session, then the
// service call. The routes carry no path target, so both references are validated out of the body or the query
// before anything reaches the service. Listing is deliberately not restricted
// to administrators here: the service scopes a member to their own grants.
func (a *authHTTP) grant(w http.ResponseWriter, r *http.Request, body func() error,
	call func(auth.Session) (any, int, error)) {
	var err error
	if body != nil {
		err = body()
	}
	var session auth.Session
	if err == nil {
		session, err = a.cliSession(r)
	}
	if err == nil {
		err = a.requireGrants()
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	result, status, err := call(session)
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, status, result)
}

// grantRequest decodes the references both mutations take: the connection and
// exactly one recipient. Each is checked for shape before the service, so an
// unusable reference is an adapter rejection rather than a lookup, and a body
// naming both recipients or neither is refused with the rule it broke.
func grantRequest(r *http.Request, request *auth.GrantRequest) error {
	if err := decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
		"user":       jsonString(func(value string) { request.User = value }),
		"group":      jsonString(func(value string) { request.Group = value }),
		"connection": jsonString(func(value string) { request.Connection = value }),
	}); err != nil {
		return err
	}
	kind, recipient, ok := request.RecipientRef()
	if !ok {
		return &auth.Error{Code: auth.InvalidArgument, Hint: auth.RecipientHint}
	}
	if !auth.ValidRecipientRef(kind, recipient) || !auth.ValidConnectionRef(request.Connection) {
		return invalidArgument()
	}
	return nil
}

func (a *authHTTP) listGrantsJSON(w http.ResponseWriter, r *http.Request) {
	filter := auth.GrantFilter{Limit: auth.MaxGrantListing}
	a.grant(w, r, func() error {
		values, err := query(r, "user", "group", "connection", "limit")
		if err != nil {
			return err
		}
		if err := emptyBody(r); err != nil {
			return err
		}
		if raw, present := values["user"]; present {
			if !auth.ValidUserRef(raw[0]) {
				return invalidArgument()
			}
			filter.User = raw[0]
		}
		// Both recipient filters are accepted here and the service decides what
		// naming two of them means: the adapter refuses only a reference whose
		// shape belongs to no namespace at all.
		if raw, present := values["group"]; present {
			if !auth.ValidGroupRef(raw[0]) {
				return invalidArgument()
			}
			filter.Group = raw[0]
		}
		if raw, present := values["connection"]; present {
			if !auth.ValidConnectionRef(raw[0]) {
				return invalidArgument()
			}
			filter.Connection = raw[0]
		}
		return listingLimit(values, auth.MaxGrantListing, &filter.Limit)
	}, func(session auth.Session) (any, int, error) {
		list, err := a.grants.ListGrants(r.Context(), session, filter)
		if err != nil {
			return nil, 0, err
		}
		grants, truncated, err := boundedListing("grants", list.Grants, list.Truncated, 0)
		if err != nil {
			return nil, 0, err
		}
		return auth.GrantList{Grants: grants, Truncated: truncated}, http.StatusOK, nil
	})
}

func (a *authHTTP) createGrantJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.GrantRequest
	var dry bool
	a.grant(w, r, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return grantRequest(r, &request)
	}, func(session auth.Session) (any, int, error) {
		mutation, err := a.grants.CreateGrant(r.Context(), session, request, dry)
		if err != nil {
			return nil, 0, err
		}
		// A committed creation answers 201; a grant that already existed and a
		// dry run both answer 200 with the mutation they would have made.
		if mutation.Created && !dry {
			return mutation, http.StatusCreated, nil
		}
		return mutation, http.StatusOK, nil
	})
}

func (a *authHTTP) revokeGrantJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.GrantRequest
	var dry bool
	a.grant(w, r, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return grantRequest(r, &request)
	}, func(session auth.Session) (any, int, error) {
		revocation, err := a.grants.RevokeGrant(r.Context(), session, request, dry)
		return revocation, http.StatusOK, err
	})
}

// subjectBytes is what the effective envelope carries besides the entries: the
// `"user":<record>,` member. It is measured rather than estimated so the whole
// document, not only the entries, stays inside the listing limit.
func subjectBytes(record auth.UserRecord) (int, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return 0, &auth.Error{Code: auth.ServiceUnavailable}
	}
	return len(`"user":,`) + len(encoded), nil
}

// listEffectiveAccessJSON reports where one subject's access comes from. The
// subject is a reference the server resolves after rechecking the session: an
// omitted user means the caller and the role rule is the service's, so the
// adapter refuses only a reference no namespace could hold.
func (a *authHTTP) listEffectiveAccessJSON(w http.ResponseWriter, r *http.Request) {
	var userRef, connectionRef string
	limit := auth.MaxAccessListing
	a.grant(w, r, func() error {
		values, err := query(r, "user", "connection", "limit")
		if err != nil {
			return err
		}
		if err := emptyBody(r); err != nil {
			return err
		}
		if raw, present := values["user"]; present {
			if !auth.ValidUserRef(raw[0]) {
				return invalidArgument()
			}
			userRef = raw[0]
		}
		if raw, present := values["connection"]; present {
			if !auth.ValidConnectionRef(raw[0]) {
				return invalidArgument()
			}
			connectionRef = raw[0]
		}
		return listingLimit(values, auth.MaxAccessListing, &limit)
	}, func(session auth.Session) (any, int, error) {
		list, err := a.grants.ListEffectiveAccess(r.Context(), session, userRef, connectionRef, limit)
		if err != nil {
			return nil, 0, err
		}
		reserved, err := subjectBytes(list.User)
		if err != nil {
			return nil, 0, err
		}
		entries, truncated, err := boundedListing("entries", list.Entries, list.Truncated, reserved)
		if err != nil {
			return nil, 0, err
		}
		return auth.AccessList{User: list.User, Entries: entries, Truncated: truncated}, http.StatusOK, nil
	})
}
