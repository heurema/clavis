package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/heurema/clavis/internal/auth"
)

// MemberConnections is the member half of the connection read routes. It is
// declared here rather than in auth because it exists only so this adapter can
// choose a projection from the caller's current role; the same service value
// satisfies it and auth.Connections.
type MemberConnections interface {
	ListGrantedConnections(ctx context.Context, session auth.Session, terms []auth.SelectorTerm, limit int) (auth.ConnectionSummaryList, error)
	GetGrantedConnection(ctx context.Context, session auth.Session, ref string) (auth.ConnectionSummary, error)
	ListGrantedConnectionNames(ctx context.Context, session auth.Session, limit int) (names []string, truncated bool, err error)
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

// grantRequest decodes the two references both mutations take. Each is checked
// for shape before the service, so an unusable reference is an adapter
// rejection rather than a lookup.
func grantRequest(r *http.Request, request *auth.GrantRequest) error {
	if err := decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
		"user":       jsonString(func(value string) { request.User = value }),
		"connection": jsonString(func(value string) { request.Connection = value }),
	}); err != nil {
		return err
	}
	if !auth.ValidUserRef(request.User) || !auth.ValidConnectionRef(request.Connection) {
		return invalidArgument()
	}
	return nil
}

func (a *authHTTP) listGrantsJSON(w http.ResponseWriter, r *http.Request) {
	filter := auth.GrantFilter{Limit: auth.MaxGrantListing}
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
			filter.User = raw[0]
		}
		if raw, present := values["connection"]; present {
			if !auth.ValidConnectionRef(raw[0]) {
				return invalidArgument()
			}
			filter.Connection = raw[0]
		}
		if raw, present := values["limit"]; present {
			value, convErr := strconv.Atoi(raw[0])
			if convErr != nil || value < 1 || value > auth.MaxGrantListing {
				return invalidArgument()
			}
			filter.Limit = value
		}
		return nil
	}, func(session auth.Session) (any, int, error) {
		list, err := a.grants.ListGrants(r.Context(), session, filter)
		if err != nil {
			return nil, 0, err
		}
		grants, truncated, err := boundedListing("grants", list.Grants, list.Truncated)
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
