package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/heurema/clavis/internal/auth"
)

// hintGroupName is the adapter's own guidance for the one name a group request
// chooses rather than resolves, and the counterpart of the username hint user
// creation gives. Every other group hint belongs to the service, which knows
// which row or guard a request ran into; a malformed name never reaches it, so
// the rule has to be stated here. It names no submitted value.
const hintGroupName = "A group name matches [a-z][a-z0-9._-]{2,63} and is never shaped like a UUID"

// The group service owns readiness and authority rechecks, exactly like user
// administration and connections; a composition without one must reject
// protected requests instead of invoking anything.
func (a *authHTTP) requireGroups() error {
	if a.groups == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

// group is the shared shape of every JSON group route and mirrors connections:
// bounded body and query handling first, then a bearer-only session, then the
// path target, then the service call. Routes with a {groupID} segment pass
// targeted=true so an unusable reference (including the empty segment of a
// doubled slash) is rejected here, never resolved by the service. Listing and
// reading are not restricted to administrators here either: the service
// rechecks the actor's current role inside its own transaction and answers
// FORBIDDEN, so one authority decision covers every route.
func (a *authHTTP) group(w http.ResponseWriter, r *http.Request, targeted bool, body func() error,
	call func(auth.Session, string) (any, int, error)) {
	var err error
	if body != nil {
		err = body()
	}
	var session auth.Session
	if err == nil {
		session, err = a.cliSession(r)
	}
	target := chi.URLParam(r, "groupID")
	if err == nil && targeted && !auth.ValidGroupRef(target) {
		err = invalidArgument()
	}
	if err == nil {
		err = a.requireGroups()
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	result, status, err := call(session, target)
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, status, result)
}

// listingLimit reads the one bounded-listing parameter the read routes share.
// An absent parameter asks for the documented bound rather than for nothing.
func listingLimit(values map[string][]string, bound int, limit *int) error {
	raw, present := values["limit"]
	if !present {
		return nil
	}
	value, err := strconv.Atoi(raw[0])
	if err != nil || value < 1 || value > bound {
		return invalidArgument()
	}
	*limit = value
	return nil
}

func (a *authHTTP) listGroupsJSON(w http.ResponseWriter, r *http.Request) {
	limit := auth.MaxGroupListing
	a.group(w, r, false, func() error {
		values, err := query(r, "limit")
		if err != nil {
			return err
		}
		if err := emptyBody(r); err != nil {
			return err
		}
		return listingLimit(values, auth.MaxGroupListing, &limit)
	}, func(session auth.Session, _ string) (any, int, error) {
		list, err := a.groups.ListGroups(r.Context(), session, limit)
		if err != nil {
			return nil, 0, err
		}
		records, truncated, err := boundedListing("groups", list.Groups, list.Truncated, 0)
		if err != nil {
			return nil, 0, err
		}
		return auth.GroupList{Groups: records, Truncated: truncated}, http.StatusOK, nil
	})
}

func (a *authHTTP) createGroupJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.GroupRequest
	var dry bool
	a.group(w, r, false, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		if err = decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
			"name":        jsonString(func(value string) { request.Name = value }),
			"description": jsonString(func(value string) { request.Description = value }),
		}); err != nil {
			return err
		}
		// The name rule, including the UUID-shape exclusion that keeps a group
		// reference unambiguous, is explained by a hint. The description's
		// character bound is the service's: it owns the stored value.
		if !auth.ValidGroupName(request.Name) {
			return &auth.Error{Code: auth.InvalidArgument, Hint: hintGroupName}
		}
		return nil
	}, func(session auth.Session, _ string) (any, int, error) {
		mutation, err := a.groups.CreateGroup(r.Context(), session, request, dry)
		if err != nil {
			return nil, 0, err
		}
		// A committed creation answers 201; a dry run answers 200 with the
		// mutation it would have made.
		if dry {
			return mutation, http.StatusOK, nil
		}
		return mutation, http.StatusCreated, nil
	})
}

func (a *authHTTP) getGroupJSON(w http.ResponseWriter, r *http.Request) {
	a.group(w, r, true, func() error {
		if _, err := query(r); err != nil {
			return err
		}
		return emptyBody(r)
	}, func(session auth.Session, target string) (any, int, error) {
		record, err := a.groups.GetGroup(r.Context(), session, target)
		return record, http.StatusOK, err
	})
}

func (a *authHTTP) updateGroupJSON(w http.ResponseWriter, r *http.Request) {
	var update auth.GroupUpdate
	var dry bool
	a.group(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		if err = decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
			"name":        jsonString(func(value string) { update.Name = &value }),
			"description": jsonString(func(value string) { update.Description = &value }),
		}); err != nil {
			return err
		}
		// An update that changes nothing is a malformed request, not a no-op
		// mutation, and never reaches the service.
		if update.Name == nil && update.Description == nil {
			return &auth.Error{Code: auth.InvalidArgument, Hint: hintEmptyUpdate}
		}
		if update.Name != nil && !auth.ValidGroupName(*update.Name) {
			return &auth.Error{Code: auth.InvalidArgument, Hint: hintGroupName}
		}
		return nil
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.groups.UpdateGroup(r.Context(), session, target, update, dry)
		return mutation, http.StatusOK, err
	})
}

func (a *authHTTP) deleteGroupJSON(w http.ResponseWriter, r *http.Request) {
	var dry bool
	a.group(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return emptyBody(r)
	}, func(session auth.Session, target string) (any, int, error) {
		deletion, err := a.groups.DeleteGroup(r.Context(), session, target, dry)
		return deletion, http.StatusOK, err
	})
}

func (a *authHTTP) listMembersJSON(w http.ResponseWriter, r *http.Request) {
	limit := auth.MaxMemberListing
	a.group(w, r, true, func() error {
		values, err := query(r, "limit")
		if err != nil {
			return err
		}
		if err := emptyBody(r); err != nil {
			return err
		}
		return listingLimit(values, auth.MaxMemberListing, &limit)
	}, func(session auth.Session, target string) (any, int, error) {
		list, err := a.groups.ListMembers(r.Context(), session, target, limit)
		if err != nil {
			return nil, 0, err
		}
		records, truncated, err := boundedListing("members", list.Members, list.Truncated, 0)
		if err != nil {
			return nil, 0, err
		}
		return auth.MemberList{Members: records, Truncated: truncated}, http.StatusOK, nil
	})
}

// membershipRequest decodes the one reference a membership mutation takes. The
// group is on the path; only the user travels in the body, and its shape is
// checked before the service, so an unusable reference is an adapter rejection
// rather than a lookup.
func membershipRequest(r *http.Request, userRef *string) error {
	if err := decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
		"user": jsonString(func(value string) { *userRef = value }),
	}); err != nil {
		return err
	}
	if !auth.ValidUserRef(*userRef) {
		return invalidArgument()
	}
	return nil
}

func (a *authHTTP) addMemberJSON(w http.ResponseWriter, r *http.Request) {
	var userRef string
	var dry bool
	a.group(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return membershipRequest(r, &userRef)
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.groups.AddMember(r.Context(), session, target, userRef, dry)
		if err != nil {
			return nil, 0, err
		}
		// A committed membership answers 201; one that already existed and a
		// dry run both answer 200 with the mutation they would have made.
		if mutation.Added && !dry {
			return mutation, http.StatusCreated, nil
		}
		return mutation, http.StatusOK, nil
	})
}

func (a *authHTTP) removeMemberJSON(w http.ResponseWriter, r *http.Request) {
	var userRef string
	var dry bool
	a.group(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return membershipRequest(r, &userRef)
	}, func(session auth.Session, target string) (any, int, error) {
		removal, err := a.groups.RemoveMember(r.Context(), session, target, userRef, dry)
		return removal, http.StatusOK, err
	})
}
