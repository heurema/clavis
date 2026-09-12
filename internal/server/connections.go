package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/heurema/clavis/internal/auth"
)

// hintEmptyUpdate is the one hint this adapter owns. Every other hint belongs
// to the service, which knows which field or range a request violated; an
// empty update never reaches it, so the guidance has to be given here.
const hintEmptyUpdate = "Provide at least one field to update"

// The connection service owns readiness, authority rechecks and its own
// events, exactly like user administration; a composition without one must
// reject protected requests instead of invoking anything.
func (a *authHTTP) requireConnections() error {
	if a.connections == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

// connection is the shared shape of every JSON connection route, and mirrors
// administration: bounded body and query handling first, then a bearer-only
// session, then the path target, then the service call that owns its own
// success and denial events. Routes with a {connectionID} segment pass
// targeted=true so an unusable reference (including the empty segment of a
// doubled slash) is rejected here and recorded like any other adapter
// rejection, never resolved by the service.
func (a *authHTTP) connection(w http.ResponseWriter, r *http.Request, targeted bool, body func() error,
	call func(auth.Session, string) (any, int, error)) {
	var err error
	if body != nil {
		err = body()
	}
	var session auth.Session
	if err == nil {
		session, err = a.cliSession(r)
	}
	target := chi.URLParam(r, "connectionID")
	if err == nil && targeted && !auth.ValidConnectionRef(target) {
		err = invalidArgument()
	}
	if err == nil {
		err = a.requireConnections()
	}
	if err != nil {
		jsonFailure(w, err)
		return
	}
	serviceOwnsEvent(r)
	result, status, err := call(session, target)
	if err != nil {
		jsonFailure(w, err)
		return
	}
	writeJSON(w, status, result)
}

// query returns the request's parameters after refusing anything the route
// does not document: an unparsable query string, an unknown parameter and a
// repeated one. Routes that take none pass no names at all.
func query(r *http.Request, allowed ...string) (url.Values, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, invalidArgument()
	}
	for name, value := range values {
		if !slices.Contains(allowed, name) || len(value) != 1 {
			return nil, invalidArgument()
		}
	}
	return values, nil
}

// dryRun reads the one documented mutation query parameter. Only the literal
// "true" requests a dry run; every other spelling is a rejection rather than a
// silent commit.
func dryRun(r *http.Request) (bool, error) {
	values, err := query(r, auth.DryRunQuery)
	if err != nil {
		return false, err
	}
	raw, present := values[auth.DryRunQuery]
	if !present {
		return false, nil
	}
	if raw[0] != "true" {
		return false, invalidArgument()
	}
	return true, nil
}

// boundedSecret keeps an oversized credential out of the service without
// judging its content. Text lengths, an empty secret and every other value
// rule are the service's to reject, so its hint reaches the caller; the body
// is already bounded to 8 KiB and nothing here is hashed or sealed.
func boundedSecret(secret auth.Secret) error {
	if len(secret) > auth.MaxSecretBytes {
		return invalidArgument()
	}
	return nil
}

func (a *authHTTP) listConnectionsJSON(w http.ResponseWriter, r *http.Request) {
	var terms []auth.SelectorTerm
	limit := auth.MaxConnectionListing
	a.connection(w, r, false, func() error {
		values, err := query(r, "selector", "limit")
		if err != nil {
			return err
		}
		if err := emptyBody(r); err != nil {
			return err
		}
		parsed, ok := auth.ParseSelector(values.Get("selector"))
		if !ok {
			return invalidArgument()
		}
		terms = parsed
		if raw, present := values["limit"]; present {
			value, convErr := strconv.Atoi(raw[0])
			if convErr != nil || value < 1 || value > auth.MaxConnectionListing {
				return invalidArgument()
			}
			limit = value
		}
		return nil
	}, func(session auth.Session, _ string) (any, int, error) {
		list, err := a.connections.ListConnections(r.Context(), session, terms, limit)
		if err != nil {
			return nil, 0, err
		}
		bounded, err := boundedListing(list)
		if err != nil {
			return nil, 0, err
		}
		return bounded, http.StatusOK, nil
	})
}

// boundedListing keeps the encoded listing inside the documented body limit.
// The row bound alone cannot guarantee it: a thousand records with long text
// and sixteen labels each are far larger than the budget, so trailing records
// are dropped in name order and the response says so, exactly as it does when
// the row bound truncates.
func boundedListing(list auth.ConnectionList) (auth.ConnectionList, error) {
	// The envelope with the longer "false" and the encoder's trailing newline.
	size := len(`{"connections":[],"truncated":false}`) + 1
	kept := 0
	for index, record := range list.Connections {
		encoded, err := json.Marshal(record)
		if err != nil {
			return auth.ConnectionList{}, &auth.Error{Code: auth.ServiceUnavailable}
		}
		next := size + len(encoded)
		if index > 0 {
			next++ // the separating comma
		}
		if next > auth.MaxListingBody {
			break
		}
		size = next
		kept++
	}
	if kept == len(list.Connections) {
		return list, nil
	}
	return auth.ConnectionList{Connections: list.Connections[:kept], Truncated: true}, nil
}

func (a *authHTTP) createConnectionJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.CreateConnectionRequest
	var dry bool
	a.connection(w, r, false, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		if err = decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
			"name":               jsonString(func(value string) { request.Name = value }),
			"title":              jsonString(func(value string) { request.Title = value }),
			"description":        jsonString(func(value string) { request.Description = value }),
			"scope":              jsonString(func(value string) { request.Scope = value }),
			"provider":           jsonString(func(value string) { request.Provider = auth.ProviderType(value) }),
			"target":             jsonStringMap(func(value map[string]string) { request.Target = value }),
			"labels":             jsonStringMap(func(value map[string]string) { request.Labels = value }),
			"statementTimeoutMs": jsonInt(func(value int) { request.StatementTimeoutMS = value }),
			"maxRows":            jsonInt(func(value int) { request.MaxRows = value }),
			"maxBytes":           jsonInt(func(value int) { request.MaxBytes = value }),
			"secret":             jsonString(func(value string) { request.Secret = auth.Secret(value) }),
		}); err != nil {
			return err
		}
		return boundedSecret(request.Secret)
	}, func(session auth.Session, _ string) (any, int, error) {
		mutation, err := a.connections.CreateConnection(r.Context(), session, request, dry)
		if err != nil {
			return nil, 0, err
		}
		// A committed creation answers 201 with the record; a dry run answers
		// 200 with the mutation it would have made.
		if dry {
			return mutation, http.StatusOK, nil
		}
		return mutation.Connection, http.StatusCreated, nil
	})
}

func (a *authHTTP) getConnectionJSON(w http.ResponseWriter, r *http.Request) {
	a.connection(w, r, true, func() error {
		if _, err := query(r); err != nil {
			return err
		}
		return emptyBody(r)
	}, func(session auth.Session, target string) (any, int, error) {
		record, err := a.connections.GetConnection(r.Context(), session, target)
		return record, http.StatusOK, err
	})
}

func (a *authHTTP) updateConnectionJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.UpdateConnectionRequest
	var dry bool
	a.connection(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		if err = decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
			"name":               jsonString(func(value string) { request.Name = &value }),
			"title":              jsonString(func(value string) { request.Title = &value }),
			"description":        jsonString(func(value string) { request.Description = &value }),
			"scope":              jsonString(func(value string) { request.Scope = &value }),
			"target":             jsonStringMap(func(value map[string]string) { request.Target = &value }),
			"labels":             jsonStringMap(func(value map[string]string) { request.Labels = &value }),
			"statementTimeoutMs": jsonInt(func(value int) { request.StatementTimeoutMS = &value }),
			"maxRows":            jsonInt(func(value int) { request.MaxRows = &value }),
			"maxBytes":           jsonInt(func(value int) { request.MaxBytes = &value }),
		}); err != nil {
			return err
		}
		if !updatesAnything(request) {
			return &auth.Error{Code: auth.InvalidArgument, Hint: hintEmptyUpdate}
		}
		title, description, scope := "", "", ""
		for _, field := range []struct {
			value *string
			into  *string
		}{{request.Title, &title}, {request.Description, &description}, {request.Scope, &scope}} {
			if field.value != nil {
				*field.into = *field.value
			}
		}
		return nil
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.connections.UpdateConnection(r.Context(), session, target, request, dry)
		return mutation, http.StatusOK, err
	})
}

// updatesAnything reports whether the body supplied a field at all. An update
// that changes nothing is a malformed request, not a no-op mutation with an
// event.
func updatesAnything(request auth.UpdateConnectionRequest) bool {
	return request.Name != nil || request.Title != nil || request.Description != nil ||
		request.Scope != nil || request.Target != nil || request.Labels != nil ||
		request.StatementTimeoutMS != nil || request.MaxRows != nil || request.MaxBytes != nil
}

func (a *authHTTP) setConnectionCredentialsJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.SetConnectionCredentialsRequest
	var dry, supplied bool
	a.connection(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		if err = decodeFields(r, auth.MaxCredentialBody, map[string]jsonValue{
			"secret": jsonString(func(value string) { request.Secret, supplied = auth.Secret(value), true }),
		}); err != nil {
			return err
		}
		// The member must be present: an empty secret is meaningful for the one
		// authentication method that takes none, so it has to be asked for
		// rather than inferred from an empty body. The stored connection
		// decides whether its method accepts it, so only the size is checked.
		if !supplied || len(request.Secret) > auth.MaxSecretBytes {
			return invalidArgument()
		}
		return nil
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.connections.SetConnectionCredentials(r.Context(), session, target, request.Secret, dry)
		return mutation, http.StatusOK, err
	})
}

func (a *authHTTP) setConnectionEnabledJSON(w http.ResponseWriter, r *http.Request, enabled bool) {
	var dry bool
	a.connection(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return emptyBody(r)
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.connections.SetConnectionEnabled(r.Context(), session, target, enabled, dry)
		return mutation, http.StatusOK, err
	})
}

func (a *authHTTP) enableConnectionJSON(w http.ResponseWriter, r *http.Request) {
	a.setConnectionEnabledJSON(w, r, true)
}

func (a *authHTTP) disableConnectionJSON(w http.ResponseWriter, r *http.Request) {
	a.setConnectionEnabledJSON(w, r, false)
}

func (a *authHTTP) deleteConnectionJSON(w http.ResponseWriter, r *http.Request) {
	var dry bool
	a.connection(w, r, true, func() error {
		var err error
		if dry, err = dryRun(r); err != nil {
			return err
		}
		return emptyBody(r)
	}, func(session auth.Session, target string) (any, int, error) {
		deletion, err := a.connections.DeleteConnection(r.Context(), session, target, dry)
		return deletion, http.StatusOK, err
	})
}

// A check contacts the source, so it has nothing to rehearse: the route takes
// no dry-run parameter and a request that asks for one is rejected.
func (a *authHTTP) checkConnectionJSON(w http.ResponseWriter, r *http.Request) {
	a.connection(w, r, true, func() error {
		if _, err := query(r); err != nil {
			return err
		}
		return emptyBody(r)
	}, func(session auth.Session, target string) (any, int, error) {
		checked, err := a.connections.CheckConnection(r.Context(), session, target)
		return checked, http.StatusOK, err
	})
}
