package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/heurema/clavis/internal/auth"
)

// The administration service owns readiness and authority rechecks exactly
// like the authentication service; a composition without one must reject
// protected requests instead of invoking anything.
func (a *authHTTP) requireAdministration() error {
	if a.admin == nil {
		return &auth.Error{Code: auth.ServiceUnavailable}
	}
	return nil
}

// administration is the shared shape of every JSON administration route:
// bounded body handling first, then a bearer-only session, then the path
// target, then the service call.
// Nothing submitted is hashed, looked up or reflected before the body and the
// target are accepted. Routes with a {userID} segment pass targeted=true so an
// empty segment (a doubled slash) is rejected here, not by the service.
func (a *authHTTP) administration(w http.ResponseWriter, r *http.Request, targeted bool, body func() error,
	call func(auth.Session, string) (any, int, error)) {
	var err error
	if body != nil {
		err = body()
	}
	var session auth.Session
	if err == nil {
		session, err = a.cliSession(r)
	}
	target := chi.URLParam(r, "userID")
	if err == nil && targeted && !auth.ValidUserRef(target) {
		err = &auth.Error{Code: auth.InvalidArgument}
	}
	if err == nil {
		err = a.requireAdministration()
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

// Listing is the only administration GET. It reads nothing from the request
// but the session, so any body is a malformed request.
func (a *authHTTP) listUsersJSON(w http.ResponseWriter, r *http.Request) {
	a.administration(w, r, false, func() error { return emptyBody(r) },
		func(session auth.Session, _ string) (any, int, error) {
			list, err := a.admin.ListUsers(r.Context(), session)
			return list, http.StatusOK, err
		})
}

func (a *authHTTP) createUserJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.CreateUserRequest
	a.administration(w, r, false, func() error {
		err := decodeJSON(r, auth.MaxCredentialBody, map[string]func(string){
			"username": func(value string) { request.Username = value },
			"password": func(value string) { request.Password = auth.Secret(value) },
		})
		if err != nil {
			return err
		}
		// The username rule, including the UUID-shape exclusion that keeps a
		// user reference unambiguous, is explained by a hint; the password
		// branch stays hint-free so no guidance is attached to a credential.
		if !auth.ValidUsername(request.Username) {
			return &auth.Error{Code: auth.InvalidArgument, Hint: auth.UsernameHint}
		}
		if !auth.ValidPassword(request.Password) {
			return &auth.Error{Code: auth.InvalidArgument}
		}
		return nil
	}, func(session auth.Session, _ string) (any, int, error) {
		record, err := a.admin.CreateUser(r.Context(), session, request)
		return record, http.StatusCreated, err
	})
}

func (a *authHTTP) setUserDisabledJSON(w http.ResponseWriter, r *http.Request, disabled bool) {
	a.administration(w, r, true, func() error { return emptyBody(r) },
		func(session auth.Session, target string) (any, int, error) {
			mutation, err := a.admin.SetUserDisabled(r.Context(), session, target, disabled)
			return mutation, http.StatusOK, err
		})
}

func (a *authHTTP) blockUserJSON(w http.ResponseWriter, r *http.Request) {
	a.setUserDisabledJSON(w, r, true)
}

func (a *authHTTP) unblockUserJSON(w http.ResponseWriter, r *http.Request) {
	a.setUserDisabledJSON(w, r, false)
}

func (a *authHTTP) resetPasswordJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.ResetPasswordRequest
	a.administration(w, r, true, func() error {
		err := decodeJSON(r, auth.MaxCredentialBody, map[string]func(string){
			"password": func(value string) { request.Password = auth.Secret(value) },
		})
		if err != nil {
			return err
		}
		if !auth.ValidPassword(request.Password) {
			return &auth.Error{Code: auth.InvalidArgument}
		}
		return nil
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.admin.ResetPassword(r.Context(), session, target, request.Password)
		return mutation, http.StatusOK, err
	})
}

func (a *authHTTP) setRoleJSON(w http.ResponseWriter, r *http.Request) {
	var request auth.SetRoleRequest
	a.administration(w, r, true, func() error {
		err := decodeJSON(r, auth.MaxCredentialBody, map[string]func(string){
			"role": func(value string) { request.Role = auth.Role(value) },
		})
		if err != nil {
			return err
		}
		if request.Role != auth.Admin && request.Role != auth.Member {
			return &auth.Error{Code: auth.InvalidArgument}
		}
		return nil
	}, func(session auth.Session, target string) (any, int, error) {
		mutation, err := a.admin.SetRole(r.Context(), session, target, request.Role)
		return mutation, http.StatusOK, err
	})
}
