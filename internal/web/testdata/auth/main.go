// This isolated view exporter is not linked into the production server.
// Its responses derive from the frozen auth outcome functions, not a database.
package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"

	"github.com/a-h/templ"
	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
	"github.com/heurema/clavis/internal/web"
)

type response struct {
	Status      int
	Location    string
	ClearCookie bool
	Body        string
}

func document(outcome auth.BrowserOutcome, view templ.Component) response {
	result := response{Status: outcome.Status, Location: outcome.Location, ClearCookie: outcome.ClearCookie}
	if view != nil {
		recorder := httptest.NewRecorder()
		if err := web.Render(recorder, httptest.NewRequest("GET", "/", nil), outcome.Status, view); err != nil {
			panic(err)
		}
		result.Body = recorder.Body.String()
	}
	return result
}

func main() {
	views := map[string]response{
		"login":         document(auth.BrowserOutcome{Status: 200}, web.Login(web.LoginModel{})),
		"admin":         document(auth.AdminOutcome(nil), web.Admin(web.AdminModel{User: auth.User{Username: "fixture.admin", Role: auth.Admin}})),
		"escaped":       document(auth.AdminOutcome(nil), web.Admin(web.AdminModel{User: auth.User{Username: `<script>alert("identity")</script>`, Role: auth.Admin}})),
		"login-success": document(auth.LoginOutcome(nil), nil),
		"setup":         document(auth.BrowserOutcome{Status: 200}, web.Page()),
	}
	for _, code := range []string{auth.InvalidArgument, auth.InvalidCredentials, auth.Forbidden, auth.RateLimited, auth.ServiceUnavailable, platform.CodeDependencyUnavailable, platform.CodeInitializing, platform.CodeSetupRequired, platform.CodeBootstrapFailed, platform.CodeSchemaError} {
		outcome := auth.LoginOutcome(&auth.Error{Code: code})
		views[code] = document(outcome, web.Login(web.LoginModel{Username: "fixture.admin", ErrorCode: code, RetryAfterSeconds: 30}))
	}
	for key, err := range map[string]error{"member": &auth.Error{Code: auth.Forbidden}, "unavailable": &auth.Error{Code: auth.ServiceUnavailable}, "anonymous": &auth.Error{Code: auth.Unauthenticated}} {
		outcome := auth.AdminOutcome(err)
		var view templ.Component
		if outcome.Location == "" {
			view = web.AuthError(web.AuthErrorModel{ErrorCode: outcome.ErrorCode})
		}
		views[key] = document(outcome, view)
	}
	for key, outcome := range map[string]auth.BrowserOutcome{
		"logout":             auth.LogoutOutcome(true, nil),
		"logout-denied":      auth.LogoutOutcome(false, nil),
		"logout-unavailable": auth.LogoutOutcome(true, &auth.Error{Code: auth.ServiceUnavailable}),
	} {
		var view templ.Component
		if outcome.Location == "" {
			view = web.AuthError(web.AuthErrorModel{ErrorCode: outcome.ErrorCode, RemoteRevocationUnconfirmed: outcome.RemoteRevocationUnconfirmed})
		}
		views[key] = document(outcome, view)
	}
	for _, state := range []platform.State{platform.Ready, platform.Initializing, platform.SetupRequired, platform.BootstrapFailed, platform.SchemaError} {
		status := 503
		if state == platform.Ready {
			status = 200
		}
		views[string(state)] = document(auth.BrowserOutcome{Status: status}, web.Readiness(platform.Readiness{State: state}))
	}
	if err := json.NewEncoder(os.Stdout).Encode(views); err != nil {
		panic(err)
	}
}
