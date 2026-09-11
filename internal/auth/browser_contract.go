package auth

import "net/http"

// BrowserOutcome is the frozen adapter/view boundary. It contains no session
// credential or untrusted text. Handlers apply headers; templates render codes.
type BrowserOutcome struct {
	Status                      int
	Location                    string
	ErrorCode                   string
	ClearCookie                 bool
	RemoteRevocationUnconfirmed bool
}

func LoginOutcome(err error) BrowserOutcome {
	if err == nil {
		return BrowserOutcome{Status: http.StatusSeeOther, Location: "/admin"}
	}
	status, response := FailureFor(err)
	return BrowserOutcome{Status: status, ErrorCode: response.Error.Code}
}

func LogoutOutcome(originAllowed bool, err error) BrowserOutcome {
	if !originAllowed {
		return BrowserOutcome{Status: http.StatusForbidden, ErrorCode: Forbidden}
	}
	if err == nil {
		return BrowserOutcome{Status: http.StatusSeeOther, Location: "/login", ClearCookie: true}
	}
	_, response := FailureFor(err)
	if response.Error.Code == Unauthenticated {
		return BrowserOutcome{Status: http.StatusSeeOther, Location: "/login", ClearCookie: true}
	}
	return BrowserOutcome{
		Status: http.StatusServiceUnavailable, ErrorCode: ServiceUnavailable,
		ClearCookie: true, RemoteRevocationUnconfirmed: true,
	}
}

func AdminOutcome(err error) BrowserOutcome {
	if err == nil {
		return BrowserOutcome{Status: http.StatusOK}
	}
	status, response := FailureFor(err)
	if response.Error.Code == Unauthenticated {
		return BrowserOutcome{Status: http.StatusSeeOther, Location: "/login"}
	}
	return BrowserOutcome{Status: status, ErrorCode: response.Error.Code}
}
