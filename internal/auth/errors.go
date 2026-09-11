package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/heurema/clavis/internal/platform"
)

const (
	InvalidArgument    = "INVALID_ARGUMENT"
	InvalidCredentials = "INVALID_CREDENTIALS"
	Unauthenticated    = "UNAUTHENTICATED"
	Forbidden          = "FORBIDDEN"
	UserNotFound       = "USER_NOT_FOUND"
	UsernameTaken      = "USERNAME_TAKEN"
	LastAdministrator  = "LAST_ADMINISTRATOR"
	SelfTarget         = "SELF_TARGET"
	RateLimited        = "RATE_LIMITED"
	ServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// Error describes a safe service failure. It deliberately cannot wrap a driver
// error or carry arbitrary messages into an adapter.
type Error struct {
	Code       string
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	_, failure, ok := LookupFailure(e.Code)
	if !ok {
		_, failure, _ = LookupFailure(ServiceUnavailable)
	}
	return failure.Message
}

type ErrorResponse struct {
	Error platform.Failure `json:"error"`
}

// LookupFailure is the wire allowlist for both adapters and strict clients.
func LookupFailure(code string) (int, platform.Failure, bool) {
	if failure, ok := platform.LookupFailure(code); ok {
		return http.StatusServiceUnavailable, failure, true
	}
	var status int
	var message string
	switch code {
	case InvalidArgument:
		status, message = http.StatusBadRequest, "Invalid arguments or request"
	case InvalidCredentials:
		status, message = http.StatusUnauthorized, "Invalid username or password"
	case Unauthenticated:
		status, message = http.StatusUnauthorized, "Sign-in is required"
	case Forbidden:
		status, message = http.StatusForbidden, "Administrator access is required"
	case UserNotFound:
		status, message = http.StatusNotFound, "User not found"
	case UsernameTaken:
		status, message = http.StatusConflict, "Username is already in use"
	case LastAdministrator:
		status, message = http.StatusConflict, "At least one enabled administrator must remain"
	case SelfTarget:
		status, message = http.StatusConflict, "Administrators cannot block or demote their own account"
	case RateLimited:
		status, message = http.StatusTooManyRequests, "Too many attempts; try again later"
	case ServiceUnavailable:
		status, message = http.StatusServiceUnavailable, "Authentication is temporarily unavailable"
	default:
		return 0, platform.Failure{}, false
	}
	return status, platform.Failure{Code: code, Message: message}, true
}

// FailureFor maps unexpected implementation errors to safe unavailability.
// Clients instead use LookupFailure and reject unknown server responses.
func FailureFor(err error) (int, ErrorResponse) {
	var failure *Error
	if errors.As(err, &failure) && failure != nil {
		if status, value, ok := LookupFailure(failure.Code); ok {
			return status, ErrorResponse{Error: value}
		}
	}
	status, value, _ := LookupFailure(ServiceUnavailable)
	return status, ErrorResponse{Error: value}
}
