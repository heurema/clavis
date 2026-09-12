package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/heurema/clavis/internal/platform"
)

const (
	InvalidArgument        = "INVALID_ARGUMENT"
	InvalidCredentials     = "INVALID_CREDENTIALS"
	Unauthenticated        = "UNAUTHENTICATED"
	Forbidden              = "FORBIDDEN"
	UserNotFound           = "USER_NOT_FOUND"
	UsernameTaken          = "USERNAME_TAKEN"
	LastAdministrator      = "LAST_ADMINISTRATOR"
	SelfTarget             = "SELF_TARGET"
	ConnectionExists       = "CONNECTION_EXISTS"
	ConnectionNotFound     = "CONNECTION_NOT_FOUND"
	ConnectionInUse        = "CONNECTION_IN_USE"
	CredentialsUnavailable = "CREDENTIALS_UNAVAILABLE"
	ConnectionDisabled     = "CONNECTION_DISABLED"
	SourceError            = "SOURCE_ERROR"
	SourceTimeout          = "SOURCE_TIMEOUT"
	SourceUnreachable      = "SOURCE_UNREACHABLE"
	SourceAuthRejected     = "SOURCE_AUTH_REJECTED"
	ProviderUnsupported    = "PROVIDER_UNSUPPORTED"
	RateLimited            = "RATE_LIMITED"
	ServiceUnavailable     = "SERVICE_UNAVAILABLE"
)

// Error describes a safe service failure. It deliberately cannot wrap a driver
// error or carry arbitrary messages into an adapter. Hint is optional,
// application-owned guidance for the caller's next step; it never echoes input.
type Error struct {
	Code       string
	RetryAfter time.Duration
	Hint       string
	// Source carries the external source's own rejection and is set only by an
	// execution the source refused. It is the one message in the envelope the
	// platform did not write: it goes to the caller who submitted the SQL and
	// never into a log.
	Source *SourceFailure
}

func (e *Error) Error() string {
	_, failure, ok := LookupFailure(e.Code)
	if !ok {
		_, failure, _ = LookupFailure(ServiceUnavailable)
	}
	return failure.Message
}

// ErrorResponse is the one failure envelope. Source is optional detail the
// external source reported; it is rendered inside the error object as
// error.source rather than beside it, so a client that knows only the shared
// failure shape still sees the envelope it already knows.
type ErrorResponse struct {
	Error  platform.Failure `json:"error"`
	Source *SourceFailure   `json:"-"`
}

// wireFailure is the error object as it travels: the shared failure fields
// with the optional source block.
type wireFailure struct {
	platform.Failure
	Source *SourceFailure `json:"source,omitempty"`
}

type wireEnvelope struct {
	Error wireFailure `json:"error"`
}

func (r ErrorResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireEnvelope{Error: wireFailure{Failure: r.Error, Source: r.Source}})
}

// UnmarshalJSON keeps the strict reading a client needs even though the
// envelope is now assembled by hand: an unknown key inside the error object is
// still a rejection rather than a silently dropped field.
func (r *ErrorResponse) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire wireEnvelope
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	r.Error, r.Source = wire.Error.Failure, wire.Error.Source
	return nil
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
	case ConnectionExists:
		status, message = http.StatusConflict, "A connection with that name already exists"
	case ConnectionNotFound:
		status, message = http.StatusNotFound, "Connection not found"
	case ConnectionInUse:
		status, message = http.StatusConflict, "The connection must be disabled and have no grants before deletion"
	case CredentialsUnavailable:
		status, message = http.StatusConflict, "The stored credentials cannot be decrypted with the configured key"
	case ConnectionDisabled:
		status, message = http.StatusConflict, "The connection is disabled"
	case SourceError:
		status, message = http.StatusUnprocessableEntity, "The source rejected the SQL"
	case SourceTimeout:
		status, message = http.StatusGatewayTimeout, "The statement timeout was exceeded"
	case SourceUnreachable:
		status, message = http.StatusBadGateway, "The source could not be reached"
	case SourceAuthRejected:
		status, message = http.StatusBadGateway, "The source refused the connection's credentials"
	case ProviderUnsupported:
		status, message = http.StatusBadRequest, "The connection's provider does not support this operation"
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
			value.Hint = failure.Hint
			return status, ErrorResponse{Error: value, Source: failure.Source}
		}
	}
	status, value, _ := LookupFailure(ServiceUnavailable)
	return status, ErrorResponse{Error: value}
}
