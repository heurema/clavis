package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/platform"
)

// Doctor checks readiness at an origin that passes the same canonical-origin
// rule as login, so a server doctor accepts is never refused by login.
func Doctor(ctx context.Context, server string, timeout time.Duration) Result {
	origin, err := auth.CanonicalOrigin(server)
	if err != nil || timeout <= 0 {
		return failure("INVALID_ARGUMENT", "Use an HTTPS root origin (literal loopback HTTP is allowed) and a positive timeout", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/readyz", nil)
	if err != nil {
		return failure("INVALID_ARGUMENT", "Invalid server URL", nil)
	}
	request.Header.Set("Accept", "application/json")
	// Redirects are not readiness evidence and must not silently change servers.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return failure("TIMEOUT", "Readiness check did not complete", Diagnosis{"unknown", "unknown"})
		}
		return failure("SERVER_UNREACHABLE", "Server could not be reached", Diagnosis{"unreachable", "unknown"})
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, auth.MaxResponseBody+1))
	if err != nil && ctx.Err() != nil {
		return failure("TIMEOUT", "Readiness check did not complete", Diagnosis{"unknown", "unknown"})
	}
	invalid := failure("INVALID_RESPONSE", "Server returned an invalid readiness response", Diagnosis{"reachable", "unknown"})
	if err != nil || len(body) > auth.MaxResponseBody {
		return invalid
	}
	var health struct {
		Status string `json:"status"`
		Error  *Error `json:"error"`
	}
	if json.Unmarshal(body, &health) != nil {
		return invalid
	}
	if response.StatusCode == http.StatusOK && health.Status == "ready" && health.Error == nil {
		return success(Diagnosis{"reachable", "ready"})
	}
	if response.StatusCode == http.StatusServiceUnavailable && health.Status == "not_ready" && health.Error != nil && health.Error.Code == "DEPENDENCY_UNAVAILABLE" {
		return failure("DEPENDENCY_UNAVAILABLE", "Database unavailable", Diagnosis{"reachable", "unavailable"})
	}
	if response.StatusCode == http.StatusServiceUnavailable && health.Status == "not_ready" && health.Error != nil {
		switch health.Error.Code {
		case platform.CodeInitializing, platform.CodeSetupRequired, platform.CodeBootstrapFailed, platform.CodeSchemaError:
			safe, _ := platform.LookupFailure(health.Error.Code)
			return failure(safe.Code, safe.Message, Diagnosis{"reachable", "ready"})
		}
	}
	return invalid
}
