package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/platform"
)

const maxResponseBytes = 64 << 10

func validateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid server URL")
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return nil, errors.New("invalid server URL")
		}
	}
	return u, nil
}

func Doctor(ctx context.Context, baseURL string, timeout time.Duration) Result {
	u, err := validateURL(baseURL)
	if err != nil || timeout <= 0 {
		return failure("INVALID_ARGUMENT", "Use an HTTP(S) server URL without credentials, query, or fragment and a positive timeout", nil)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/health/ready"
	u.RawPath = ""
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil && ctx.Err() != nil {
		return failure("TIMEOUT", "Readiness check did not complete", Diagnosis{"unknown", "unknown"})
	}
	invalid := failure("INVALID_RESPONSE", "Server returned an invalid readiness response", Diagnosis{"reachable", "unknown"})
	if err != nil || len(body) > maxResponseBytes {
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
