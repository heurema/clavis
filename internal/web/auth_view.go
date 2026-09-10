package web

import (
	"regexp"
	"strconv"

	"github.com/heurema/clavis/internal/auth"
)

// Retain only canonical, bounded usernames, never arbitrary submitted text.
var displayUsername = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

func retainedUsername(value string) string {
	if len(value) <= 64 && displayUsername.MatchString(value) {
		return value
	}
	return ""
}

func authMessage(code string) string {
	_, failure, ok := auth.LookupFailure(code)
	if !ok {
		_, failure, _ = auth.LookupFailure(auth.ServiceUnavailable)
	}
	// FORBIDDEN also describes rejected Origin checks, not just role checks.
	if code == auth.Forbidden {
		return "This request is not permitted. Use this site's sign-in page; administrator access is required for administration."
	}
	return failure.Message
}

func retryMessage(seconds int) string {
	if seconds <= 0 || seconds > 300 {
		return "Wait a few minutes before trying again."
	}
	return "Try again in " + strconv.Itoa(seconds) + " seconds."
}
