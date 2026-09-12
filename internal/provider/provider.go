// Package provider holds the closed registry of connection providers. It is
// the only place that understands provider-specific target syntax and
// connectivity; storage, authorization and audit stay provider-neutral.
//
// Providers are stateless values: every method is safe for concurrent use and
// keeps no state between calls. A probe reports one of the safe outcomes and
// never returns driver text, so a source's error message cannot reach a
// response, an event or a log.
package provider

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
)

// Provider is the provider-specific half of a connection. ParseTarget takes
// the raw submitted settings and returns the canonical stored settings; every
// other method receives a map that ParseTarget produced.
type Provider interface {
	Type() auth.ProviderType
	ParseTarget(raw map[string]string) (map[string]string, error)
	ValidateSecret(target map[string]string, secret auth.Secret) error
	Probe(ctx context.Context, target map[string]string, secret auth.Secret) auth.CheckOutcome
}

// A probe without a caller deadline still has to end. The service always
// passes the remaining part of the operation deadline; this is the fallback.
const defaultProbeTimeout = 5 * time.Second

var registry = map[auth.ProviderType]Provider{
	auth.ProviderPostgreSQL:      postgreSQL{},
	auth.ProviderVictoriaMetrics: victoriaMetrics{},
}

func Lookup(provider auth.ProviderType) (Provider, bool) {
	implementation, ok := registry[provider]
	return implementation, ok
}

// Types lists the registered providers in a stable order, for hints and for
// the CLI.
func Types() []auth.ProviderType {
	types := make([]auth.ProviderType, 0, len(registry))
	for provider := range registry {
		types = append(types, provider)
	}
	slices.Sort(types)
	return types
}

// TypeHint lists the registered providers for an unknown-provider rejection.
func TypeHint() string {
	names := make([]string, 0, len(registry))
	for _, provider := range Types() {
		names = append(names, string(provider))
	}
	return "Valid providers are " + strings.Join(names, ", ") + "."
}

// invalid builds the only error shape this package produces. Hints are fixed
// application text: they name a key or list the valid values and never echo a
// submitted value, which could carry a secret or a host.
func invalid(hint string) error {
	return &auth.Error{Code: auth.InvalidArgument, Hint: hint}
}

// allowedKeys rejects unknown settings. The hint lists the valid keys rather
// than repeating the offending one, which is itself submitted input.
func allowedKeys(raw map[string]string, keys ...string) error {
	for key := range raw {
		if !slices.Contains(keys, key) {
			return invalid("Valid target settings are " + strings.Join(keys, ", ") + ".")
		}
	}
	return nil
}

// probeTimeout turns the caller's deadline into a driver timeout. An expired
// or exhausted deadline is reported by the caller as unreachable rather than
// spending a dial on it.
func probeTimeout(ctx context.Context) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultProbeTimeout, true
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, false
	}
	return remaining, true
}

// printableURL keeps whitespace, control characters and non-ASCII bytes out of
// a URL before it is parsed, so a submitted value cannot smuggle a line break
// or a stray space past a permissive parser.
func printableURL(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] <= ' ' || value[index] > '~' {
			return false
		}
	}
	return true
}

// validPort accepts a decimal port in range; an empty string means the
// provider default and is handled by the caller.
func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535 && strconv.Itoa(port) == value
}

// validHost accepts one IP literal or one DNS name. It rejects a comma, so a
// multi-host connection string cannot reach a driver that would fan out to
// hosts an administrator never reviewed.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			c := label[index]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// validIdentifier bounds a role or database name: PostgreSQL truncates past 63
// bytes, and control characters have no place in either.
func validIdentifier(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index := range len(value) {
		if value[index] < ' ' || value[index] == 0x7f {
			return false
		}
	}
	return true
}
