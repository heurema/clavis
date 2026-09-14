// Package provider holds the closed registry of connection providers. It is
// the only place that understands provider-specific target syntax and
// connectivity; storage and authorization stay provider-neutral.
//
// Providers are stateless values: every method is safe for concurrent use and
// keeps no state between calls. A probe reports one of the safe outcomes and
// never returns driver text, so a source's error message cannot reach a
// response or a log.
package provider

import (
	"context"
	"encoding/json"
	"errors"
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

// Executor is the optional execution capability. A provider that lacks it is
// refused with PROVIDER_UNSUPPORTED before any credential is opened, decided
// by a type assertion rather than by calling anything.
type Executor interface {
	Execute(ctx context.Context, target map[string]string, secret auth.Secret, request ExecuteRequest) (ExecuteResult, error)
}

// ExecuteRequest is one pass-through execution under the connection's bounds.
// Exactly one input is set and it reaches the source unchanged: the SQL for
// PostgreSQL, or for a metrics source the expression with its optional time
// bounds, or one of the three discovery inputs. Application is the
// application_name a SQL source will see; the service composes it, because
// only the service knows the connection name and the caller, and a metrics
// source has nowhere to put it.
type ExecuteRequest struct {
	SQL    string
	PromQL string
	At     string
	Start  string
	End    string
	Step   string

	Labels      bool
	LabelValues string
	Series      string
	Match       string

	Timeout     time.Duration
	MaxRows     int
	MaxBytes    int
	Application string
}

// ExecuteResult is the bounded view of what the source produced. For a SQL
// source Results is one entry per statement in order; for a metrics source
// ResultType names the shape and Result holds the source's own data, with the
// source's warnings, infos and partial-answer flag beside it. Statements, Rows
// and Bytes count what was kept, not what the source sent: the rest was read
// and dropped, so the counters describe the response rather than the work.
type ExecuteResult struct {
	Results []auth.QueryResult

	ResultType string
	Result     json.RawMessage
	Warnings   []string
	Infos      []string
	IsPartial  bool

	Truncated  bool
	Statements int64
	Rows       int64
	Bytes      int64
}

// The execution failures a provider may report. They are sentinel values, not
// messages: the service maps them to codes, and none of them can carry driver
// text, a target or a secret into a response or a log.
var (
	ErrTimeout      = errors.New("the statement timeout was exceeded")
	ErrUnreachable  = errors.New("the source could not be reached")
	ErrAuthRejected = errors.New("the source refused the credentials")
	ErrUnsupported  = errors.New("the provider does not support this operation")
	// ErrUnsupportedInput is the backstop for an input this provider does not
	// take, such as SQL for a metrics source. The service refuses a mismatch
	// before any credential is opened, so reaching this means the service's
	// own rule was missed rather than that a caller found a way in.
	ErrUnsupportedInput = errors.New("the provider does not take this input")
)

// The two failures the platform classifies itself, because the answer never
// became the source's envelope. They travel as the source failure's errorType
// so the caller branches on them like the source's own, and the service attaches
// the next step to each; every other errorType is the source's own word.
const (
	ResponseTooLarge  = "response_too_large"
	MalformedResponse = "malformed_response"
)

// SourceError is the source's own rejection of the submitted input, the one
// failure whose text the caller sees. Error() is fixed application text: the
// source's message travels in Failure, which the service puts in the
// envelope's source block and nothing logs.
type SourceError struct {
	Failure auth.SourceFailure
}

func (e *SourceError) Error() string { return "the source rejected the statement" }

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
