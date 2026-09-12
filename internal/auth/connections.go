package auth

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Connection routes: GET ConnectionsPath lists, POST ConnectionsPath creates.
// {connectionID} accepts a UUID or a connection name.
const (
	ConnectionsPath           = "/api/admin/connections"
	ConnectionPath            = "/api/admin/connections/{connectionID}"
	ConnectionUpdatePath      = "/api/admin/connections/{connectionID}/update"
	ConnectionCredentialsPath = "/api/admin/connections/{connectionID}/credentials"
	ConnectionEnablePath      = "/api/admin/connections/{connectionID}/enable"
	ConnectionDisablePath     = "/api/admin/connections/{connectionID}/disable"
	ConnectionDeletePath      = "/api/admin/connections/{connectionID}/delete"
	ConnectionCheckPath       = "/api/admin/connections/{connectionID}/check"
	DryRunQuery               = "dryRun"
)

// Bounds shared by the service, the routes and the CLI.
const (
	MaxConnectionListing    = 1000
	MaxLabels               = 16
	MaxSelectorTerms        = 8
	MaxTitleLength          = 128
	MaxDescriptionLength    = 2000
	MaxSecretBytes          = 4096
	DefaultStatementTimeout = 30 * time.Second
	MinStatementTimeout     = time.Second
	MaxStatementTimeout     = 120 * time.Second
	DefaultMaxRows          = 1000
	MaxMaxRows              = 100000
	DefaultMaxBytes         = 1 << 20
	MinMaxBytes             = 1024
	MaxMaxBytes             = 10 << 20
)

type ProviderType string

const (
	ProviderPostgreSQL      ProviderType = "postgresql"
	ProviderVictoriaMetrics ProviderType = "victoriametrics"
)

func ValidProvider(p ProviderType) bool {
	return p == ProviderPostgreSQL || p == ProviderVictoriaMetrics
}

type CheckOutcome string

const (
	CheckReachable              CheckOutcome = "reachable"
	CheckAuthRejected           CheckOutcome = "auth_rejected"
	CheckUnreachable            CheckOutcome = "unreachable"
	CheckCredentialsUnavailable CheckOutcome = "credentials_unavailable"
)

type CheckResult struct {
	Outcome   CheckOutcome `json:"outcome"`
	CheckedAt time.Time    `json:"checkedAt"`
}

// Connection is the safe administrative projection. Target holds only
// non-secret provider settings; the secret envelope never leaves storage.
type Connection struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	Scope              string            `json:"scope"`
	Provider           ProviderType      `json:"provider"`
	Target             map[string]string `json:"target"`
	Labels             map[string]string `json:"labels"`
	Enabled            bool              `json:"enabled"`
	StatementTimeoutMS int               `json:"statementTimeoutMs"`
	MaxRows            int               `json:"maxRows"`
	MaxBytes           int               `json:"maxBytes"`
	LastCheck          *CheckResult      `json:"lastCheck"`
	CreatedAt          time.Time         `json:"createdAt"`
	UpdatedAt          time.Time         `json:"updatedAt"`
}

type ConnectionList struct {
	Connections []Connection `json:"connections"`
	Truncated   bool         `json:"truncated"`
}

// ConnectionSummary is what a member sees of a granted connection: identity,
// descriptive text, labels, state and the last check. It has no target,
// bounds or secret fields, so a member response can never carry them.
type ConnectionSummary struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Scope       string            `json:"scope"`
	Provider    ProviderType      `json:"provider"`
	Labels      map[string]string `json:"labels"`
	Enabled     bool              `json:"enabled"`
	LastCheck   *CheckResult      `json:"lastCheck"`
}

// Summary projects a full record to the member view.
func (c Connection) Summary() ConnectionSummary {
	return ConnectionSummary{
		ID: c.ID, Name: c.Name, Title: c.Title, Description: c.Description, Scope: c.Scope,
		Provider: c.Provider, Labels: c.Labels, Enabled: c.Enabled, LastCheck: c.LastCheck,
	}
}

// ConnectionSummaryList is the member listing: summaries only, with the same
// truncation flag as the administrator listing.
type ConnectionSummaryList struct {
	Connections []ConnectionSummary `json:"connections"`
	Truncated   bool                `json:"truncated"`
}

// CreateConnectionRequest carries the only secret a connection request may
// hold; it is transport input, never result data.
type CreateConnectionRequest struct {
	Name               string            `json:"name"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	Scope              string            `json:"scope"`
	Provider           ProviderType      `json:"provider"`
	Target             map[string]string `json:"target"`
	Labels             map[string]string `json:"labels"`
	StatementTimeoutMS int               `json:"statementTimeoutMs"`
	MaxRows            int               `json:"maxRows"`
	MaxBytes           int               `json:"maxBytes"`
	Secret             Secret            `json:"secret"`
}

// UpdateConnectionRequest changes only the fields that are present.
type UpdateConnectionRequest struct {
	Name               *string            `json:"name,omitempty"`
	Title              *string            `json:"title,omitempty"`
	Description        *string            `json:"description,omitempty"`
	Scope              *string            `json:"scope,omitempty"`
	Target             *map[string]string `json:"target,omitempty"`
	Labels             *map[string]string `json:"labels,omitempty"`
	StatementTimeoutMS *int               `json:"statementTimeoutMs,omitempty"`
	MaxRows            *int               `json:"maxRows,omitempty"`
	MaxBytes           *int               `json:"maxBytes,omitempty"`
}

type SetConnectionCredentialsRequest struct {
	Secret Secret `json:"secret"`
}

type ConnectionMutation struct {
	Connection Connection `json:"connection"`
	DryRun     bool       `json:"dryRun"`
}

type ConnectionDeletion struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
	DryRun  bool   `json:"dryRun"`
}

type ConnectionCheck struct {
	Connection Connection  `json:"connection"`
	Check      CheckResult `json:"check"`
}

// Connections is the administrator-only connection lifecycle. Every method
// rechecks the actor's current session and role inside its own transaction.
// A dry run performs validation, authorization and guards, then rolls back.
type Connections interface {
	ListConnections(context.Context, Session, []SelectorTerm, int) (ConnectionList, error)
	GetConnection(context.Context, Session, string) (Connection, error)
	CreateConnection(context.Context, Session, CreateConnectionRequest, bool) (ConnectionMutation, error)
	UpdateConnection(context.Context, Session, string, UpdateConnectionRequest, bool) (ConnectionMutation, error)
	SetConnectionCredentials(context.Context, Session, string, Secret, bool) (ConnectionMutation, error)
	SetConnectionEnabled(context.Context, Session, string, bool, bool) (ConnectionMutation, error)
	DeleteConnection(context.Context, Session, string, bool) (ConnectionDeletion, error)
	CheckConnection(context.Context, Session, string) (ConnectionCheck, error)
}

var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidConnectionName uses the username character rule and additionally
// refuses anything shaped like a UUID, so UUID-or-name lookups stay
// unambiguous. The migration enforces the same exclusion.
// ValidConnectionName shares the username rule, which already refuses the
// UUID shape, so a reference that is a UUID can never be a name.
func ValidConnectionName(value string) bool { return ValidUsername(value) }

// ValidConnectionRef accepts a UUID or a connection name.
func ValidConnectionRef(value string) bool {
	return ValidUserID(value) || ValidConnectionName(value)
}

func ValidLabelKey(value string) bool   { return labelPattern.MatchString(value) }
func ValidLabelValue(value string) bool { return labelPattern.MatchString(value) }

func ValidSecret(value Secret) bool {
	s := string(value)
	return len(s) > 0 && len(s) <= MaxSecretBytes && !strings.ContainsAny(s, "\x00\r\n")
}

// ValidLabels checks a complete label set: bounded count, valid keys and values.
func ValidLabels(labels map[string]string) bool {
	if len(labels) > MaxLabels {
		return false
	}
	for key, value := range labels {
		if !ValidLabelKey(key) || !ValidLabelValue(value) {
			return false
		}
	}
	return true
}

// ParseLabels turns repeated key=value arguments into a label set. A repeated
// key is an error rather than a silent overwrite.
func ParseLabels(pairs []string) (map[string]string, bool) {
	labels := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found || !ValidLabelKey(key) || !ValidLabelValue(value) {
			return nil, false
		}
		if _, duplicate := labels[key]; duplicate {
			return nil, false
		}
		labels[key] = value
	}
	if !ValidLabels(labels) {
		return nil, false
	}
	return labels, true
}

type SelectorOp string

const (
	SelectorEquals    SelectorOp = "="
	SelectorNotEquals SelectorOp = "!="
	SelectorExists    SelectorOp = "exists"
)

type SelectorTerm struct {
	Key   string
	Op    SelectorOp
	Value string
}

// ParseSelector parses the kubectl-style grammar "k=v,k!=v,k" with terms
// combined by AND. An empty selector matches everything.
func ParseSelector(selector string) ([]SelectorTerm, bool) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, true
	}
	parts := strings.Split(selector, ",")
	if len(parts) > MaxSelectorTerms {
		return nil, false
	}
	terms := make([]SelectorTerm, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		var term SelectorTerm
		switch {
		case strings.Contains(part, "!="):
			key, value, _ := strings.Cut(part, "!=")
			term = SelectorTerm{Key: key, Op: SelectorNotEquals, Value: value}
		case strings.Contains(part, "="):
			key, value, _ := strings.Cut(part, "=")
			term = SelectorTerm{Key: key, Op: SelectorEquals, Value: value}
		default:
			term = SelectorTerm{Key: part, Op: SelectorExists}
		}
		if !ValidLabelKey(term.Key) || (term.Op != SelectorExists && !ValidLabelValue(term.Value)) {
			return nil, false
		}
		terms = append(terms, term)
	}
	return terms, true
}
