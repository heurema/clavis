package web

import (
	"slices"
	"strconv"
	"time"

	"github.com/heurema/clavis/internal/auth"
	"github.com/heurema/clavis/internal/web/ui/badge"
)

// These models are the backend/web ownership boundary. They contain only safe
// display data; HTTP status, cookies and credential processing belong to server.
type LoginModel struct {
	Username          string
	ErrorCode         string
	RetryAfterSeconds int
}

type AdminModel struct {
	User                 auth.User
	Users                []auth.UserRecord
	Truncated            bool
	Connections          []auth.Connection
	ConnectionsTruncated bool
}

type AuthErrorModel struct {
	ErrorCode                   string
	RemoteRevocationUnconfirmed bool
}

// createdLayout renders instants in UTC so the page never depends on the
// viewer's locale or on a server-side time zone configuration.
const createdLayout = "2006-01-02 15:04 UTC"

func createdLabel(value time.Time) string {
	return value.UTC().Format(createdLayout)
}

func statusLabel(disabled bool) string {
	if disabled {
		return "Blocked"
	}
	return "Enabled"
}

func statusVariant(disabled bool) badge.Variant {
	if disabled {
		return badge.VariantDestructive
	}
	return badge.VariantSecondary
}

func roleVariant(role auth.Role) badge.Variant {
	if role == auth.Admin {
		return badge.VariantDefault
	}
	return badge.VariantOutline
}

func truncationNotice() string {
	return "Showing the first " + strconv.Itoa(auth.MaxUserListing) + " users; the list is limited."
}

// The connection projection carries a target map; the table deliberately reads
// only the identifying and operational fields, so no host, port, role or URL
// can reach the page through display data.
func connectionStatusLabel(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func connectionStatusVariant(enabled bool) badge.Variant {
	if enabled {
		return badge.VariantSecondary
	}
	return badge.VariantDestructive
}

// labelPairs renders a label set in a stable order so the same connection
// always produces the same markup. Keys and values are escaped by the template.
func labelPairs(labels map[string]string) []string {
	pairs := make([]string, 0, len(labels))
	for key, value := range labels {
		pairs = append(pairs, key+"="+value)
	}
	slices.Sort(pairs)
	return pairs
}

func checkOutcomeVariant(outcome auth.CheckOutcome) badge.Variant {
	if outcome == auth.CheckReachable {
		return badge.VariantSecondary
	}
	return badge.VariantDestructive
}

func connectionsTruncationNotice() string {
	return "Showing the first " + strconv.Itoa(auth.MaxConnectionListing) + " connections; the list is limited."
}
