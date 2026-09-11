package web

import (
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
	User      auth.User
	Users     []auth.UserRecord
	Truncated bool
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
