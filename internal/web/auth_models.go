package web

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heurema/clavis/internal/auth"
)

// These models are the backend/web ownership boundary. They contain only safe
// display data; HTTP status, cookies and credential processing belong to server.
type LoginModel struct {
	Username          string
	ErrorCode         string
	RetryAfterSeconds int
	// Action is where the form posts: the sign-in route, carrying the CLI
	// authorization link to return to after sign-in when the request that
	// rendered the document carried one. The document renders it only when it
	// is that route with such a link, and then with the link rebuilt.
	Action string
}

// AuthorizeModel is the approval document for one parsed authorization link:
// the signed-in username and the link, whose port the document names.
type AuthorizeModel struct {
	Username string
	Link     auth.CLIAuthorization
}

// returnTarget keeps a return target only as a rebuilt authorization link,
// never as the submitted text.
func returnTarget(next string) string {
	link, ok := auth.ParseAuthorizeLink(next)
	if !ok {
		return ""
	}
	return link.Link()
}

// loginAction keeps the sign-in form on the sign-in route, carrying at most one
// return target rebuilt from its parsed values. Anything else posts to the bare
// route, so no submitted text can steer where the credentials go.
func loginAction(action string) string {
	path, query, _ := strings.Cut(action, "?")
	if path != "/login" {
		return "/login"
	}
	values, err := url.ParseQuery(query)
	if err != nil || len(values["next"]) != 1 {
		return "/login"
	}
	next := returnTarget(values.Get("next"))
	if next == "" {
		return "/login"
	}
	return "/login?" + url.Values{"next": {next}}.Encode()
}

// AdminPage names the administration page a request asked for. The shell needs
// it to mark the current navigation entry and to pick the table to render, so
// the three routes differ only by this value.
type AdminPage string

const (
	PageUsers       AdminPage = "users"
	PageGroups      AdminPage = "groups"
	PageConnections AdminPage = "connections"
	PageGrants      AdminPage = "grants"
)

// pageHeading is the page title and its navigation label, kept in one place so
// the heading, the sidebar entry and the document title cannot disagree.
func pageHeading(page AdminPage) string {
	switch page {
	case PageGroups:
		return "Groups"
	case PageConnections:
		return "Connections"
	case PageGrants:
		return "Grants"
	default:
		return "Users"
	}
}

type AdminModel struct {
	Page                 AdminPage
	User                 auth.User
	Users                []auth.UserRecord
	Truncated            bool
	Groups               []auth.Group
	GroupsTruncated      bool
	Connections          []auth.Connection
	ConnectionsTruncated bool
	Grants               []auth.Grant
	GrantsTruncated      bool
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

// initial is the decorative letter in the sidebar's identity row. It is hidden
// from assistive technology, which reads the username beside it instead.
func initial(username string) string {
	for _, first := range username {
		return strings.ToUpper(string(first))
	}
	return ""
}

// listCount is what a sidebar entry shows. A truncated list is never presented
// as a complete count, so the bound carries a trailing plus sign instead.
func listCount(n int, truncated bool) string {
	if truncated {
		return strconv.Itoa(n) + "+"
	}
	return strconv.Itoa(n)
}

// statusKind selects the indicator colour only. Every status also renders the
// word naming the state, so colour is reinforcement and never the signal.
type statusKind string

const (
	statusOK  statusKind = "ok"
	statusBad statusKind = "bad"
	statusOff statusKind = "off"
)

func userStatus(disabled bool) (statusKind, string) {
	if disabled {
		return statusBad, "Blocked"
	}
	return statusOK, "Active"
}

// The connection projection carries a target map; the table deliberately reads
// only the identifying and operational fields, so no host, port, role or URL
// can reach the page through display data.
func connectionStatus(enabled bool) (statusKind, string) {
	if enabled {
		return statusOK, "Enabled"
	}
	return statusOff, "Disabled"
}

// Only a reachable source is healthy. Every other outcome is a problem and is
// named by the outcome itself rather than by an interpretation of it.
func checkStatus(outcome auth.CheckOutcome) (statusKind, string) {
	if outcome == auth.CheckReachable {
		return statusOK, "Reachable"
	}
	return statusBad, string(outcome)
}

func truncationNotice() string {
	return "Showing the first " + strconv.Itoa(auth.MaxUserListing) + " users; the list is limited."
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

func groupsTruncationNotice() string {
	return "Showing the first " + strconv.Itoa(auth.MaxGroupListing) + " groups; the list is limited."
}

func connectionsTruncationNotice() string {
	return "Showing the first " + strconv.Itoa(auth.MaxConnectionListing) + " connections; the list is limited."
}

func grantsTruncationNotice() string {
	return "Showing the first " + strconv.Itoa(auth.MaxGrantListing) + " grants; the list is limited."
}

// roleLabel names the two known roles for display; anything else renders as
// its escaped raw value so an unexpected role is never hidden.
func roleLabel(role auth.Role) string {
	switch role {
	case auth.Admin:
		return "Admin"
	case auth.Member:
		return "Member"
	}
	return string(role)
}
