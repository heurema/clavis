package web

import "github.com/heurema/clavis/internal/platform"

type statusView struct {
	title, description, badge, server, database, tone string
}

// These are presentation states, not persisted readiness evidence. Browser-only
// failures are rendered into inert templates so scripts never display raw errors.
func readinessView(state string) statusView {
	switch state {
	case "checking":
		return statusView{
			"Checking your environment",
			"Contacting the server and checking its database connection.",
			"Checking", "Checking…", "Checking…", "",
		}
	case string(platform.Ready):
		return statusView{
			"Your environment is ready",
			"The Clavis server is reachable, its platform schema is supported and installation is complete. You can sign in.",
			"Ready", "Reachable", "Ready", "status-success",
		}
	case string(platform.Initializing):
		return statusView{
			"Initialization in progress",
			"Clavis is preparing its schema and initial administrator. Wait a moment, then retry. This page does not poll automatically.",
			"Initializing", "Reachable", "Ready", "status-warning",
		}
	case string(platform.SetupRequired):
		return statusView{
			"Administrator setup required",
			"Ask your deployment operator to supply the initial administrator username and a protected password file in deployment configuration. Accounts cannot be created in this browser.",
			"Setup required", "Reachable", "Ready", "status-warning",
		}
	case string(platform.BootstrapFailed):
		return statusView{
			"Administrator setup failed",
			"The configured initial administrator inputs could not be used. Ask your deployment operator to check the username and password file validity, access and permissions, then retry after the server rechecks them.",
			"Setup failed", "Reachable", "Ready", "status-warning",
		}
	case string(platform.SchemaError):
		return statusView{
			"Platform schema requires attention",
			"The database is reachable, but its schema is unavailable or incompatible. Ask your deployment operator to repair the schema or use a compatible server version. Retrying does not repair it.",
			"Schema error", "Reachable", "Ready", "status-warning",
		}
	case string(platform.DependencyUnavailable):
		return statusView{
			"Database unavailable",
			"The server is reachable, but its platform database is not responding. Start the database, then retry.",
			"Needs attention", "Reachable", "Unavailable", "status-warning",
		}
	default:
		description := "Clavis received an unexpected response. Check the server, then retry."
		switch state {
		case "server-unavailable":
			description = "Clavis could not reach the server. Start it, then retry."
		case "timeout":
			description = "The readiness check timed out after five seconds. Check the server, then retry."
		}
		return statusView{
			"Server unavailable", description,
			"Needs attention", "Unavailable", "Not checked", "status-warning",
		}
	}
}
