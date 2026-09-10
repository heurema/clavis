package web

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
	case "ready":
		return statusView{
			"Your environment is ready",
			"The Clavis server is reachable and its platform database is responding.",
			"Ready", "Reachable", "Ready", "status-success",
		}
	case "database-unavailable":
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
