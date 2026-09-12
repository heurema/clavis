package auth

import "context"

// Event is the narrow safe boundary for adapter rejections. It intentionally
// cannot carry submitted usernames, request data, credentials or raw errors.
type EventAction string
type EventOutcome string

const (
	EventLogin             EventAction  = "login"
	EventLogout            EventAction  = "logout"
	EventRevoke            EventAction  = "revoke"
	EventUserCreate        EventAction  = "user.create"
	EventUserBlock         EventAction  = "user.block"
	EventUserUnblock       EventAction  = "user.unblock"
	EventUserResetPassword EventAction  = "user.reset_password"
	EventUserPromote       EventAction  = "user.promote"
	EventUserDemote        EventAction  = "user.demote"
	EventUsersList         EventAction  = "users.list"
	EventConnectionCreate  EventAction  = "connection.create"
	EventConnectionUpdate  EventAction  = "connection.update"
	EventConnectionSecrets EventAction  = "connection.set_credentials"
	EventConnectionEnable  EventAction  = "connection.enable"
	EventConnectionDisable EventAction  = "connection.disable"
	EventConnectionDelete  EventAction  = "connection.delete"
	EventConnectionCheck   EventAction  = "connection.check"
	EventConnectionsList   EventAction  = "connections.list"
	OutcomeInvalidArgument EventOutcome = "invalid_argument"
	OutcomeUnauthenticated EventOutcome = "unauthenticated"
	OutcomeForbidden       EventOutcome = "forbidden"
	OutcomeRateLimited     EventOutcome = "rate_limited"
)

type Event struct {
	Action    EventAction
	Outcome   EventOutcome
	ActorID   string
	TargetID  string
	SessionID string
}

type EventRecorder interface {
	RecordEvent(context.Context, Event) error
}

// ValidEventAction is the action allowlist shared with the event schema's
// check constraint. Extending it requires a forward migration.
func ValidEventAction(action EventAction) bool {
	switch action {
	case EventLogin, EventLogout, EventRevoke,
		EventUserCreate, EventUserBlock, EventUserUnblock, EventUserResetPassword,
		EventUserPromote, EventUserDemote, EventUsersList,
		EventConnectionCreate, EventConnectionUpdate, EventConnectionSecrets, EventConnectionEnable,
		EventConnectionDisable, EventConnectionDelete, EventConnectionCheck, EventConnectionsList:
		return true
	}
	return false
}

func (e Event) Valid() bool {
	if !ValidEventAction(e.Action) {
		return false
	}
	switch e.Outcome {
	case OutcomeInvalidArgument, OutcomeUnauthenticated, OutcomeForbidden, OutcomeRateLimited:
	default:
		return false
	}
	for _, id := range []string{e.ActorID, e.TargetID, e.SessionID} {
		if id != "" && !ValidUserID(id) {
			return false
		}
	}
	return true
}
