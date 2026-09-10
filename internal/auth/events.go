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

func (e Event) Valid() bool {
	if e.Action != EventLogin && e.Action != EventLogout && e.Action != EventRevoke {
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
