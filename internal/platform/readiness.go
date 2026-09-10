// Package platform defines installation state shared by server, web and CLI.
package platform

import "context"

type State string

const (
	Ready                 State = "ready"
	DependencyUnavailable State = "database-unavailable"
	Initializing          State = "initializing"
	SetupRequired         State = "setup-required"
	BootstrapFailed       State = "bootstrap-failed"
	SchemaError           State = "schema-error"
)

const (
	CodeDependencyUnavailable = "DEPENDENCY_UNAVAILABLE"
	CodeInitializing          = "INITIALIZING"
	CodeSetupRequired         = "SETUP_REQUIRED"
	CodeBootstrapFailed       = "BOOTSTRAP_FAILED"
	CodeSchemaError           = "SCHEMA_ERROR"
)

// Failure is an application-owned representation, never a dependency error.
type Failure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Status string   `json:"status"`
	Error  *Failure `json:"error,omitempty"`
}

type Readiness struct {
	State State
}

func (r Readiness) Ready() bool { return r.State == Ready }

// Response fails closed for zero and unknown states. A caller must have fresh
// database evidence before reporting any state other than dependency failure.
func (r Readiness) Response() Response {
	if r.Ready() {
		return Response{Status: "ready"}
	}
	var code string
	switch r.State {
	case Initializing:
		code = CodeInitializing
	case SetupRequired:
		code = CodeSetupRequired
	case BootstrapFailed:
		code = CodeBootstrapFailed
	case SchemaError:
		code = CodeSchemaError
	default:
		code = CodeDependencyUnavailable
	}
	failure, _ := LookupFailure(code)
	return Response{Status: "not_ready", Error: &failure}
}

// LookupFailure lets clients allowlist codes without trusting a remote message.
func LookupFailure(code string) (Failure, bool) {
	var message string
	switch code {
	case CodeDependencyUnavailable:
		message = "Database unavailable"
	case CodeInitializing:
		message = "Platform initialization is in progress"
	case CodeSetupRequired:
		message = "Initial administrator configuration is required"
	case CodeBootstrapFailed:
		message = "Initial administrator configuration could not be used"
	case CodeSchemaError:
		message = "Platform schema is unavailable or incompatible"
	default:
		return Failure{}, false
	}
	return Failure{Code: code, Message: message}, true
}

// Checker observes readiness; it must not migrate or bootstrap on a GET.
type Checker interface {
	Check(context.Context) Readiness
}

type CheckFunc func(context.Context) Readiness

func (f CheckFunc) Check(ctx context.Context) Readiness { return f(ctx) }
