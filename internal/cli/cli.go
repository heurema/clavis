package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/heurema/clavis/internal/buildinfo"
	urfave "github.com/urfave/cli/v3"
)

// Run preserves the stdout-only entry point for callers that do not need input.
func Run(ctx context.Context, args []string, stdout io.Writer) int {
	return RunWithIO(ctx, args, IO{Stdout: stdout})
}

// RunWithIO is the command output/exit boundary. Library usage errors and help
// are buffered so an invalid invocation always produces one JSON document.
func RunWithIO(ctx context.Context, args []string, streams IO) int {
	streams = streams.withDefaults()
	stdout := streams.Stdout
	var help bytes.Buffer
	var result *Result
	format := "json"
	invalid := errors.New("invalid invocation")
	check := func(command *urfave.Command) error {
		format = command.String("output")
		if command.Args().Len() != 0 || (format != "json" && format != "text") {
			return invalid
		}
		return nil
	}
	command := &urfave.Command{
		Name: "clavis", Usage: "Controlled access for your agents",
		Reader: streams.Stdin, Writer: &help, ErrWriter: io.Discard,
		ExitErrHandler: func(context.Context, *urfave.Command, error) {},
		OnUsageError:   func(context.Context, *urfave.Command, error, bool) error { return invalid },
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "output", Value: "json", Usage: "Output format: json or text"},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			if err := check(command); err != nil {
				return err
			}
			return urfave.ShowAppHelp(command)
		},
		Commands: []*urfave.Command{
			{Name: "version", Usage: "Show local build information", Action: func(ctx context.Context, command *urfave.Command) error {
				if err := check(command); err != nil {
					return err
				}
				value := success(buildinfo.Current())
				result = &value
				return nil
			}},
			{Name: "doctor", Usage: "Check server and platform database readiness", Flags: []urfave.Flag{
				&urfave.StringFlag{Name: "server", Value: "http://127.0.0.1:8080", Sources: urfave.EnvVars("CLAVIS_SERVER_URL"), Usage: "Server base URL"},
				&urfave.DurationFlag{Name: "timeout", Value: 5 * time.Second, Usage: "Entire readiness request deadline"},
			}, Action: func(ctx context.Context, command *urfave.Command) error {
				if err := check(command); err != nil {
					return err
				}
				value := Doctor(ctx, command.String("server"), command.Duration("timeout"))
				result = &value
				return nil
			}},
		},
	}
	command.Commands = append(command.Commands, authCommands(streams, check, func(value Result) { result = &value })...)
	if err := command.Run(ctx, args); err != nil {
		value := failure("INVALID_ARGUMENT", "Invalid arguments or configuration; run clavis help", nil)
		if secretValueFlag(args) {
			// There is deliberately no flag that carries a secret value; say
			// which channels exist instead of the generic usage message.
			value = failureWithHint("INVALID_ARGUMENT", "A secret is never accepted as a flag value", secretInputHint)
		}
		result = &value
	}
	if result == nil {
		if _, err := io.Copy(stdout, &help); err != nil {
			return 1
		}
		return 0
	}
	invalidArgument := result.Error != nil && result.Error.Code == "INVALID_ARGUMENT"
	if invalidArgument {
		format = "json"
	}
	if err := render(stdout, *result, format); err != nil {
		return 1
	}
	switch {
	case result.OK:
		return 0
	case invalidArgument:
		return 2
	default:
		return 1
	}
}
