package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// secretInputHint is the single description of every accepted secret channel.
// It names flags only, never a submitted value.
const secretInputHint = "Supply the secret through exactly one of: a hidden terminal prompt, --password-stdin, " +
	"--password-file <absolute path to a regular file without group or world permissions>, or --password-env <NAME>"

var errSecretInput = errors.New("secret input unavailable or invalid")

// environmentName is the portable environment-variable spelling; the value is
// read from the process environment, never from an argument.
var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// secretFlags are the non-interactive secret channels. There is deliberately
// no flag carrying the secret value itself, so such an argument is an unknown
// flag and exits 2 before anything else happens.
func secretFlags() []urfave.Flag {
	return []urfave.Flag{
		&urfave.BoolFlag{Name: "password-stdin", Usage: "Read the bounded secret from stdin instead of a hidden terminal prompt"},
		&urfave.StringFlag{Name: "password-file", Usage: "Absolute path of a protected regular file holding the secret"},
		&urfave.StringFlag{Name: "password-env", Usage: "Name of an environment variable holding the secret"},
	}
}

func invalidSecretInput() *Result {
	r := failureWithHint(auth.InvalidArgument, "Provide exactly one valid secret input", secretInputHint)
	return &r
}

// readSecret is the connection credential input path. Exactly one channel may
// be used, the prompt only when hidden terminal input is available. When the
// operation needs no secret, supplying one is refused. Every rejection happens
// before any cache or network access, and no rejection echoes the value.
func readSecret(ctx context.Context, command *urfave.Command, streams IO, required bool) (auth.Secret, *Result) {
	stdin, file, name := command.Bool("password-stdin"), command.String("password-file"), command.String("password-env")
	given := 0
	for _, used := range []bool{stdin, file != "", name != ""} {
		if used {
			given++
		}
	}
	if given > 1 || (!required && given > 0) {
		return "", invalidSecretInput()
	}
	if !required {
		return "", nil
	}
	var value []byte
	var err error
	switch {
	case stdin:
		value, err = secretFromStdin(ctx, streams.Stdin)
	case file != "":
		value, err = secretFromFile(file)
	case name != "":
		value, err = secretFromEnvironment(name)
	case streams.ReadPassword != nil:
		value, err = streams.ReadPassword(ctx, streams.Stdin, streams.Stderr)
	default:
		err = errSecretInput
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		r := failure("TIMEOUT", "Secret input was canceled", nil)
		return "", &r
	}
	if err != nil || !auth.ValidSecret(auth.Secret(value)) {
		return "", invalidSecretInput()
	}
	return auth.Secret(value), nil
}

// secretFromStdin reads one bounded line without prompting.
func secretFromStdin(ctx context.Context, input io.Reader) ([]byte, error) {
	// One byte beyond the largest secret plus CRLF separates an exactly full
	// input from a truncated oversized one.
	body := make([]byte, 0, auth.MaxSecretBytes+3)
	for len(body) <= auth.MaxSecretBytes+2 {
		b, err := inputByte(ctx, input)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		body = append(body, b)
	}
	return trimTerminator(body), nil
}

// secretFromFile applies the bootstrap secret-file rules: absolute path,
// special files opened nonblocking, regular file, no group or world permission
// bits, bounded size and at most one terminal newline. The rules are copied
// rather than imported so the CLI build stays free of server packages.
func secretFromFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errSecretInput
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errSecretInput
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errSecretInput
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errSecretInput
	}
	if info.Size() > auth.MaxSecretBytes+2 {
		return nil, errSecretInput
	}
	data, err := io.ReadAll(io.LimitReader(file, auth.MaxSecretBytes+3))
	if err != nil || len(data) > auth.MaxSecretBytes+2 {
		return nil, errSecretInput
	}
	return trimTerminator(data), nil
}

// secretFromEnvironment reads a named variable. The name is an argument; the
// value never is.
func secretFromEnvironment(name string) ([]byte, error) {
	if !environmentName.MatchString(name) {
		return nil, errSecretInput
	}
	value := os.Getenv(name)
	if value == "" {
		return nil, errSecretInput
	}
	return []byte(value), nil
}

func trimTerminator(body []byte) []byte {
	if bytes.HasSuffix(body, []byte("\r\n")) {
		return body[:len(body)-2]
	}
	return bytes.TrimSuffix(body, []byte("\n"))
}

// secretValueFlag reports whether the invocation tried to pass a secret as a
// flag value. Only the bare flag counts: the documented channels carry a path
// or a variable name, never the secret itself.
func secretValueFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--password" || arg == "-password" ||
			strings.HasPrefix(arg, "--password=") || strings.HasPrefix(arg, "-password=") {
			return true
		}
	}
	return false
}
