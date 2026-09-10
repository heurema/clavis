package cli

import (
	"context"
	"io"
	"strings"
)

// HiddenPasswordReader reads a password without echo from stdin, writing any
// prompt only to stderr. Implementations must reject non-terminal input, honor
// ctx cancellation and restore terminal state before returning. It is separate
// from explicit password-stdin input, which reads Stdin without prompting.
type HiddenPasswordReader func(ctx context.Context, stdin io.Reader, stderr io.Writer) ([]byte, error)

// IO supplies command streams without relying on process-global standard files.
// Nil streams mean empty input or discarded output, never an implicit OS stream.
// ReadPassword is optional; nil means hidden input is unavailable, not permission
// to fall back to echoed input. Existing commands do not read passwords.
// The caller owns the streams; commands do not close them.
type IO struct {
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
	ReadPassword HiddenPasswordReader
}

func (streams IO) withDefaults() IO {
	if streams.Stdin == nil {
		streams.Stdin = strings.NewReader("")
	}
	if streams.Stdout == nil {
		streams.Stdout = io.Discard
	}
	if streams.Stderr == nil {
		streams.Stderr = io.Discard
	}
	return streams
}
