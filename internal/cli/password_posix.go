//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/heurema/clavis/internal/auth"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ReadTerminalPassword is the production hidden-input adapter. Raw mode bounds
// allocation before a newline, and polling observes cancellation even while the
// terminal is idle. Every return restores the original terminal configuration.
func ReadTerminalPassword(ctx context.Context, input io.Reader, prompt io.Writer) (password []byte, err error) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, errPasswordInput
	}
	fd := int(file.Fd())
	var state *term.State
	defer func() {
		// Flush on every exit, including success: CRLF and pasted lines after
		// the terminator must not become input to the invoking shell. Do this
		// while echo is still disabled, without waiting for future input.
		if flushErr := flushTerminalInput(fd); flushErr != nil {
			password, err = nil, errPasswordInput
		}
		if state != nil {
			if restoreErr := term.Restore(fd, state); restoreErr != nil {
				password, err = nil, errPasswordInput
			}
			_, _ = io.WriteString(prompt, "\n")
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err = term.MakeRaw(fd)
	if err != nil {
		return nil, errPasswordInput
	}
	if _, err := io.WriteString(prompt, "Password: "); err != nil {
		return nil, errPasswordInput
	}
	password = make([]byte, 0, auth.MaxPasswordBytes)
	overflow := false
	for {
		b, err := inputByte(ctx, input)
		if err != nil {
			return nil, err
		}
		switch b {
		case 3: // Raw mode delivers Ctrl-C rather than generating SIGINT.
			return nil, context.Canceled
		case 4:
			return nil, errPasswordInput
		case '\r', '\n':
			if overflow || !validPassword(password) {
				return nil, errPasswordInput
			}
			return password, nil
		case 8, 127:
			if !overflow && len(password) > 0 {
				_, size := utf8.DecodeLastRune(password)
				password = password[:len(password)-size]
			}
		default:
			if overflow {
				continue
			}
			if len(password) == auth.MaxPasswordBytes {
				// An oversized line stays invalid even after backspace. Drain
				// through its terminator with bounded memory and cancellable
				// reads; returning here would expose the rest of the password.
				overflow = true
				continue
			}
			password = append(password, b)
		}
	}
}

func inputByte(ctx context.Context, input io.Reader) (byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if file, ok := input.(*os.File); ok {
			fds := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 50)
			if errors.Is(err, unix.EINTR) || (err == nil && n == 0) {
				continue
			}
			if err != nil || fds[0].Revents&unix.POLLNVAL != 0 {
				return 0, errPasswordInput
			}
		}
		var b [1]byte
		n, err := input.Read(b[:])
		if n == 1 {
			return b[0], nil
		}
		if err != nil {
			return 0, err
		}
	}
}
