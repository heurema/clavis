//go:build darwin || linux

package cli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

type passwordPromptFunc func([]byte) (int, error)

func (f passwordPromptFunc) Write(p []byte) (int, error) { return f(p) }

// Check in raw mode so even an unterminated fragment would be visible to the
// next terminal reader (a canonical-mode poll alone would miss that fragment).
func assertTerminalInputEmpty(t *testing.T, slave *os.File) {
	t.Helper()
	state, err := term.MakeRaw(int(slave.Fd()))
	require.NoError(t, err)
	defer func() { require.NoError(t, term.Restore(int(slave.Fd()), state)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = inputByte(ctx, slave)
	require.ErrorIs(t, err, context.DeadlineExceeded, "password remainder reached the next terminal reader")
}

func TestTerminalPasswordFlushQueuedInput(t *testing.T) {
	const secret = "SECRET-SUFFIX-MUST-NOT-REACH-SHELL"
	for _, mode := range []string{"success-crlf", "invalid", "ctrl-c", "ctrl-d", "cancel-queued", "prompt-failure"} {
		t.Run(mode, func(t *testing.T) {
			master, slave := testPTY(t)
			original, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			// Queue input synchronously in the prompt writer, after raw mode
			// starts but before any password read. Cancellation therefore
			// deterministically has unread data, rather than racing the reader.
			prompt := passwordPromptFunc(func(p []byte) (int, error) {
				if string(p) != "Password: " {
					return len(p), nil
				}
				prefix := strings.Repeat("a", 20) + "\r\n"
				switch mode {
				case "invalid":
					prefix = "\n"
				case "ctrl-c":
					prefix = "\x03"
				case "ctrl-d":
					prefix = "\x04"
				case "cancel-queued", "prompt-failure":
					prefix = ""
				}
				_, err := io.WriteString(master, prefix+secret+"\nunterminated-secret")
				require.NoError(t, err)
				if mode == "cancel-queued" {
					cancel()
				}
				if mode == "prompt-failure" {
					return 0, io.ErrClosedPipe
				}
				return len(p), nil
			})
			password, err := ReadTerminalPassword(ctx, slave, prompt)
			switch mode {
			case "success-crlf":
				require.NoError(t, err)
				require.Equal(t, strings.Repeat("a", 20), string(password))
			case "cancel-queued", "ctrl-c":
				require.ErrorIs(t, err, context.Canceled)
				require.Nil(t, password)
			default:
				require.ErrorIs(t, err, errPasswordInput)
				require.Nil(t, password)
			}
			restored, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			require.Equal(t, original, restored)
			assertTerminalInputEmpty(t, slave)
		})
	}
}

func TestTerminalPasswordOverflowDrainsUntilTerminatorOrCancellation(t *testing.T) {
	for _, cancelOverflow := range []bool{false, true} {
		name := "terminator"
		if cancelOverflow {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			master, slave := testPTY(t)
			original, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := ReadTerminalPassword(ctx, slave, slave)
				result <- err
			}()
			// Always cancel and join the reader, including when an assertion fails.
			defer func() {
				cancel()
				select {
				case <-result:
				case <-time.After(time.Second):
					t.Error("password reader did not stop")
				}
			}()
			for range len("Password: ") {
				_, err := inputByte(ctx, master)
				require.NoError(t, err)
			}
			_, err = io.WriteString(master, strings.Repeat("x", 3072))
			require.NoError(t, err)
			select {
			case err := <-result:
				result <- err
				t.Fatal("oversized input returned before terminator or cancellation")
			case <-time.After(100 * time.Millisecond):
			}
			raw, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			require.NotEqual(t, original, raw)
			if cancelOverflow {
				cancel()
			} else {
				_, err = io.WriteString(master, "SECRET-SUFFIX-MUST-NOT-REACH-SHELL\n")
				require.NoError(t, err)
			}
			select {
			case err := <-result:
				result <- err // Leave completion available to the deferred join.
				if cancelOverflow {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, errPasswordInput)
				}
			case <-time.After(time.Second):
				t.Fatal("password cleanup hung")
			}
			restored, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			require.Equal(t, original, restored)
			assertTerminalInputEmpty(t, slave)
		})
	}
}
