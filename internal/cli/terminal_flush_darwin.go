//go:build darwin

package cli

import "golang.org/x/sys/unix"

func flushTerminalInput(fd int) error {
	// TIOCFLUSH takes a pointer to an FREAD/FWRITE bitmask, not the
	// tcflush selector used by Linux. FREAD is 1 on Darwin.
	const fRead = 1
	return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fRead)
}
