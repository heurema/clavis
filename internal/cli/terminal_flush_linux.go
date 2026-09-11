//go:build linux

package cli

import "golang.org/x/sys/unix"

func flushTerminalInput(fd int) error {
	// Linux TCFLSH takes the tcflush selector as a value, not a pointer.
	return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}
