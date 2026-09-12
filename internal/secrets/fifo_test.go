package secrets

import "golang.org/x/sys/unix"

// A FIFO must be rejected without blocking: the loader opens nonblocking and
// checks the opened file's type rather than a pre-open stat.
func mkfifo(path string) error { return unix.Mkfifo(path, 0o600) }
