//go:build darwin

package cli

import (
	"os"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

func testPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	// Keep Darwin's PTY allocation in the maintained platform adapter rather
	// than issuing a deprecated raw ioctl from the test harness.
	master, slave, err := pty.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = master.Close() })
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}
