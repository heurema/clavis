//go:build !darwin && !linux

package cli

import (
	"context"
	"io"
)

func ReadTerminalPassword(context.Context, io.Reader, io.Writer) ([]byte, error) {
	return nil, errPasswordInput
}

func inputByte(ctx context.Context, input io.Reader) (byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var b [1]byte
	_, err := io.ReadFull(input, b[:])
	return b[0], err
}
