package cli

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/heurema/clavis/internal/auth"
)

var errPasswordInput = errors.New("password input unavailable or invalid")

func passwordFromStdin(ctx context.Context, input io.Reader) ([]byte, error) {
	// Read one extra byte beyond the largest password plus CRLF to distinguish
	// an exactly full input from a truncated oversized one.
	body := make([]byte, 0, auth.MaxPasswordBytes+3)
	for len(body) <= auth.MaxPasswordBytes+2 {
		b, err := inputByte(ctx, input)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		body = append(body, b)
	}
	if bytes.HasSuffix(body, []byte("\r\n")) {
		body = body[:len(body)-2]
	} else if bytes.HasSuffix(body, []byte("\n")) {
		body = body[:len(body)-1]
	}
	if !validPassword(body) {
		return nil, errPasswordInput
	}
	return body, nil
}

func validPassword(body []byte) bool {
	return auth.ValidPassword(auth.Secret(body))
}
