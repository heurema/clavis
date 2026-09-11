package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestDeriveReturnsArgon2Key(t *testing.T) {
	password := Secret("fixed derivation test password")
	salt := []byte("fixed-test-salt!!")
	want := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	got, err := derive(t.Context(), password, salt)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestDeriveCanceledContextReturnsNoKey(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	key, err := derive(ctx, "fixed derivation test password", []byte("fixed-test-salt!!"))
	require.Nil(t, key)
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, ServiceUnavailable, authErr.Code)
}
