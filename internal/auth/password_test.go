package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCredentialValidationBoundaries(t *testing.T) {
	for _, value := range []string{"abc", "a._-", "a" + strings.Repeat("9", 63)} {
		require.True(t, ValidUsername(value))
	}
	for _, value := range []string{"ab", "Alice", " abc", "1abc", "a@example.com", strings.Repeat("a", 65), "ábc", "abcdef12-3456-4890-abcd-ef1234567890"} {
		require.False(t, ValidUsername(value))
	}
	for _, value := range []string{strings.Repeat(" ", 15), strings.Repeat("\x01", 1024), strings.Repeat("é", 512), "  valid password  "} {
		require.True(t, ValidPassword(Secret(value)))
	}
	for _, value := range []string{strings.Repeat("x", 14), strings.Repeat("x", 1025), strings.Repeat("é", 513), "a valid password\n", "a valid password\r", "a valid password\x00", "a valid password\xff"} {
		require.False(t, ValidPassword(Secret(value)))
	}
}

func TestPasswordEncodingAndBoundedParsing(t *testing.T) {
	password := Secret("  unique test password  ")
	encoded, err := HashPassword(t.Context(), password)
	require.NoError(t, err)
	other, err := HashPassword(t.Context(), password)
	require.NoError(t, err)
	require.NotEqual(t, encoded, other)
	ok, err := VerifyPassword(t.Context(), password, encoded)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = VerifyPassword(t.Context(), "different test password", encoded)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = VerifyPassword(t.Context(), password, DummyPasswordHash())
	require.NoError(t, err)
	require.False(t, ok)
	for _, bad := range []string{"", strings.Repeat("x", 10000), strings.Replace(encoded, "65536", "999999999", 1), strings.Replace(encoded, "v=19", "v=18", 1), encoded + "=", encoded[:len(encoded)-1]} {
		start := time.Now()
		_, err := VerifyPassword(t.Context(), password, bad)
		require.Error(t, err)
		require.Less(t, time.Since(start), 100*time.Millisecond)
	}
}

func TestHashBudgetSurvivesCancellation(t *testing.T) {
	require.Empty(t, hashSlots)
	hashSlots <- struct{}{}
	hashSlots <- struct{}{}
	_, err := HashPassword(t.Context(), "valid test password")
	require.ErrorAs(t, err, new(*Error))
	require.Equal(t, RateLimited, err.(*Error).Code)
	<-hashSlots
	<-hashSlots
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := HashPassword(ctx, "valid test password"); done <- err }()
	require.Eventually(t, func() bool { return len(hashSlots) == 1 }, time.Second, time.Millisecond)
	cancel()
	require.Error(t, <-done)
	// Slot remains owned by the fixed KDF, not by the canceled request.
	require.Eventually(t, func() bool { return len(hashSlots) == 0 }, 5*time.Second, time.Millisecond)
	_, err = HashPassword(ctx, "valid test password")
	require.Error(t, err)
	require.Empty(t, hashSlots)
}

func BenchmarkArgon2idBaseline(b *testing.B) {
	for b.Loop() {
		_, err := HashPassword(context.Background(), "benchmark-only test password")
		if err != nil {
			b.Fatal("hash failed")
		}
	}
}
