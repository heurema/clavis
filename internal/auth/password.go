package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

func ValidUsername(value string) bool { return usernamePattern.MatchString(value) }

func ValidPassword(value Secret) bool {
	s := string(value)
	return len(s) >= MinPasswordBytes && len(s) <= MaxPasswordBytes &&
		utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

// The encoded format is deliberately fixed: a corrupt stored value cannot
// request arbitrary memory or CPU. Future cost changes require a new version.
const hashPrefix = "$clavis$1$argon2id$v=19$m=65536,t=3,p=1$"

var hashSlots = make(chan struct{}, 2)

type hashResult struct {
	key []byte
}

func derive(ctx context.Context, password Secret, salt []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, &Error{Code: ServiceUnavailable}
	}
	select {
	case hashSlots <- struct{}{}:
	default:
		return nil, &Error{Code: RateLimited, RetryAfter: time.Second}
	}
	result := make(chan hashResult, 1)
	go func() {
		defer func() { <-hashSlots }()
		result <- hashResult{argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)}
	}()
	select {
	case <-ctx.Done():
		return nil, &Error{Code: ServiceUnavailable}
	case r := <-result:
		if ctx.Err() != nil {
			return nil, &Error{Code: ServiceUnavailable}
		}
		return r.key, nil
	}
}

func HashPassword(ctx context.Context, password Secret) (string, error) {
	if !ValidPassword(password) {
		return "", &Error{Code: InvalidArgument}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", &Error{Code: ServiceUnavailable}
	}
	key, err := derive(ctx, password, salt)
	if err != nil {
		return "", err
	}
	return hashPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

func VerifyPassword(ctx context.Context, password Secret, encoded string) (bool, error) {
	if !ValidPassword(password) {
		return false, &Error{Code: InvalidArgument}
	}
	if len(encoded) != len(hashPrefix)+22+1+43 || !strings.HasPrefix(encoded, hashPrefix) {
		return false, &Error{Code: ServiceUnavailable}
	}
	parts := strings.Split(strings.TrimPrefix(encoded, hashPrefix), "$")
	if len(parts) != 2 {
		return false, &Error{Code: ServiceUnavailable}
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return false, &Error{Code: ServiceUnavailable}
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(want) != 32 {
		return false, &Error{Code: ServiceUnavailable}
	}
	key, err := derive(ctx, password, salt)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, want) == 1, nil
}

// DummyPasswordHash uses the same cost and allocation as a real account.
// The public constant is not an account credential.
func DummyPasswordHash() string {
	return hashPrefix + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" +
		base64.RawStdEncoding.EncodeToString(make([]byte, 32))
}
