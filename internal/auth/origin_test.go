package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Clavis.Example:443/":      "https://clavis.example",
		"https://EXAMPLE.com:0443/":        "https://example.com",
		"HTTPS://EXAMPLE.com/":             "https://example.com",
		"http://127.0.0.1:80":              "http://127.0.0.1",
		"http://127.0.0.1:080/":            "http://127.0.0.1",
		"http://127.2.3.4:65535":           "http://127.2.3.4:65535",
		"http://[::1]:1234":                "http://[::1]:1234",
		"http://[0:0:0:0:0:0:0:1]:80":      "http://[::1]",
		"https://[2001:0db8::1]:443":       "https://[2001:db8::1]",
		"https://[2001:0db8::1]:00444":     "https://[2001:db8::1]:444",
		"http://[::ffff:127.0.0.1]:80":     "http://[::ffff:127.0.0.1]",
		"https://[::ffff:127.0.0.1]:443":   "https://[::ffff:127.0.0.1]",
		"https://[::ffff:192.0.2.1]:00444": "https://[::ffff:192.0.2.1]:444",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := CanonicalOrigin(raw)
			require.NoError(t, err)
			require.Equal(t, want, got)
			again, err := CanonicalOrigin(got)
			require.NoError(t, err)
			require.Equal(t, got, again)
		})
	}
}

func TestCanonicalOriginRejectsUnsafeAndMalformedOrigins(t *testing.T) {
	for _, raw := range []string{
		"http://localhost", "http://clavis.example", "http://example.com",
		"http://127.0.0.1.example.com", "http://2130706433", "http://192.0.2.1",
		"http://[2001:db8::1]", "http://[::ffff:192.0.2.1]",
		"https://user:secret@clavis.example", "https://user:pass@example.com",
		"https://clavis.example/path", "https://example.com/base", "https://example.com//",
		"https://example.com/%2f", "https://example.com/%2F", "https://example.com/%",
		"https://example.com/%zz", "https://%65xample.com", "https://example%25.com",
		"https://example.com?", "https://example.com#", "https://clavis.example?secret",
		"https://clavis.example#secret", "https://example.com\\secret",
		"https://example.com:0", "http://127.0.0.1:0", "http://[::1]:000",
		"https://example.com:65536", "https://clavis.example:99999",
		"https://example.com:", "https://[::1]:", "https://example.com:-1",
		"https://example.com:+443", "https://example.com:secret",
		"http://[::1%25lo0]", "https://[fe80::1%25en0]",
		"https://[example.com]", "https://[127.0.0.1]", "https://::1",
		"https://[::1", "https://::1]", "https://example.com::443",
		"file:///tmp/test", "https:example.com", "https:///example.com", "",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := CanonicalOrigin(raw)
			require.EqualError(t, err, "invalid origin")
			require.Empty(t, got)
		})
	}
}
