// Adapted from templUI v1.13.2 utils/templui.go; see ../THIRD_PARTY_NOTICES.md.
package utils

import (
	"crypto/rand"
	"fmt"

	twmerge "github.com/Oudwins/tailwind-merge-go"
)

// TwMerge combines Tailwind classes and resolves conflicts.
// Example: "bg-red-500 hover:bg-blue-500", "bg-green-500" → "hover:bg-blue-500 bg-green-500"
func TwMerge(classes ...string) string {
	return twmerge.Merge(classes...)
}

// If returns value if condition is true, otherwise the zero value of T.
// Example: true, "bg-red-500" → "bg-red-500"
func If[T any](condition bool, value T) T {
	var empty T
	if condition {
		return value
	}
	return empty
}

// RandomID generates a random ID string.
// Example: RandomID() → "id-1a2b3c"
func RandomID() string {
	return fmt.Sprintf("id-%s", rand.Text())
}
