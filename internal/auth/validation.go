package auth

import (
	"encoding/base64"
	"encoding/hex"
)

func ValidUserID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:])
	return err == nil
}

func ValidToken(value Secret) bool {
	if len(value) != 43 {
		return false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(string(value))
	return err == nil && len(data) == 32
}
