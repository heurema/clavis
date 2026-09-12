// Package secrets encrypts connection credentials at rest under an
// operator-held key. It has no knowledge of connections, storage or HTTP.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	KeyBytes       = 32
	currentVersion = "v1"
	maxPlaintext   = 4096
	nonceBytes     = 12
)

// ErrEnvelope is the only error Open returns for undecryptable, tampered,
// misattributed or unknown-version envelopes. Callers must not distinguish.
var ErrEnvelope = errors.New("secret envelope cannot be opened")

var errKey = errors.New("invalid key material")

// Keyring holds the current sealing key. Versions are part of the envelope
// so a later key can be added without touching stored rows.
type Keyring struct {
	current string
	keys    map[string]cipher.AEAD
}

func NewKeyring(key []byte) (*Keyring, error) {
	if len(key) != KeyBytes {
		return nil, errKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errKey
	}
	return &Keyring{current: currentVersion, keys: map[string]cipher.AEAD{currentVersion: aead}}, nil
}

// Seal encrypts plaintext for one owner. The context (for example
// "connection:<uuid>") and the key version are bound as associated data so an
// envelope cannot be moved between rows or replayed under another version.
// Nonces are random: GCM's collision bound (about 2^32 seals per key) is far
// beyond credential-write volume, and key rotation is a later change.
func (k *Keyring) Seal(plaintext []byte, context string) (string, error) {
	if k == nil || len(plaintext) == 0 || len(plaintext) > maxPlaintext || context == "" {
		return "", errKey
	}
	aead := k.keys[k.current]
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, plaintext, []byte(context+":"+k.current))
	return k.current + ":" + base64.RawStdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// Open decrypts an envelope produced by Seal for the same context.
func (k *Keyring) Open(envelope, context string) ([]byte, error) {
	if k == nil || context == "" {
		return nil, ErrEnvelope
	}
	version, encoded, found := strings.Cut(envelope, ":")
	aead, known := k.keys[version]
	if !found || !known {
		return nil, ErrEnvelope
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < nonceBytes+aead.Overhead() {
		return nil, ErrEnvelope
	}
	plaintext, err := aead.Open(nil, raw[:nonceBytes], raw[nonceBytes:], []byte(context+":"+version))
	if err != nil {
		return nil, ErrEnvelope
	}
	return plaintext, nil
}
