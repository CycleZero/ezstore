// Package crypto implements value encryption for ezstore.
//
// Every secret version is sealed with AES-256-GCM using a fresh random nonce.
// The associated data binds the ciphertext to the secret name and version, so
// a row copied to a different name or version fails authentication instead of
// silently decrypting into the wrong place.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the required master key length in bytes (AES-256).
const KeySize = 32

// Cipher seals and opens secret values with the master key.
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a 32-byte master key.
func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Seal returns a fresh nonce and the sealed ciphertext.
func (c *Cipher) Seal(plain, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, c.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	return nonce, c.aead.Seal(nil, nonce, plain, aad), nil
}

// Open decrypts a ciphertext produced by Seal with the same associated data.
func (c *Cipher) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != c.aead.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	plain, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decryption failed: wrong master key or tampered ciphertext")
	}
	return plain, nil
}

// GenerateKey returns a new random master key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ParseKey accepts a hex (64 chars) or base64 encoded master key.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty master key")
	}
	if len(s) == hex.EncodedLen(KeySize) {
		if key, err := hex.DecodeString(s); err == nil {
			return key, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if key, err := enc.DecodeString(s); err == nil && len(key) == KeySize {
			return key, nil
		}
	}
	return nil, errors.New("master key must be 32 bytes encoded as hex or base64")
}

// FormatKey renders a master key as lowercase hex.
func FormatKey(key []byte) string { return hex.EncodeToString(key) }

// AAD returns the associated data bound to one secret version.
func AAD(name string, version int64) []byte {
	return fmt.Appendf(nil, "ezstore|v1|%s|%d", name, version)
}

// Checksum returns the hex SHA-256 of the plaintext. It is stored next to the
// ciphertext so integrity can be checked without opening the value.
func Checksum(plain []byte) string {
	sum := sha256.Sum256(plain)
	return hex.EncodeToString(sum[:])
}
