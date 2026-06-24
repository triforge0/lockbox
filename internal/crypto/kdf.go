// Package crypto isolates all key derivation and authenticated encryption. It
// depends only on the standard library and the Argon2 package, never on the CLI
// or storage layers.
package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These are fixed so a vault written on one machine can
// always be reopened on another.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4

	// KeyLen is the derived key length: 32 bytes for AES-256.
	KeyLen = 32
	// SaltLen is the Argon2id salt length.
	SaltLen = 16
)

// DeriveKey turns a master password + salt into a 32-byte AES key via Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, KeyLen)
}

// NewSalt returns a fresh cryptographically random Argon2id salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
