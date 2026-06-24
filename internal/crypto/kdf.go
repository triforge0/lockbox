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

// Argon2id parameters. Memory and threads are fixed so a vault written on one
// machine can always be reopened on another; the time cost is passed per call so
// older vaults can be opened with the cost they were created with (see
// Argon2Time / Argon2TimeV1).
const (
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4

	// Argon2Time is the time cost for new vaults (file version 2+). Raised from
	// the original 1 to make offline brute force of a stolen vault costlier.
	Argon2Time uint32 = 3
	// Argon2TimeV1 is the time cost baked into version-1 vaults. Kept so they
	// can still be opened (and transparently re-keyed to Argon2Time on unlock).
	Argon2TimeV1 uint32 = 1

	// KeyLen is the derived key length: 32 bytes for AES-256.
	KeyLen = 32
	// SaltLen is the Argon2id salt length.
	SaltLen = 16
)

// DeriveKey turns a master password + salt into a 32-byte AES key via Argon2id
// at the given time cost. Pass Argon2Time for new vaults, or the cost matching
// an existing vault's file version when reopening one.
func DeriveKey(password string, salt []byte, timeCost uint32) []byte {
	return argon2.IDKey([]byte(password), salt, timeCost, argonMemory, argonThreads, KeyLen)
}

// NewSalt returns a fresh cryptographically random Argon2id salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
