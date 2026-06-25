package crypto

import (
	"crypto/rand"
	"fmt"
)

// passwordAlphabet is the character set for generated passwords: digits, upper
// and lower case letters, and a set of common symbols. Ambiguous-looking
// characters are kept for entropy; this is a generated secret, not something a
// user transcribes by hand.
const passwordAlphabet = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"0123456789" +
	"!@#$%^&*()-_=+[]{};:,.?"

// GeneratePassword returns a cryptographically random password of the given
// length, drawn uniformly from passwordAlphabet. It uses rejection sampling so
// every character is equally likely (no modulo bias).
func GeneratePassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive, got %d", length)
	}

	// Reject byte values in the final, partial block of the alphabet so the
	// mapping byte%len(alphabet) stays uniform.
	n := byte(len(passwordAlphabet))
	limit := byte(256 - (256 % int(n)))

	out := make([]byte, length)
	buf := make([]byte, length)
	for i := 0; i < length; {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, b := range buf {
			if b >= limit {
				continue // would bias the distribution; draw again
			}
			out[i] = passwordAlphabet[b%n]
			i++
			if i == length {
				break
			}
		}
	}
	return string(out), nil
}
