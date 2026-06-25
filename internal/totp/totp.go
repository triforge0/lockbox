// Package totp implements RFC 6238 time-based one-time passwords (TOTP) over the
// RFC 4226 HOTP construction. It uses HMAC-SHA1, a 30-second time step, and
// 6-digit codes — the defaults every authenticator app and provider assumes.
//
// Like the other leaf packages it depends only on the standard library; it knows
// nothing about vaults, storage, or the CLI.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// period is the time step in seconds (RFC 6238 default).
	period = 30
	// digits is the length of a generated code (RFC 4226 default).
	digits = 6
)

// NormalizeSecret cleans a user-entered base32 secret (uppercasing, stripping
// spaces and padding) and verifies it decodes, returning the canonical form. Use
// it to validate a secret before storing it.
func NormalizeSecret(secret string) (string, error) {
	cleaned := canonical(secret)
	if cleaned == "" {
		return "", fmt.Errorf("empty TOTP secret")
	}
	if _, err := decode(cleaned); err != nil {
		return "", err
	}
	return cleaned, nil
}

// Generate returns the TOTP code for the given base32 secret at time t, along
// with how many seconds remain before it rolls over.
func Generate(secret string, t time.Time) (code string, secondsLeft int, err error) {
	key, err := decode(canonical(secret))
	if err != nil {
		return "", 0, err
	}

	counter := uint64(t.Unix()) / period
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3).
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code = fmt.Sprintf("%0*d", digits, value%mod)
	secondsLeft = period - int(uint64(t.Unix())%period)
	return code, secondsLeft, nil
}

// canonical uppercases the secret and removes spaces and base32 padding, the
// forms providers commonly present secrets in.
func canonical(secret string) string {
	s := strings.ToUpper(strings.TrimSpace(secret))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return strings.TrimRight(s, "=")
}

// decode interprets s as unpadded standard base32.
func decode(s string) ([]byte, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 TOTP secret")
	}
	return key, nil
}
