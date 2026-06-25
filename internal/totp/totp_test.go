package totp

import (
	"testing"
	"time"
)

// rfc6238Secret is the SHA1 seed from RFC 6238 Appendix B ("12345678901234567890")
// expressed as base32.
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestGenerateRFC6238Vectors(t *testing.T) {
	// The RFC publishes 8-digit codes; we emit 6 digits, i.e. the low 6 of each.
	cases := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		code, _, err := Generate(rfc6238Secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("Generate at %d: %v", c.unix, err)
		}
		if code != c.code {
			t.Errorf("Generate at %d = %s, want %s", c.unix, code, c.code)
		}
	}
}

func TestGenerateSecondsLeft(t *testing.T) {
	cases := []struct {
		unix int64
		want int
	}{
		{30, 30}, // start of a step
		{59, 1},  // one second before rollover
		{45, 15},
	}
	for _, c := range cases {
		_, left, err := Generate(rfc6238Secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("Generate at %d: %v", c.unix, err)
		}
		if left != c.want {
			t.Errorf("secondsLeft at %d = %d, want %d", c.unix, left, c.want)
		}
	}
}

func TestNormalizeSecret(t *testing.T) {
	// Lowercase, spaces, and padding are all tolerated and canonicalized.
	got, err := NormalizeSecret("gezd gnbv gy3t qojq")
	if err != nil {
		t.Fatalf("NormalizeSecret: %v", err)
	}
	if got != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("NormalizeSecret = %q", got)
	}

	if _, err := NormalizeSecret(""); err == nil {
		t.Error("empty secret should error")
	}
	if _, err := NormalizeSecret("not!valid!base32"); err == nil {
		t.Error("non-base32 secret should error")
	}
}

func TestGenerateInvalidSecret(t *testing.T) {
	if _, _, err := Generate("1", time.Now()); err == nil {
		t.Error("invalid base32 should error")
	}
}
