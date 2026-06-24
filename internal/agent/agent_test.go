package agent

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"lockbox/internal/crypto"
)

// roundtrip drives a single request through agent.handle over an in-memory pipe.
func roundtrip(t *testing.T, a *agent, req request) (response, bool) {
	t.Helper()
	client, server := net.Pipe()
	var stop bool
	done := make(chan struct{})
	go func() {
		stop = a.handle(server)
		close(done)
	}()

	data, _ := json.Marshal(req)
	if _, err := client.Write(append(data, '\n')); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var resp response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	<-done
	client.Close()
	return resp, stop
}

func newTestAgent(t *testing.T, ttl time.Duration) *agent {
	t.Helper()
	salt, err := crypto.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	return &agent{
		key:          crypto.DeriveKey("pw", salt, crypto.Argon2Time),
		salt:         salt,
		expiresAt:    time.Now().Add(ttl),
		hardDeadline: time.Now().Add(ttl),
	}
}

func TestAgentExpiredSessionRejectsAndStops(t *testing.T) {
	a := newTestAgent(t, -time.Minute) // already expired
	resp, stop := roundtrip(t, a, request{Op: "status"})
	if resp.OK {
		t.Error("expired session returned OK")
	}
	if resp.Error != ErrNoSession.Error() {
		t.Errorf("error = %q, want %q", resp.Error, ErrNoSession.Error())
	}
	if !stop {
		t.Error("expired session should stop the agent")
	}
}

func TestAgentLockStops(t *testing.T) {
	a := newTestAgent(t, time.Hour)
	resp, stop := roundtrip(t, a, request{Op: "lock"})
	if !resp.OK {
		t.Errorf("lock returned error: %s", resp.Error)
	}
	if !stop {
		t.Error("lock should stop the agent")
	}
}

func TestAgentEncryptDecryptRoundTrip(t *testing.T) {
	a := newTestAgent(t, time.Hour)
	secret := []byte(`{"items":[{"service":"x","username":"u","password":"p"}]}`)

	enc, stop := roundtrip(t, a, request{
		Op:        "encrypt",
		Plaintext: base64.StdEncoding.EncodeToString(secret),
	})
	if !enc.OK || stop {
		t.Fatalf("encrypt failed: ok=%v stop=%v err=%s", enc.OK, stop, enc.Error)
	}

	dec, _ := roundtrip(t, a, request{
		Op:         "decrypt",
		Nonce:      enc.Nonce,
		Ciphertext: enc.Ciphertext,
	})
	if !dec.OK {
		t.Fatalf("decrypt failed: %s", dec.Error)
	}
	got, err := base64.StdEncoding.DecodeString(dec.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("round trip mismatch: got %q", got)
	}
}

func TestAgentActivityExtendsIdleDeadline(t *testing.T) {
	a := newTestAgent(t, time.Hour)
	// Force the idle window close, but keep a generous hard cap so extend can
	// push the deadline back out.
	a.expiresAt = time.Now().Add(50 * time.Millisecond)
	a.hardDeadline = time.Now().Add(time.Hour)
	before := a.expiresAt

	enc, stop := roundtrip(t, a, request{
		Op:        "encrypt",
		Plaintext: base64.StdEncoding.EncodeToString([]byte(`{"items":[]}`)),
	})
	if !enc.OK || stop {
		t.Fatalf("encrypt failed: ok=%v stop=%v err=%s", enc.OK, stop, enc.Error)
	}
	if !a.expiresAt.After(before) {
		t.Errorf("activity did not extend the idle deadline: before=%v after=%v", before, a.expiresAt)
	}
	if a.expiresAt.After(a.hardDeadline) {
		t.Errorf("extended deadline %v exceeded hard cap %v", a.expiresAt, a.hardDeadline)
	}
}

func TestAgentExtendNeverExceedsHardDeadline(t *testing.T) {
	a := newTestAgent(t, time.Hour)
	// Hard cap nearer than one IdleTTL: extend must clamp to it.
	a.hardDeadline = time.Now().Add(time.Second)
	a.extend()
	if a.expiresAt.After(a.hardDeadline) {
		t.Errorf("extend exceeded hard deadline: %v > %v", a.expiresAt, a.hardDeadline)
	}
}

func TestAgentValidSessionStatusDoesNotStop(t *testing.T) {
	a := newTestAgent(t, time.Hour)
	resp, stop := roundtrip(t, a, request{Op: "status"})
	if !resp.OK {
		t.Errorf("status returned error: %s", resp.Error)
	}
	if stop {
		t.Error("valid status should not stop the agent")
	}
	if resp.ExpiresAt == "" {
		t.Error("status should report expiry")
	}
}
