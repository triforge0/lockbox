// Package agent implements the in-memory session as a detached background
// daemon. The daemon holds the derived key in RAM (never on disk) and serves
// encrypt/decrypt requests over a Unix-domain socket; the data commands act as
// clients. This package is the home of all session/TTL logic.
package agent

import (
	"errors"
	"time"
)

// IdleTTL is how long a session survives without vault activity. Each
// encrypt/decrypt request slides this window forward, so an actively used
// session stays open while an abandoned one locks itself quickly — shrinking the
// window in which the in-memory key is exposed.
const IdleTTL = 15 * time.Minute

// MaxTTL is the absolute lifetime of a session regardless of activity.
const MaxTTL = 24 * time.Hour

// ErrNoSession indicates that no usable session is available, either because
// the agent is not running or because it has expired. Callers translate this
// into a "run lockbox unlock" message.
var ErrNoSession = errors.New("locked: run \"lockbox unlock\" first")

// request / response are the newline-delimited JSON messages exchanged over the
// agent socket. Payloads are base64-encoded raw bytes.
type request struct {
	Op         string `json:"op"`                   // ping | status | encrypt | decrypt | lock
	Plaintext  string `json:"plaintext,omitempty"`  // for encrypt
	Nonce      string `json:"nonce,omitempty"`      // for decrypt
	Ciphertext string `json:"ciphertext,omitempty"` // for decrypt
}

type response struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"` // RFC3339, for status
	Salt       string `json:"salt,omitempty"`       // for encrypt
	Nonce      string `json:"nonce,omitempty"`      // for encrypt
	Ciphertext string `json:"ciphertext,omitempty"` // for encrypt
	Plaintext  string `json:"plaintext,omitempty"`  // for decrypt
}

// handshake is what the parent writes to the agent's stdin at startup. It
// carries the derived key and the vault's fixed salt — over a pipe, never to
// disk and never via argv.
type handshake struct {
	Key  string `json:"key"`  // base64 derived key
	Salt string `json:"salt"` // base64 vault salt
}
