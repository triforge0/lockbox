package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lockbox/internal/crypto"
	"lockbox/internal/storage"
)

// agent is the in-memory session state held by the detached daemon process.
type agent struct {
	mu        sync.Mutex
	key       []byte
	salt      []byte
	expiresAt time.Time
}

// Run is the entry point for the detached agent process (the hidden "__agent"
// subcommand). It reads the key and salt from stdin, then serves crypto
// requests over the socket until it is locked or the session expires.
func Run() error {
	var hs handshake
	if err := json.NewDecoder(os.Stdin).Decode(&hs); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(hs.Key)
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(hs.Salt)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}

	sock, err := storage.SocketPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		return err
	}
	// Clear any stale socket left by a previous agent that exited uncleanly.
	os.Remove(sock)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// Best effort on platforms with POSIX permissions; a no-op on Windows.
	os.Chmod(sock, 0o600)

	a := &agent{
		key:       key,
		salt:      salt,
		expiresAt: time.Now().Add(SessionTTL),
	}
	defer a.shutdown(sock)

	// Self-destruct when the session expires.
	expiryTimer := time.AfterFunc(SessionTTL, func() { ln.Close() })
	defer expiryTimer.Stop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // listener closed (lock or expiry): clean exit
		}
		if stop := a.handle(conn); stop {
			return nil
		}
	}
}

// shutdown wipes key material and removes the socket file.
func (a *agent) shutdown(sock string) {
	a.mu.Lock()
	for i := range a.key {
		a.key[i] = 0
	}
	a.mu.Unlock()
	os.Remove(sock)
}

// handle processes a single request. It returns true if the agent should stop
// (because of an explicit lock or an expired session).
func (a *agent) handle(conn net.Conn) (stop bool) {
	defer conn.Close()

	var req request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResponse(conn, response{OK: false, Error: "bad request"})
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if time.Now().After(a.expiresAt) {
		writeResponse(conn, response{OK: false, Error: ErrNoSession.Error()})
		return true // expired: shut down
	}

	switch req.Op {
	case "ping":
		writeResponse(conn, response{OK: true})
	case "status":
		writeResponse(conn, response{OK: true, ExpiresAt: a.expiresAt.UTC().Format(time.RFC3339)})
	case "lock":
		writeResponse(conn, response{OK: true})
		return true
	case "encrypt":
		plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			writeResponse(conn, response{OK: false, Error: "bad plaintext"})
			return false
		}
		nonce, ciphertext, err := crypto.Encrypt(a.key, plaintext)
		if err != nil {
			writeResponse(conn, response{OK: false, Error: err.Error()})
			return false
		}
		writeResponse(conn, response{
			OK:         true,
			Salt:       base64.StdEncoding.EncodeToString(a.salt),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		})
	case "decrypt":
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			writeResponse(conn, response{OK: false, Error: "bad nonce"})
			return false
		}
		ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			writeResponse(conn, response{OK: false, Error: "bad ciphertext"})
			return false
		}
		plaintext, err := crypto.Decrypt(a.key, nonce, ciphertext)
		if err != nil {
			writeResponse(conn, response{OK: false, Error: err.Error()})
			return false
		}
		writeResponse(conn, response{OK: true, Plaintext: base64.StdEncoding.EncodeToString(plaintext)})
	default:
		writeResponse(conn, response{OK: false, Error: "unknown op"})
	}
	return false
}

func writeResponse(conn net.Conn, resp response) {
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}
