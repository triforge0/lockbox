package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// sessionTTL is how long an unlocked session stays valid.
const sessionTTL = 24 * time.Hour

// errNoSession indicates that no usable session is available, either because
// the agent is not running or because it has expired. Commands translate this
// into a "run lockbox unlock" message.
var errNoSession = errors.New("locked: run \"lockbox unlock\" first")

// agentRequest / agentResponse are the newline-delimited JSON messages
// exchanged over the agent socket. Payloads are base64-encoded raw bytes.
type agentRequest struct {
	Op         string `json:"op"`                   // ping | status | encrypt | decrypt | lock
	Plaintext  string `json:"plaintext,omitempty"`  // for encrypt
	Nonce      string `json:"nonce,omitempty"`      // for decrypt
	Ciphertext string `json:"ciphertext,omitempty"` // for decrypt
}

type agentResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"` // RFC3339, for status
	Salt       string `json:"salt,omitempty"`       // for encrypt
	Nonce      string `json:"nonce,omitempty"`      // for encrypt
	Ciphertext string `json:"ciphertext,omitempty"` // for encrypt
	Plaintext  string `json:"plaintext,omitempty"`  // for decrypt
}

// agentHandshake is what the parent writes to the agent's stdin at startup. It
// carries the derived key and the vault's fixed salt — over a pipe, never to
// disk and never via argv.
type agentHandshake struct {
	Key  string `json:"key"`  // base64 derived key
	Salt string `json:"salt"` // base64 vault salt
}

// socketPath returns ~/.lockbox/agent.sock.
func socketPath() (string, error) {
	dir, err := vaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent.sock"), nil
}

// -----------------------------------------------------------------------------
// Agent server (runs in the detached "__agent" process)
// -----------------------------------------------------------------------------

type agent struct {
	mu        sync.Mutex
	key       []byte
	salt      []byte
	expiresAt time.Time
	ln        net.Listener
}

// runAgent is the entry point for the detached agent process. It reads the key
// and salt from stdin, then serves crypto requests over the socket until it is
// locked or the session expires.
func runAgent() error {
	var hs agentHandshake
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

	sock, err := socketPath()
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
		expiresAt: time.Now().Add(sessionTTL),
		ln:        ln,
	}
	defer a.shutdown(sock)

	// Self-destruct when the session expires.
	expiryTimer := time.AfterFunc(sessionTTL, func() { ln.Close() })
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

	var req agentRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResponse(conn, agentResponse{OK: false, Error: "bad request"})
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if time.Now().After(a.expiresAt) {
		writeResponse(conn, agentResponse{OK: false, Error: errNoSession.Error()})
		return true // expired: shut down
	}

	switch req.Op {
	case "ping":
		writeResponse(conn, agentResponse{OK: true})
	case "status":
		writeResponse(conn, agentResponse{OK: true, ExpiresAt: a.expiresAt.UTC().Format(time.RFC3339)})
	case "lock":
		writeResponse(conn, agentResponse{OK: true})
		return true
	case "encrypt":
		plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			writeResponse(conn, agentResponse{OK: false, Error: "bad plaintext"})
			return false
		}
		nonce, ciphertext, err := gcmEncrypt(a.key, plaintext)
		if err != nil {
			writeResponse(conn, agentResponse{OK: false, Error: err.Error()})
			return false
		}
		writeResponse(conn, agentResponse{
			OK:         true,
			Salt:       base64.StdEncoding.EncodeToString(a.salt),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		})
	case "decrypt":
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			writeResponse(conn, agentResponse{OK: false, Error: "bad nonce"})
			return false
		}
		ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			writeResponse(conn, agentResponse{OK: false, Error: "bad ciphertext"})
			return false
		}
		plaintext, err := gcmDecrypt(a.key, nonce, ciphertext)
		if err != nil {
			writeResponse(conn, agentResponse{OK: false, Error: err.Error()})
			return false
		}
		writeResponse(conn, agentResponse{OK: true, Plaintext: base64.StdEncoding.EncodeToString(plaintext)})
	default:
		writeResponse(conn, agentResponse{OK: false, Error: "unknown op"})
	}
	return false
}

func writeResponse(conn net.Conn, resp agentResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}

// -----------------------------------------------------------------------------
// Agent client (used by unlock/lock and the data commands)
// -----------------------------------------------------------------------------

// agentCall connects to the agent and performs one request/response exchange.
// A failure to connect is reported as errNoSession.
func agentCall(req agentRequest) (*agentResponse, error) {
	sock, err := socketPath()
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, errNoSession
	}
	defer conn.Close()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, errNoSession
	}

	var resp agentResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return nil, errNoSession
	}
	if !resp.OK {
		if resp.Error == errNoSession.Error() {
			return nil, errNoSession
		}
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}

// agentAlive reports whether a live, unexpired agent is currently reachable.
func agentAlive() bool {
	_, err := agentCall(agentRequest{Op: "ping"})
	return err == nil
}

// agentDecrypt asks the agent to decrypt a vault envelope's payload.
func agentDecrypt(nonce, ciphertext []byte) ([]byte, error) {
	resp, err := agentCall(agentRequest{
		Op:         "decrypt",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// agentEncrypt asks the agent to encrypt plaintext, returning a ready-to-save
// envelope (the salt is the vault's fixed salt held by the agent).
func agentEncrypt(plaintext []byte) (*vaultFile, error) {
	resp, err := agentCall(agentRequest{
		Op:        "encrypt",
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(resp.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, err
	}
	return newVaultFile(salt, nonce, ciphertext), nil
}
