package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"time"

	"lockbox/internal/storage"
)

// call connects to the named vault's agent and performs one request/response
// exchange. A failure to connect is reported as ErrNoSession.
func call(name string, req request) (*response, error) {
	sock, err := storage.SocketPath(name)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, ErrNoSession
	}
	defer conn.Close()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, ErrNoSession
	}

	var resp response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return nil, ErrNoSession
	}
	if !resp.OK {
		if resp.Error == ErrNoSession.Error() {
			return nil, ErrNoSession
		}
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}

// Alive reports whether a live, unexpired agent for the named vault is reachable.
func Alive(name string) bool {
	_, err := call(name, request{Op: "ping"})
	return err == nil
}

// Lock asks the named vault's agent to clear its session and exit. It is a
// no-op (nil) if no agent is running.
func Lock(name string) error {
	if !Alive(name) {
		return nil
	}
	_, err := call(name, request{Op: "lock"})
	return err
}

// Status returns the named vault session's expiry as an RFC3339 string.
func Status(name string) (expiresAt string, err error) {
	resp, err := call(name, request{Op: "status"})
	if err != nil {
		return "", err
	}
	return resp.ExpiresAt, nil
}

// Decrypt asks the named vault's agent to decrypt an envelope's payload.
func Decrypt(name string, nonce, ciphertext []byte) ([]byte, error) {
	resp, err := call(name, request{
		Op:         "decrypt",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// Encrypt asks the named vault's agent to encrypt plaintext, returning the raw
// salt (the vault's fixed salt held by the agent), nonce, and ciphertext.
func Encrypt(name string, plaintext []byte) (salt, nonce, ciphertext []byte, err error) {
	resp, err := call(name, request{
		Op:        "encrypt",
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if salt, err = base64.StdEncoding.DecodeString(resp.Salt); err != nil {
		return nil, nil, nil, err
	}
	if nonce, err = base64.StdEncoding.DecodeString(resp.Nonce); err != nil {
		return nil, nil, nil, err
	}
	if ciphertext, err = base64.StdEncoding.DecodeString(resp.Ciphertext); err != nil {
		return nil, nil, nil, err
	}
	return salt, nonce, ciphertext, nil
}
