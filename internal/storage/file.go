// Package storage handles the on-disk encrypted envelope and all path handling
// for ~/.lockbox. It knows nothing about how the ciphertext was produced.
package storage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileVersion is the current on-disk format version written by New. Bump it if
// the layout or crypto parameters change in a backwards-incompatible way, and
// teach Decode to accept the older versions.
//
// v1: Argon2id time cost 1.  v2: time cost 3 (see crypto.Argon2Time). Only the
// KDF time cost differs, so a v1 vault is re-keyed to v2 on the next unlock.
const FileVersion = 2

// minSupportedVersion is the oldest on-disk format Decode can still read.
const minSupportedVersion = 1

// VaultFile is the encrypted on-disk JSON envelope. The plaintext vault is
// never written to disk; only Ciphertext (the encrypted vault JSON) is.
//
// Salt is fixed for the life of the vault: the session key is derived from
// (master password, salt), and the running agent holds only that derived key —
// not the password — so it cannot re-derive against a new salt. Each save
// therefore reuses Salt and generates a fresh Nonce.
type VaultFile struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`       // base64, Argon2id salt
	Nonce      string `json:"nonce"`      // base64, AES-GCM nonce
	Ciphertext string `json:"ciphertext"` // base64, AES-256-GCM(vault JSON)
}

// New builds an on-disk envelope from raw crypto material.
func New(salt, nonce, ciphertext []byte) *VaultFile {
	return &VaultFile{
		Version:    FileVersion,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
}

// Decode returns the raw salt, nonce, and ciphertext bytes from the envelope.
func (vf *VaultFile) Decode() (salt, nonce, ciphertext []byte, err error) {
	if vf.Version < minSupportedVersion || vf.Version > FileVersion {
		return nil, nil, nil, fmt.Errorf("unsupported vault version %d (supported %d–%d)", vf.Version, minSupportedVersion, FileVersion)
	}
	if salt, err = base64.StdEncoding.DecodeString(vf.Salt); err != nil {
		return nil, nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	if nonce, err = base64.StdEncoding.DecodeString(vf.Nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("decode nonce: %w", err)
	}
	if ciphertext, err = base64.StdEncoding.DecodeString(vf.Ciphertext); err != nil {
		return nil, nil, nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return salt, nonce, ciphertext, nil
}

// Dir returns ~/.lockbox.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".lockbox"), nil
}

// Path returns ~/.lockbox/store.vault.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "store.vault"), nil
}

// SocketPath returns ~/.lockbox/agent.sock.
func SocketPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent.sock"), nil
}

// Load reads and parses the on-disk envelope.
func Load() (*VaultFile, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no vault found at %s; run \"lockbox init\" first", path)
		}
		return nil, fmt.Errorf("read vault: %w", err)
	}
	var vf VaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("parse vault file: %w", err)
	}
	return &vf, nil
}

// Save writes the envelope atomically (temp file + rename) with owner-only
// permissions.
func Save(vf *VaultFile) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}

	data, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return fmt.Errorf("encode vault file: %w", err)
	}

	path, err := Path()
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "store.vault.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename succeeded

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close vault: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	return nil
}

// Exists reports whether a vault file is already present.
func Exists() (bool, error) {
	path, err := Path()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
