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
	"regexp"
	"sort"
	"strings"
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

// DefaultVault is the vault used when no --vault is given. It maps to the
// original store.vault/agent.sock names so existing single-vault installs keep
// working with no migration.
const DefaultVault = "default"

// vaultNamePattern restricts vault names to characters that are safe in a
// filename and a socket name, blocking path traversal (no "/", "..", etc.).
var vaultNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// reservedVaultNames would collide with the default vault's fixed filenames
// (store.vault / agent.sock), so they are not allowed as explicit names.
var reservedVaultNames = map[string]bool{"store": true, "agent": true}

// ValidVaultName reports whether name is usable as a vault name.
func ValidVaultName(name string) error {
	if name == DefaultVault {
		return nil
	}
	if !vaultNamePattern.MatchString(name) {
		return fmt.Errorf("invalid vault name %q: use letters, digits, '-' or '_'", name)
	}
	if reservedVaultNames[name] {
		return fmt.Errorf("vault name %q is reserved", name)
	}
	return nil
}

func vaultFileName(name string) string {
	if name == DefaultVault {
		return "store.vault"
	}
	return name + ".vault"
}

func socketFileName(name string) string {
	if name == DefaultVault {
		return "agent.sock"
	}
	return name + ".sock"
}

// Dir returns ~/.lockbox.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".lockbox"), nil
}

// Path returns the on-disk vault file for the named vault.
func Path(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, vaultFileName(name)), nil
}

// SocketPath returns the agent socket for the named vault.
func SocketPath(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, socketFileName(name)), nil
}

// ListVaults returns the names of all vaults present in ~/.lockbox, sorted.
func ListVaults() ([]string, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read vault dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".vault") {
			continue
		}
		if e.Name() == "store.vault" {
			names = append(names, DefaultVault)
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".vault"))
	}
	sort.Strings(names)
	return names, nil
}

// Load reads and parses the named vault's on-disk envelope.
func Load(name string) (*VaultFile, error) {
	path, err := Path(name)
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

// Save writes the named vault's envelope atomically (temp file + rename) with
// owner-only permissions.
func Save(name string, vf *VaultFile) error {
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

	path, err := Path(name)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, vaultFileName(name)+".tmp-*")
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

// Exists reports whether the named vault file is already present.
func Exists(name string) (bool, error) {
	path, err := Path(name)
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
