package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// vaultFileVersion is the on-disk format version. Bump it if the layout or
// crypto parameters change in a backwards-incompatible way.
const vaultFileVersion = 1

// Argon2id key-derivation parameters. These are fixed for v1 so that a vault
// written on one machine can always be reopened on another.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	keyLen       = 32 // AES-256
	saltLen      = 16
)

// Item is a single stored credential.
type Item struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Vault is the decrypted, in-memory representation of the store.
type Vault struct {
	Items []Item `json:"items"`
}

// vaultFile is the encrypted on-disk JSON envelope. The plaintext Vault is
// never written to disk; only Ciphertext (the encrypted Vault JSON) is.
type vaultFile struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`       // base64, Argon2id salt
	Nonce      string `json:"nonce"`      // base64, AES-GCM nonce
	Ciphertext string `json:"ciphertext"` // base64, AES-256-GCM(vault JSON)
}

// find returns a pointer to the item matching service (case-insensitive on the
// exact string), or nil if not present.
func (v *Vault) find(service string) *Item {
	for i := range v.Items {
		if v.Items[i].Service == service {
			return &v.Items[i]
		}
	}
	return nil
}

// remove deletes the item for service and reports whether anything was removed.
func (v *Vault) remove(service string) bool {
	for i := range v.Items {
		if v.Items[i].Service == service {
			v.Items = append(v.Items[:i], v.Items[i+1:]...)
			return true
		}
	}
	return false
}

// deriveKey turns a master password + salt into a 32-byte AES key via Argon2id.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

// encryptVault serializes v, encrypts it with a freshly generated salt and
// nonce, and returns the on-disk envelope. A new salt is generated on every
// save so each write produces independent ciphertext.
func encryptVault(v *Vault, password string) (*vaultFile, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal vault: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &vaultFile{
		Version:    vaultFileVersion,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// errWrongPassword is returned when GCM authentication fails, which for a
// well-formed vault almost always means the master password was wrong.
var errWrongPassword = errors.New("incorrect master password or corrupted vault")

// decryptVault reverses encryptVault, returning the in-memory Vault.
func decryptVault(vf *vaultFile, password string) (*Vault, error) {
	if vf.Version != vaultFileVersion {
		return nil, fmt.Errorf("unsupported vault version %d (expected %d)", vf.Version, vaultFileVersion)
	}

	salt, err := base64.StdEncoding.DecodeString(vf.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(vf.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(vf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errWrongPassword
	}

	var v Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("parse decrypted vault: %w", err)
	}
	return &v, nil
}

// vaultDir returns ~/.lockbox.
func vaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".lockbox"), nil
}

// vaultPath returns ~/.lockbox/store.vault.
func vaultPath() (string, error) {
	dir, err := vaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "store.vault"), nil
}

// loadVaultFile reads and parses the on-disk envelope.
func loadVaultFile() (*vaultFile, error) {
	path, err := vaultPath()
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
	var vf vaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("parse vault file: %w", err)
	}
	return &vf, nil
}

// saveVaultFile writes the envelope atomically (temp file + rename) with
// owner-only permissions.
func saveVaultFile(vf *vaultFile) error {
	dir, err := vaultDir()
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

	path, err := vaultPath()
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

// vaultExists reports whether a vault file is already present.
func vaultExists() (bool, error) {
	path, err := vaultPath()
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
