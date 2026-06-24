package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestVaultFileEnvelopeRoundTrip(t *testing.T) {
	salt := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	ciphertext := []byte("some-ciphertext-bytes")

	vf := New(salt, nonce, ciphertext)
	if vf.Version != FileVersion {
		t.Fatalf("version = %d, want %d", vf.Version, FileVersion)
	}

	gotSalt, gotNonce, gotCipher, err := vf.Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(gotSalt, salt) || !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotCipher, ciphertext) {
		t.Fatal("envelope round trip mismatch")
	}
}

func TestDecodeRejectsWrongVersion(t *testing.T) {
	for _, v := range []int{0, FileVersion + 1} {
		vf := &VaultFile{Version: v}
		if _, _, _, err := vf.Decode(); err == nil {
			t.Fatalf("version %d: expected error for unsupported version", v)
		}
	}
}

// TestDecodeAcceptsLegacyVersion guards backward compatibility: a v1 envelope
// must still decode so existing vaults can be opened (and upgraded on unlock).
func TestDecodeAcceptsLegacyVersion(t *testing.T) {
	vf := New([]byte("0123456789abcdef"), []byte("0123456789ab"), []byte("ct"))
	vf.Version = 1
	if _, _, _, err := vf.Decode(); err != nil {
		t.Fatalf("v1 envelope must still decode: %v", err)
	}
}

// writeFiles creates dir and an empty file for each name under it.
func writeFiles(t *testing.T, dir string, names ...string) error {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func TestValidVaultName(t *testing.T) {
	ok := []string{"default", "work", "personal", "my-vault", "v2_team"}
	for _, n := range ok {
		if err := ValidVaultName(n); err != nil {
			t.Errorf("ValidVaultName(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{"", "../escape", "a/b", "with space", "dot.name", "store", "agent"}
	for _, n := range bad {
		if err := ValidVaultName(n); err == nil {
			t.Errorf("ValidVaultName(%q) = nil, want error", n)
		}
	}
}

// TestDefaultVaultKeepsLegacyFilenames pins the zero-migration guarantee: the
// default vault must still map to store.vault / agent.sock.
func TestDefaultVaultKeepsLegacyFilenames(t *testing.T) {
	vp, err := Path(DefaultVault)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got := filepath.Base(vp); got != "store.vault" {
		t.Errorf("default vault file = %q, want store.vault", got)
	}
	sp, err := SocketPath(DefaultVault)
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if got := filepath.Base(sp); got != "agent.sock" {
		t.Errorf("default socket = %q, want agent.sock", got)
	}

	wp, _ := Path("work")
	if got := filepath.Base(wp); got != "work.vault" {
		t.Errorf("named vault file = %q, want work.vault", got)
	}
	wsp, _ := SocketPath("work")
	if got := filepath.Base(wsp); got != "work.sock" {
		t.Errorf("named socket = %q, want work.sock", got)
	}
}

func TestListVaults(t *testing.T) {
	home := t.TempDir()
	// os.UserHomeDir (used by Dir) reads HOME on Unix but USERPROFILE on
	// Windows, so set both to redirect it to the temp dir on every platform.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".lockbox")
	if err := writeFiles(t, dir, "store.vault", "work.vault", "personal.vault", "notes.txt"); err != nil {
		t.Fatal(err)
	}
	got, err := ListVaults()
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	want := []string{"default", "personal", "work"} // sorted; store.vault -> default; .txt ignored
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListVaults() = %v, want %v", got, want)
	}
}
