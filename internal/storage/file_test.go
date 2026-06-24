package storage

import (
	"bytes"
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
	vf := &VaultFile{Version: FileVersion + 1}
	if _, _, _, err := vf.Decode(); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}
