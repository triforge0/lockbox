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
