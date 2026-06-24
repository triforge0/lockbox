package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestGCMRoundTrip(t *testing.T) {
	salt, err := newSalt()
	if err != nil {
		t.Fatalf("newSalt: %v", err)
	}
	key := deriveKey("correct horse", salt)

	in := &Vault{Items: []Item{
		{Service: "github", Username: "octocat", Password: "gh-secret"},
		{Service: "aws", Username: "root", Password: "aws-secret"},
	}}
	plaintext, _ := json.Marshal(in)

	nonce, ciphertext, err := gcmEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("gcmEncrypt: %v", err)
	}

	got, err := gcmDecrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("gcmDecrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	salt, _ := newSalt()
	right := deriveKey("right", salt)
	wrong := deriveKey("wrong", salt)

	nonce, ciphertext, err := gcmEncrypt(right, []byte(`{"items":[]}`))
	if err != nil {
		t.Fatalf("gcmEncrypt: %v", err)
	}
	if _, err := gcmDecrypt(wrong, nonce, ciphertext); err != errWrongPassword {
		t.Fatalf("err = %v, want errWrongPassword", err)
	}
}

func TestCiphertextHasNoPlaintext(t *testing.T) {
	salt, _ := newSalt()
	key := deriveKey("pw", salt)
	secret := "super-secret-value"
	plaintext, _ := json.Marshal(&Vault{Items: []Item{
		{Service: "svc", Username: "user", Password: secret},
	}})

	_, ciphertext, err := gcmEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("gcmEncrypt: %v", err)
	}
	if bytes.Contains(ciphertext, []byte(secret)) || bytes.Contains(ciphertext, []byte("user")) {
		t.Fatal("plaintext leaked into ciphertext")
	}
}

func TestSaltFixedKeyStableNonceFresh(t *testing.T) {
	// With the session model the salt (hence key) is fixed; only the nonce
	// changes per save. Re-encrypting the same data must still differ.
	salt, _ := newSalt()
	key := deriveKey("pw", salt)
	data := []byte(`{"items":[{"service":"x"}]}`)

	n1, c1, err := gcmEncrypt(key, data)
	if err != nil {
		t.Fatalf("gcmEncrypt: %v", err)
	}
	n2, c2, err := gcmEncrypt(key, data)
	if err != nil {
		t.Fatalf("gcmEncrypt: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Error("nonce was reused across saves")
	}
	if bytes.Equal(c1, c2) {
		t.Error("ciphertext identical across saves")
	}
}

func TestVaultFileEnvelopeRoundTrip(t *testing.T) {
	salt, _ := newSalt()
	key := deriveKey("pw", salt)
	nonce, ciphertext, _ := gcmEncrypt(key, []byte(`{"items":[]}`))

	vf := newVaultFile(salt, nonce, ciphertext)
	if vf.Version != vaultFileVersion {
		t.Fatalf("version = %d, want %d", vf.Version, vaultFileVersion)
	}
	gotSalt, gotNonce, gotCipher, err := vf.decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(gotSalt, salt) || !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotCipher, ciphertext) {
		t.Fatal("envelope round trip mismatch")
	}
}

func TestVaultFindAndRemove(t *testing.T) {
	v := &Vault{Items: []Item{
		{Service: "a"}, {Service: "b"}, {Service: "c"},
	}}
	if v.find("b") == nil {
		t.Error("find(b) returned nil")
	}
	if v.find("missing") != nil {
		t.Error("find(missing) should be nil")
	}
	if !v.remove("b") {
		t.Error("remove(b) returned false")
	}
	if v.find("b") != nil {
		t.Error("b still present after remove")
	}
	if v.remove("b") {
		t.Error("remove(b) twice returned true")
	}
	if len(v.Items) != 2 {
		t.Errorf("len = %d, want 2", len(v.Items))
	}
}
