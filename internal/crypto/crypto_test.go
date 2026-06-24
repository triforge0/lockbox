package crypto

import (
	"bytes"
	"testing"
)

func TestGCMRoundTrip(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	key := DeriveKey("correct horse", salt)
	msg := []byte(`{"items":[{"service":"github","username":"octocat","password":"gh"}]}`)

	nonce, ciphertext, err := Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round trip mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	salt, _ := NewSalt()
	right := DeriveKey("right", salt)
	wrong := DeriveKey("wrong", salt)

	nonce, ciphertext, err := Encrypt(right, []byte(`{"items":[]}`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(wrong, nonce, ciphertext); err != ErrWrongPassword {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}
}

func TestCiphertextHasNoPlaintext(t *testing.T) {
	salt, _ := NewSalt()
	key := DeriveKey("pw", salt)
	secret := "super-secret-value"

	_, ciphertext, err := Encrypt(key, []byte(`{"p":"`+secret+`","u":"user"}`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ciphertext, []byte(secret)) || bytes.Contains(ciphertext, []byte("user")) {
		t.Fatal("plaintext leaked into ciphertext")
	}
}

func TestFreshNoncePerEncrypt(t *testing.T) {
	// With the session model the salt (hence key) is fixed; only the nonce
	// changes per save. Re-encrypting the same data must still differ.
	salt, _ := NewSalt()
	key := DeriveKey("pw", salt)
	data := []byte(`{"items":[{"service":"x"}]}`)

	n1, c1, err := Encrypt(key, data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	n2, c2, err := Encrypt(key, data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Error("nonce was reused across saves")
	}
	if bytes.Equal(c1, c2) {
		t.Error("ciphertext identical across saves")
	}
}
