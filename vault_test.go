package main

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	in := &Vault{Items: []Item{
		{Service: "github", Username: "octocat", Password: "gh-secret"},
		{Service: "aws", Username: "root", Password: "aws-secret"},
	}}

	vf, err := encryptVault(in, "correct horse")
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	out, err := decryptVault(vf, "correct horse")
	if err != nil {
		t.Fatalf("decryptVault: %v", err)
	}

	if len(out.Items) != len(in.Items) {
		t.Fatalf("item count = %d, want %d", len(out.Items), len(in.Items))
	}
	for i := range in.Items {
		if out.Items[i] != in.Items[i] {
			t.Errorf("item %d = %+v, want %+v", i, out.Items[i], in.Items[i])
		}
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	vf, err := encryptVault(&Vault{Items: []Item{{Service: "x"}}}, "right")
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	if _, err := decryptVault(vf, "wrong"); err != errWrongPassword {
		t.Fatalf("err = %v, want errWrongPassword", err)
	}
}

func TestCiphertextHasNoPlaintext(t *testing.T) {
	secret := "super-secret-value"
	vf, err := encryptVault(&Vault{Items: []Item{
		{Service: "svc", Username: "user", Password: secret},
	}}, "pw")
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	if strings.Contains(vf.Ciphertext, secret) || strings.Contains(vf.Ciphertext, "user") {
		t.Fatal("plaintext leaked into ciphertext field")
	}
}

func TestEncryptUsesFreshSaltAndNonce(t *testing.T) {
	v := &Vault{Items: []Item{{Service: "x"}}}
	a, err := encryptVault(v, "pw")
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	b, err := encryptVault(v, "pw")
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	if a.Salt == b.Salt {
		t.Error("salt was reused across saves")
	}
	if a.Nonce == b.Nonce {
		t.Error("nonce was reused across saves")
	}
	if a.Ciphertext == b.Ciphertext {
		t.Error("ciphertext identical across saves")
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
