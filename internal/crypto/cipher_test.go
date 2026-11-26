package crypto

import (
	"bytes"
	"testing"
)

func newCipher(t *testing.T) *Cipher {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestSealOpenRoundTrip(t *testing.T) {
	c := newCipher(t)
	plain := []byte("sk_live_example")
	aad := AAD("team/stripe", 3)

	nonce, ciphertext, err := c.Seal(plain, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ciphertext, plain) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := c.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, want %q", got, plain)
	}
}

func TestOpenRejectsForeignAAD(t *testing.T) {
	c := newCipher(t)
	nonce, ciphertext, err := c.Seal([]byte("value"), AAD("team/a", 1))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := c.Open(nonce, ciphertext, AAD("team/b", 1)); err == nil {
		t.Fatal("expected failure when the name binding changes")
	}
	if _, err := c.Open(nonce, ciphertext, AAD("team/a", 2)); err == nil {
		t.Fatal("expected failure when the version binding changes")
	}
}

func TestNonceIsUnique(t *testing.T) {
	c := newCipher(t)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		nonce, _, err := c.Seal([]byte("v"), nil)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		key := string(nonce)
		if seen[key] {
			t.Fatal("nonce reused")
		}
		seen[key] = true
	}
}

func TestKeyParsing(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := ParseKey(FormatKey(key)); err != nil {
		t.Errorf("hex round trip: %v", err)
	}
	if _, err := ParseKey("too-short"); err == nil {
		t.Error("short key must be rejected")
	}
	if _, err := New(make([]byte, 16)); err == nil {
		t.Error("16-byte key must be rejected")
	}
}
