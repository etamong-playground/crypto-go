package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func keyB64(t *testing.T) string {
	t.Helper()
	k := make([]byte, chacha20poly1305.KeySize)
	for i := range k {
		k[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestNew_Empty(t *testing.T) {
	c, err := New("")
	if err != nil || c != nil {
		t.Fatalf("New(\"\") = %v, %v; want nil, nil", c, err)
	}
}

func TestNew_BadEncoding(t *testing.T) {
	if _, err := New("not base64 @@"); !errors.Is(err, ErrBadKeyEncoding) {
		t.Fatalf("got %v, want ErrBadKeyEncoding", err)
	}
}

func TestNew_BadLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if _, err := New(short); !errors.Is(err, ErrBadKey) {
		t.Fatalf("got %v, want ErrBadKey", err)
	}
}

func TestSealOpen_Roundtrip(t *testing.T) {
	c, err := New(keyB64(t))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hunter2")
	aad := "owner|cred-1"
	nonce, ct, err := c.Seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 24 {
		t.Errorf("nonce size %d, want 24", len(nonce))
	}
	got, err := c.Open(nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("roundtrip mismatch: %s vs %s", got, plain)
	}
}

func TestSeal_EmptyAADRejected(t *testing.T) {
	c, _ := New(keyB64(t))
	if _, _, err := c.Seal([]byte("x"), ""); !errors.Is(err, ErrEmptyAAD) {
		t.Fatalf("got %v, want ErrEmptyAAD", err)
	}
}

func TestOpen_EmptyAADRejected(t *testing.T) {
	c, _ := New(keyB64(t))
	nonce, ct, _ := c.Seal([]byte("x"), "row")
	if _, err := c.Open(nonce, ct, ""); !errors.Is(err, ErrEmptyAAD) {
		t.Fatalf("got %v, want ErrEmptyAAD", err)
	}
}

func TestOpen_WrongAAD(t *testing.T) {
	c, _ := New(keyB64(t))
	nonce, ct, _ := c.Seal([]byte("hunter2"), "row-A")
	if _, err := c.Open(nonce, ct, "row-B"); err == nil {
		t.Fatal("wrong AAD should fail authentication")
	}
}

func TestNilCrypter_FailsClosed(t *testing.T) {
	var c *Crypter
	if _, _, err := c.Seal([]byte("x"), "row"); !errors.Is(err, ErrNoKey) {
		t.Errorf("Seal nil: got %v, want ErrNoKey", err)
	}
	if _, err := c.Open([]byte("n"), []byte("c"), "row"); !errors.Is(err, ErrNoKey) {
		t.Errorf("Open nil: got %v, want ErrNoKey", err)
	}
}

func TestRewrap(t *testing.T) {
	oldKey := keyB64(t)
	newRaw := make([]byte, chacha20poly1305.KeySize)
	for i := range newRaw {
		newRaw[i] = byte(0xff - i)
	}
	newKey := base64.StdEncoding.EncodeToString(newRaw)

	oldC, _ := New(oldKey)
	newC, _ := New(newKey)
	nonce, ct, _ := oldC.Seal([]byte("hunter2"), "row")

	nNonce, nCT, err := Rewrap(oldC, newC, nonce, ct, "row")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nNonce, nonce) || bytes.Equal(nCT, ct) {
		t.Error("rewrap should change ciphertext")
	}
	got, err := newC.Open(nNonce, nCT, "row")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hunter2")) {
		t.Errorf("rewrap roundtrip: %s", got)
	}
	// Old crypter should NOT decrypt the rewrapped blob.
	if _, err := oldC.Open(nNonce, nCT, "row"); err == nil {
		t.Error("old crypter should fail on rewrapped blob")
	}
}
