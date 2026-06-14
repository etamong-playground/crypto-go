// Package crypto implements the etamong-lab encryption standard for
// secret-at-rest fields: XChaCha20-Poly1305 with a Vault-issued KEK and
// per-row AAD.
//
// The library is opinionated:
//   - XChaCha20's 24-byte random nonce removes collision risk at fleet scale.
//   - AAD is mandatory — empty AAD is rejected so blobs can't be replayed
//     under a different identity.
//   - A nil/zero Crypter fails closed: every method returns ErrNoKey instead
//     of silently passing plaintext through.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrNoKey is returned when a Crypter was built from an empty key. Callers
	// should refuse to persist or read the protected field.
	ErrNoKey = errors.New("crypto-go: no KEK configured — encrypted storage disabled")
	// ErrEmptyAAD is returned when Seal/Open are called without an AAD. Per the
	// etamong-lab standard, AAD must bind the ciphertext to its row identity so
	// a stored blob can't be replayed under a different actor.
	ErrEmptyAAD = errors.New("crypto-go: AAD required")
	// ErrBadKey is returned when the KEK fails to decode to a 32-byte value.
	ErrBadKey = errors.New("crypto-go: KEK must decode to 32 bytes")
	// ErrBadKeyEncoding is returned when the KEK string is not valid base64.
	ErrBadKeyEncoding = errors.New("crypto-go: KEK must be base64-encoded")
)

// Crypter wraps an XChaCha20-Poly1305 AEAD with a 32-byte KEK. Build one at
// startup and share it; AEADs are safe for concurrent use.
type Crypter struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
}

// New parses a base64-encoded 32-byte KEK and returns a ready Crypter. An empty
// key yields (nil, nil) so callers can treat "no key configured" as a feature
// flag without panicking — every subsequent Seal/Open returns ErrNoKey.
func New(b64KEK string) (*Crypter, error) {
	if b64KEK == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(b64KEK)
	if err != nil {
		return nil, ErrBadKeyEncoding
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrBadKey
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Crypter{aead: aead}, nil
}

// Seal returns (nonce, ciphertext). aad must be non-empty: bind ciphertext to
// the row's stable identity (e.g. "owner|credID") so replay across rows fails
// authentication.
func (c *Crypter) Seal(plaintext []byte, aad string) (nonce, ct []byte, err error) {
	if c == nil {
		return nil, nil, ErrNoKey
	}
	if aad == "" {
		return nil, nil, ErrEmptyAAD
	}
	nonce = make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct = c.aead.Seal(nil, nonce, plaintext, []byte(aad))
	return nonce, ct, nil
}

// Open reverses Seal. A mismatched aad (or any byte tampering) fails
// authentication and returns an error.
func (c *Crypter) Open(nonce, ct []byte, aad string) ([]byte, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	if aad == "" {
		return nil, ErrEmptyAAD
	}
	return c.aead.Open(nil, nonce, ct, []byte(aad))
}

// Rewrap decrypts under old and re-seals under new with a fresh nonce. Used by
// per-row KEK rotation jobs; track the KEK version in a sibling column.
func Rewrap(old, new *Crypter, nonce, ct []byte, aad string) (newNonce, newCT []byte, err error) {
	plain, err := old.Open(nonce, ct, aad)
	if err != nil {
		return nil, nil, err
	}
	return new.Seal(plain, aad)
}
