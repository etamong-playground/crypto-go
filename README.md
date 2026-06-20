> Canonical: https://github.com/etamong-playground/crypto-go

# @etamong-lab/crypto-go

The etamong-lab encryption standard ([[etamong_encryption_standard]]) as a Go
library: **XChaCha20-Poly1305 + Vault KEK + per-row AAD**. Same primitives the
reference impl in `pages/apiserver/crypto.go` ships today.

Three guarantees the library enforces by construction:

- 24-byte random nonce per seal (XChaCha20) — no collision risk under many secrets,
  unlike a 96-bit nonce.
- **AAD required**. `Seal` and `Open` reject `""` AAD with `ErrEmptyAAD`. Callers
  must bind ciphertext to its row (`fmt.Sprintf("%s|%s", owner, credID)`).
- **Fail closed.** A `*Crypter` constructed from an empty/missing key returns
  `ErrNoKey` from every method; never silently passes through plaintext.

## Install

```sh
go get github.com/etamong-playground/crypto-go
```

## Use

```go
import "github.com/etamong-playground/crypto-go/crypto"

c, err := crypto.New(os.Getenv("PAGES_ENCRYPTION_KEY"))   // base64 32-byte KEK
if err != nil { return err }

nonce, ct, err := c.Seal([]byte(token), fmt.Sprintf("%s|%s", owner, credID))
// store (nonce, ct) in the DB

plain, err := c.Open(nonce, ct, fmt.Sprintf("%s|%s", owner, credID))
```

Wiring inside cluster apps: KEK comes from Vault (`homelab/apps/<app>/encryption`,
`key=<base64>`); `vault-secrets-operator` projects it as an env var named
`<APP>_ENCRYPTION_KEY`. Rotate by issuing a new KEK and re-wrapping rows
(`crypto.Rewrap(old, new, nonce, ct, aad)` — see below).

## Rotation

```go
nNonce, nCT, err := crypto.Rewrap(oldC, newC, nonce, ct, aad)
```

Decrypts under `oldC`, re-seals under `newC` with a fresh nonce. Run as a
batched migration job; KEK version lives in a sibling column on the row.

## Out of scope

- Hashing actors (`AnonID`) → that's in [`audit-go`](https://github.com/etamong-playground/audit-go).
- TLS / certificate handling.
- KEK lifecycle in Vault — operator concern.

Relates to etamong-lab/planning#244 #248.
