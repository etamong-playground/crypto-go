# crypto-go

> **About** — One of several shared libraries behind a personal homelab "fleet" of small apps (error handling · audit logging · encryption-at-rest · i18n · UI · …). Published to show the **design decisions** behind these cross-cutting concerns. It is authored and maintained with [Claude Code](https://www.anthropic.com/claude-code) (Anthropic's agentic CLI), not hand-written.
>
> **This is a public repository** — keep internal infrastructure details (hostnames, secret/Vault paths, private URLs, internal issue/MR references) out of code, comments, README, and commit messages.

Encryption-at-rest as a Go library: **XChaCha20-Poly1305 + KEK + per-row AAD**.

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

c, err := crypto.New(os.Getenv("APP_ENCRYPTION_KEY"))   // base64 32-byte KEK
if err != nil { return err }

nonce, ct, err := c.Seal([]byte(token), fmt.Sprintf("%s|%s", owner, credID))
// store (nonce, ct) in the DB

plain, err := c.Open(nonce, ct, fmt.Sprintf("%s|%s", owner, credID))
```

Provide the KEK as a base64 env var from your secret manager (e.g. `APP_ENCRYPTION_KEY`).
Rotate by issuing a new KEK and re-wrapping rows (see `crypto.Rewrap` below).

## Rotation

```go
nNonce, nCT, err := crypto.Rewrap(oldC, newC, nonce, ct, aad)
```

Decrypts under `oldC`, re-seals under `newC` with a fresh nonce. Run as a
batched migration job; KEK version lives in a sibling column on the row.

## Out of scope

- Hashing actors (`AnonID`) → that's in [`audit-go`](https://github.com/etamong-playground/audit-go).
- TLS / certificate handling.
- KEK lifecycle management — operator concern.

## Acknowledgements

Uses [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) (BSD-3-Clause).

## License

MIT — see [LICENSE](LICENSE).
