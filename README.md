# @emberlay/crypto

Zero-knowledge encryption library powering [Emberlay](https://emberlay.com) — a digital legacy vault where files are encrypted on the client before upload. The server never sees plaintext data or encryption keys.

This is the exact cryptographic code running in production at Emberlay. We publish it so security researchers, users, and anyone curious can verify our claims.

## Architecture

```
Passphrase (≥12 chars)
    │
    ▼ Argon2id (128 MiB, 3 iterations)
    │
    PDK (Passphrase-Derived Key, 32 bytes)
    │
    ▼ AES-256-GCM encrypt
    │
    EMVK (Encrypted Master Vault Key — stored server-side)
    │
    ▼ AES-256-GCM decrypt (client-side only)
    │
    MVK (Master Vault Key, 32 bytes)
    ├──▶ HKDF(SHA-256, info=fileId) → per-file AES-256-GCM key
    └──▶ HKDF(SHA-256, info="emberlay-metadata-v1") → metadata key (file names)
```

### Key points

- **MVK** is generated client-side using `crypto.getRandomValues(new Uint8Array(32))` — 256 bits from the browser's CSPRNG.
- **Per-file keys** are derived deterministically from the MVK via HKDF, so they don't need to be stored.
- **File encryption** uses AES-256-GCM with 4 MB chunking. Each chunk gets a unique IV (base IV XORed with chunk index).
- **Metadata encryption** (file names) uses a separate HKDF-derived key with a distinct `info` parameter, providing cryptographic isolation from file content keys.
- **The server stores only ciphertext.** It cannot decrypt files, file names, or derive any keys.

## Modules

| File | Purpose |
|------|---------|
| `keys.ts` | Argon2id key derivation, MVK encrypt/decrypt, per-file key derivation (HKDF) |
| `files.ts` | AES-256-GCM file encryption/decryption with 4 MB chunking |
| `metadata.ts` | AES-256-GCM metadata (file name) encryption/decryption |
| `encoding.ts` | Base64 and hex encoding utilities |
| `compare.ts` | Constant-time byte array comparison |
| `client.ts` | Promise-based Web Worker client for off-main-thread crypto |
| `worker.ts` | Web Worker message handler (pairs with `client.ts`) |
| `types.ts` | TypeScript types for the worker message protocol |

## Dependencies

- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — Argon2id implementation. Zero transitive dependencies, widely audited.
- **Web Crypto API** (`crypto.subtle`) — All AES-256-GCM, HKDF, and random number generation. Built into every modern browser and Cloudflare Workers.

That's it. No other cryptographic dependencies.

## Running tests

```bash
npm install
npm test
```

Tests cover:
- Key derivation determinism and parameter sensitivity
- MVK encrypt/decrypt round-trips
- File encrypt/decrypt round-trips (including multi-chunk files)
- Metadata encrypt/decrypt round-trips (ASCII, unicode, empty strings)
- Tamper detection (GCM authentication tag verification)
- Wrong-key rejection
- Constant-time comparison correctness
- IV uniqueness (no two encryptions of the same plaintext produce the same ciphertext)

## Design decisions

**Why Argon2id at 128 MiB?**
Argon2id is memory-hard, making GPU-based brute force expensive. 128 MiB is above OWASP's minimum recommendation and makes each guess attempt cost ~128 MiB of RAM on the attacker's hardware.

**Why HKDF with a zero salt for file keys?**
The MVK is already 256 bits of CSPRNG output — uniformly random and full-entropy. HKDF's salt adds value when the input key material is weak or non-uniform. With a strong IKM, the zero salt is equivalent to any other salt per RFC 5869. The `info` parameter (fileId) is what provides key separation.

**Why chunked encryption?**
4 MB chunks allow streaming decryption of large files without loading the entire plaintext into memory. The XOR'd IV scheme (base IV ⊕ chunk index) ensures each chunk has a unique nonce without requiring additional random generation per chunk.

**Why a separate metadata key?**
Key separation via distinct HKDF `info` parameters means compromising the metadata key doesn't compromise file content keys. The metadata key is derived once per session and reused for all file name operations.

## License

MIT

## Links

- [Emberlay](https://emberlay.com) — The product this powers
- [Security page](https://emberlay.com/security) — How Emberlay protects your data
- [Security whitepaper](https://emberlay.com/security/whitepaper) — Full technical breakdown
