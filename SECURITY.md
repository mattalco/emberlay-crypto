# Security Policy

## Threat model

This library implements the client-side cryptographic operations for [Emberlay](https://emberlay.com), a zero-knowledge digital legacy vault. The threat model assumes:

- **The server is untrusted.** It stores only ciphertext and encrypted metadata. A full server compromise (database dump, R2 object access) yields nothing decryptable.
- **The attacker does not have the user's passphrase or Printable Legacy Key (PLK).** If they do, the encryption is moot — that's the key.
- **The browser environment is trusted.** A compromised browser (malicious extension, XSS) can exfiltrate keys from memory. This library does not defend against that — it's the application's responsibility to prevent XSS.

### What this library protects against

- Server-side data breaches (encrypted blobs are useless without the MVK)
- Offline brute-force attacks on the passphrase (Argon2id at 128 MiB makes this expensive)
- Timing side-channels on key comparison (constant-time comparison)
- File tampering detection (AES-GCM authentication tags)
- Cross-file key compromise (per-file HKDF derivation — one file's key doesn't reveal another's)
- Metadata leakage (file names encrypted with a separate derived key)

### What this library does NOT protect against

- Compromised client environment (malicious browser extensions, XSS)
- Passphrase/PLK theft via social engineering or physical access
- Side-channel attacks on the Argon2id computation itself (timing, power analysis)
- Quantum computing (AES-256 is believed to retain 128-bit security under Grover's algorithm)

## Reporting vulnerabilities

If you discover a security vulnerability in this library, please report it responsibly:

**Email:** security@emberlay.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide a timeline for a fix. We will not take legal action against researchers who report vulnerabilities responsibly.

## Algorithms and parameters

| Operation | Algorithm | Key size | Notes |
|-----------|-----------|----------|-------|
| Passphrase → PDK | Argon2id | 256-bit output | 128 MiB memory, 3 iterations, parallelism 1 |
| MVK encryption | AES-256-GCM | 256-bit | 12-byte random IV, 16-byte auth tag |
| Per-file key derivation | HKDF-SHA256 | 256-bit output | info = fileId (UUID), zero salt (IKM is full-entropy) |
| File encryption | AES-256-GCM | 256-bit | 4 MB chunks, IV = baseIV ⊕ chunkIndex |
| Metadata encryption | AES-256-GCM | 256-bit | Separate HKDF key (info = "emberlay-metadata-v1") |
| Constant-time compare | Bitwise OR accumulator | — | Iterates full length regardless of mismatch position |

## IV/nonce management

- **MVK encryption:** Fresh 12-byte random IV per encryption. The MVK is re-encrypted only on passphrase change (infrequent), so IV reuse probability is negligible.
- **File encryption:** Fresh 12-byte random base IV per file. Chunk IVs are derived by XORing the last 4 bytes with the chunk index. With 2³² possible chunks per file and a random base, collision probability within a single file is zero.
- **Metadata encryption:** Fresh 12-byte random IV per file name encryption. Each encrypt call generates a new IV.

## Dependencies

This library has exactly one external cryptographic dependency:

- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (Argon2id only) — zero transitive dependencies, audited by Cure53, widely used in the JavaScript ecosystem.

All other cryptographic operations use the Web Crypto API (`crypto.subtle`), which is implemented natively by the browser or runtime (not in JavaScript).
