/**
 * Tests for metadata encryption (file name encryption/decryption).
 */

import { describe, expect, it } from "vitest";
import { toBase64 } from "./encoding.js";
import { decryptMetadata, deriveMetadataKey, encryptMetadata } from "./metadata.js";

// ---------------------------------------------------------------------------
// deriveMetadataKey
// ---------------------------------------------------------------------------

describe("deriveMetadataKey", () => {
  it("returns an AES-GCM CryptoKey", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect(key.usages).toContain("encrypt");
    expect(key.usages).toContain("decrypt");
  });

  it("is deterministic for the same MVK", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const keyA = await deriveMetadataKey(mvk);
    const keyB = await deriveMetadataKey(mvk);

    // Verify by encrypting with one key and decrypting with the other
    const { ciphertext, iv } = await encryptMetadata(keyA, "determinism-check");
    const decrypted = await decryptMetadata(keyB, ciphertext, iv);
    expect(decrypted).toBe("determinism-check");
  });

  it("produces different keys for different MVKs", async () => {
    const mvkA = crypto.getRandomValues(new Uint8Array(32));
    const mvkB = crypto.getRandomValues(new Uint8Array(32));
    const keyA = await deriveMetadataKey(mvkA);
    const keyB = await deriveMetadataKey(mvkB);

    // Encrypting with keyA should not be decryptable with keyB
    const { ciphertext, iv } = await encryptMetadata(keyA, "cross-key-test");
    await expect(decryptMetadata(keyB, ciphertext, iv)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// encryptMetadata / decryptMetadata
// ---------------------------------------------------------------------------

describe("encryptMetadata / decryptMetadata", () => {
  it("round-trips a file name", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const original = "my-important-document.pdf";
    const { ciphertext, iv } = await encryptMetadata(key, original);
    const decrypted = await decryptMetadata(key, ciphertext, iv);

    expect(decrypted).toBe(original);
  });

  it("round-trips unicode file names", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const original = "日本語ファイル名 — résumé (2024).docx";
    const { ciphertext, iv } = await encryptMetadata(key, original);
    const decrypted = await decryptMetadata(key, ciphertext, iv);

    expect(decrypted).toBe(original);
  });

  it("round-trips an empty string", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const { ciphertext, iv } = await encryptMetadata(key, "");
    const decrypted = await decryptMetadata(key, ciphertext, iv);

    expect(decrypted).toBe("");
  });

  it("produces valid base64 for ciphertext and iv", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const { ciphertext, iv } = await encryptMetadata(key, "test.txt");

    expect(ciphertext).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(iv).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  it("produces a 12-byte IV", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const { iv } = await encryptMetadata(key, "test.txt");
    const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));

    expect(ivBytes.length).toBe(12);
  });

  it("produces different ciphertext for the same plaintext (random IV)", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const a = await encryptMetadata(key, "same-name.pdf");
    const b = await encryptMetadata(key, "same-name.pdf");

    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.iv).not.toBe(b.iv);
  });

  it("fails to decrypt with a different key", async () => {
    const mvkA = crypto.getRandomValues(new Uint8Array(32));
    const mvkB = crypto.getRandomValues(new Uint8Array(32));
    const keyA = await deriveMetadataKey(mvkA);
    const keyB = await deriveMetadataKey(mvkB);

    const { ciphertext, iv } = await encryptMetadata(keyA, "secret.pdf");

    await expect(decryptMetadata(keyB, ciphertext, iv)).rejects.toThrow();
  });

  it("fails to decrypt with tampered ciphertext", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveMetadataKey(mvk);

    const { ciphertext, iv } = await encryptMetadata(key, "important.pdf");

    // Flip a byte in the ciphertext
    const bytes = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
    bytes[0] = (bytes[0] ?? 0) ^ 0xff;
    const tampered = toBase64(bytes);

    await expect(decryptMetadata(key, tampered, iv)).rejects.toThrow();
  });
});
