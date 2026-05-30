/**
 * Tests for key derivation and MVK encryption/decryption.
 */

import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { fromBase64, toBase64 } from "./encoding.js";
import {
  DEFAULT_ARGON2_PARAMS,
  decryptMVK,
  deriveFileKey,
  deriveKey,
  encryptMVK,
  LEGACY_ARGON2_PARAMS,
} from "./keys.js";

// ---------------------------------------------------------------------------
// deriveKey (Argon2id)
// ---------------------------------------------------------------------------

describe("deriveKey", () => {
  it("returns a 32-byte Uint8Array", { timeout: 30_000 }, () => {
    const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const pdk = deriveKey("test-passphrase", salt);
    expect(pdk).toBeInstanceOf(Uint8Array);
    expect(pdk.length).toBe(32);
  });

  it("is deterministic for the same passphrase and salt", { timeout: 30_000 }, () => {
    const salt = toBase64(new Uint8Array(16)); // all zeros
    const a = deriveKey("hello", salt);
    const b = deriveKey("hello", salt);
    expect(a).toEqual(b);
  });

  it("produces different keys for different passphrases", { timeout: 30_000 }, () => {
    const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const a = deriveKey("passphrase-one", salt);
    const b = deriveKey("passphrase-two", salt);
    expect(a).not.toEqual(b);
  });

  it("produces different keys for different salts", { timeout: 30_000 }, () => {
    const saltA = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const saltB = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const a = deriveKey("same-passphrase", saltA);
    const b = deriveKey("same-passphrase", saltB);
    expect(a).not.toEqual(b);
  });

  it("produces different keys for the same passphrase under different params", {
    timeout: 60_000,
  }, () => {
    const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const a = deriveKey("same-passphrase", salt, LEGACY_ARGON2_PARAMS);
    const b = deriveKey("same-passphrase", salt, DEFAULT_ARGON2_PARAMS);
    expect(a).not.toEqual(b);
  });

  it("round-trips the same key when called twice with the same legacy params", {
    timeout: 60_000,
  }, () => {
    const salt = toBase64(new Uint8Array(16));
    const a = deriveKey("hello", salt, LEGACY_ARGON2_PARAMS);
    const b = deriveKey("hello", salt, LEGACY_ARGON2_PARAMS);
    expect(a).toEqual(b);
  });
});
// ---------------------------------------------------------------------------
// encryptMVK / decryptMVK
// ---------------------------------------------------------------------------

describe("encryptMVK / decryptMVK", () => {
  it("round-trips a 32-byte MVK", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const pdk = crypto.getRandomValues(new Uint8Array(32));

    const { ciphertext, iv } = await encryptMVK(mvk, pdk);
    const decrypted = await decryptMVK(ciphertext, iv, pdk);

    expect(decrypted).toEqual(mvk);
  });

  it("ciphertext and iv are valid base64", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const pdk = crypto.getRandomValues(new Uint8Array(32));

    const { ciphertext, iv } = await encryptMVK(mvk, pdk);

    expect(ciphertext).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(iv).toMatch(/^[A-Za-z0-9+/=]+$/);
    // IV should decode to 12 bytes (AES-GCM nonce)
    expect(fromBase64(iv).length).toBe(12);
  });

  it("throws WRONG_PASSPHRASE with incorrect PDK", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const correctPdk = crypto.getRandomValues(new Uint8Array(32));
    const wrongPdk = crypto.getRandomValues(new Uint8Array(32));

    const { ciphertext, iv } = await encryptMVK(mvk, correctPdk);

    await expect(decryptMVK(ciphertext, iv, wrongPdk)).rejects.toThrow("WRONG_PASSPHRASE");
  });

  it("throws WRONG_PASSPHRASE with tampered ciphertext", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const pdk = crypto.getRandomValues(new Uint8Array(32));

    const { ciphertext, iv } = await encryptMVK(mvk, pdk);

    // Flip a byte in the ciphertext
    const bytes = fromBase64(ciphertext);
    bytes[0] = (bytes[0] ?? 0) ^ 0xff;
    const tampered = toBase64(bytes);

    await expect(decryptMVK(tampered, iv, pdk)).rejects.toThrow("WRONG_PASSPHRASE");
  });

  it("property: encrypt then decrypt always recovers the original MVK", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 32, maxLength: 32 }), async (mvk) => {
        const pdk = crypto.getRandomValues(new Uint8Array(32));
        const { ciphertext, iv } = await encryptMVK(mvk, pdk);
        const recovered = await decryptMVK(ciphertext, iv, pdk);
        expect(recovered).toEqual(mvk);
      }),
      { numRuns: 50 }
    );
  });
});

// ---------------------------------------------------------------------------
// deriveFileKey
// ---------------------------------------------------------------------------

describe("deriveFileKey", () => {
  it("returns an AES-GCM CryptoKey", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const fileKey = await deriveFileKey(mvk, "file-001");

    expect(fileKey).toBeInstanceOf(CryptoKey);
    expect(fileKey.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect(fileKey.usages).toContain("encrypt");
    expect(fileKey.usages).toContain("decrypt");
  });

  it("is deterministic for the same MVK and fileId", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const a = await deriveFileKey(mvk, "same-file");
    const b = await deriveFileKey(mvk, "same-file");

    // Export raw key material to compare
    const rawA = new Uint8Array(await crypto.subtle.exportKey("raw", a));
    const rawB = new Uint8Array(await crypto.subtle.exportKey("raw", b));
    expect(rawA).toEqual(rawB);
  });

  it("produces different keys for different fileIds", async () => {
    const mvk = crypto.getRandomValues(new Uint8Array(32));
    const a = await deriveFileKey(mvk, "file-a");
    const b = await deriveFileKey(mvk, "file-b");

    const rawA = new Uint8Array(await crypto.subtle.exportKey("raw", a));
    const rawB = new Uint8Array(await crypto.subtle.exportKey("raw", b));
    expect(rawA).not.toEqual(rawB);
  });

  it("produces different keys for different MVKs", async () => {
    const mvkA = crypto.getRandomValues(new Uint8Array(32));
    const mvkB = crypto.getRandomValues(new Uint8Array(32));
    const a = await deriveFileKey(mvkA, "same-file");
    const b = await deriveFileKey(mvkB, "same-file");

    const rawA = new Uint8Array(await crypto.subtle.exportKey("raw", a));
    const rawB = new Uint8Array(await crypto.subtle.exportKey("raw", b));
    expect(rawA).not.toEqual(rawB);
  });
});
