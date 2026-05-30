/**
 * Tests for file encryption and decryption with chunking.
 */

import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { toBase64 } from "./encoding.js";
import { decryptFile, encryptFile } from "./files.js";
import { deriveFileKey } from "./keys.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeFileKey(): Promise<CryptoKey> {
  const mvk = crypto.getRandomValues(new Uint8Array(32));
  return deriveFileKey(mvk, "test-file-id");
}

/** Fill a large Uint8Array with random bytes (works around jsdom's 65536-byte limit). */
function fillRandom(bytes: Uint8Array): Uint8Array {
  const chunkSize = 65536;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const size = Math.min(chunkSize, bytes.length - offset);
    const chunk = new Uint8Array(size);
    crypto.getRandomValues(chunk);
    bytes.set(chunk, offset);
  }
  return bytes;
}

/** Get the ArrayBuffer from a Uint8Array (typed to satisfy strict TS). */
function bufferOf(arr: Uint8Array): ArrayBuffer {
  return arr.buffer as ArrayBuffer;
}

// ---------------------------------------------------------------------------
// encryptFile / decryptFile round-trip
// ---------------------------------------------------------------------------

describe("encryptFile / decryptFile", () => {
  it("round-trips an empty file", async () => {
    const fileKey = await makeFileKey();
    const input = new ArrayBuffer(0);

    const { encrypted, encParams } = await encryptFile(input, fileKey);
    const decrypted = await decryptFile(bufferOf(encrypted), fileKey, encParams);

    expect(decrypted).toEqual(new Uint8Array(0));
  });

  it("round-trips a small file (< 4MB)", async () => {
    const fileKey = await makeFileKey();
    const content = crypto.getRandomValues(new Uint8Array(1024));

    const { encrypted, encParams } = await encryptFile(bufferOf(content), fileKey);
    const decrypted = await decryptFile(bufferOf(encrypted), fileKey, encParams);

    expect(decrypted).toEqual(content);
  });

  it("round-trips a file exactly at chunk boundary (4MB)", { timeout: 60_000 }, async () => {
    const fileKey = await makeFileKey();
    const chunkSize = 4 * 1024 * 1024;
    const content = fillRandom(new Uint8Array(chunkSize));

    const { encrypted, encParams } = await encryptFile(bufferOf(content), fileKey);
    const decrypted = await decryptFile(bufferOf(encrypted), fileKey, encParams);

    expect(decrypted).toEqual(content);
  });

  it("round-trips a multi-chunk file (> 4MB)", { timeout: 60_000 }, async () => {
    const fileKey = await makeFileKey();
    const chunkSize = 4 * 1024 * 1024;
    // 4MB + 100 bytes = 2 chunks
    const content = fillRandom(new Uint8Array(chunkSize + 100));

    const { encrypted, encParams } = await encryptFile(bufferOf(content), fileKey);
    const decrypted = await decryptFile(bufferOf(encrypted), fileKey, encParams);

    expect(decrypted).toEqual(content);
  });

  it("encrypted output is larger than input (auth tags + header)", async () => {
    const fileKey = await makeFileKey();
    const content = crypto.getRandomValues(new Uint8Array(500));

    const { encrypted } = await encryptFile(bufferOf(content), fileKey);

    // 4-byte header + plaintext + 16-byte GCM auth tag per chunk
    expect(encrypted.length).toBeGreaterThan(content.length);
  });

  it("encParams contains valid base64 IV", async () => {
    const fileKey = await makeFileKey();
    const content = crypto.getRandomValues(new Uint8Array(64));

    const { encParams } = await encryptFile(bufferOf(content), fileKey);

    expect(encParams.iv).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(encParams.keyDerivation.algorithm).toBe("HKDF");
    expect(encParams.keyDerivation.hash).toBe("SHA-256");
  });

  it("property: encrypt then decrypt recovers original content", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 0, maxLength: 8192 }), async (content) => {
        const fileKey = await makeFileKey();
        const { encrypted, encParams } = await encryptFile(bufferOf(content), fileKey);
        const decrypted = await decryptFile(bufferOf(encrypted), fileKey, encParams);
        expect(decrypted).toEqual(content);
      }),
      { numRuns: 30 }
    );
  });
});

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

describe("decryptFile error handling", () => {
  it("throws CORRUPTED_FILE for buffer shorter than 4 bytes", async () => {
    const fileKey = await makeFileKey();
    const tiny = bufferOf(new Uint8Array([1, 2, 3]));

    await expect(decryptFile(tiny, fileKey, { iv: toBase64(new Uint8Array(12)) })).rejects.toThrow(
      "CORRUPTED_FILE"
    );
  });

  it("throws CORRUPTED_FILE when ciphertext is tampered", async () => {
    const fileKey = await makeFileKey();
    const content = crypto.getRandomValues(new Uint8Array(256));

    const { encrypted, encParams } = await encryptFile(bufferOf(content), fileKey);

    // Tamper with encrypted data (after the 4-byte header)
    const tampered = new Uint8Array(encrypted);
    tampered[10] = (tampered[10] ?? 0) ^ 0xff;

    await expect(decryptFile(bufferOf(tampered), fileKey, encParams)).rejects.toThrow(
      "CORRUPTED_FILE"
    );
  });

  it("throws CORRUPTED_FILE with wrong file key", async () => {
    const fileKey = await makeFileKey();
    const wrongKey = await makeFileKey(); // different MVK → different key
    const content = crypto.getRandomValues(new Uint8Array(128));

    const { encrypted, encParams } = await encryptFile(bufferOf(content), fileKey);

    await expect(decryptFile(bufferOf(encrypted), wrongKey, encParams)).rejects.toThrow(
      "CORRUPTED_FILE"
    );
  });
});
