/**
 * File encryption and decryption using AES-256-GCM with chunking.
 *
 * Files are split into 4 MB chunks, each encrypted with a unique IV derived
 * from a base IV XORed with the chunk index. This allows streaming decryption
 * of large files without loading the entire plaintext into memory at once.
 */

import { fromBase64, toBase64 } from "./encoding.js";

const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB

export interface FileEncParams {
  iv: string;
  keyDerivation: {
    algorithm: string;
    hash: string;
    salt: string;
    info: string;
  };
}

/**
 * Encrypt a file buffer using AES-256-GCM with chunking.
 *
 * @param fileBuffer - Raw file content
 * @param fileKey - AES-256-GCM CryptoKey (from deriveFileKey)
 * @returns Encrypted buffer (4-byte chunk count header + encrypted chunks) and encryption params
 */
export async function encryptFile(
  fileBuffer: ArrayBuffer,
  fileKey: CryptoKey
): Promise<{ encrypted: Uint8Array; encParams: FileEncParams }> {
  const input = new Uint8Array(fileBuffer);
  const chunkCount = Math.ceil(input.length / CHUNK_SIZE) || 1;
  const baseIv = crypto.getRandomValues(new Uint8Array(12));

  const encParams: FileEncParams = {
    iv: toBase64(baseIv),
    keyDerivation: {
      algorithm: "HKDF",
      hash: "SHA-256",
      salt: toBase64(new Uint8Array(32)),
      info: "",
    },
  };

  const encryptedChunks: Uint8Array[] = [];
  let totalEncryptedBytes = 0;

  for (let i = 0; i < chunkCount; i++) {
    const chunk = input.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, input.length));
    const chunkIv = new Uint8Array(baseIv);
    new DataView(chunkIv.buffer).setUint32(8, new DataView(chunkIv.buffer).getUint32(8) ^ i, false);
    const enc = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv: chunkIv }, fileKey, chunk)
    );
    encryptedChunks.push(enc);
    totalEncryptedBytes += enc.length;
  }

  const result = new Uint8Array(4 + totalEncryptedBytes);
  new DataView(result.buffer).setUint32(0, chunkCount, false);
  let offset = 4;
  for (const chunk of encryptedChunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return { encrypted: result, encParams };
}

/**
 * Decrypt an encrypted file buffer using AES-256-GCM with chunking.
 *
 * @param encryptedBuffer - Encrypted file (4-byte header + chunks)
 * @param fileKey - AES-256-GCM CryptoKey (from deriveFileKey)
 * @param encParams - Encryption parameters (must include iv)
 * @returns Decrypted file content
 * @throws Error with message "CORRUPTED_FILE" if decryption fails
 */
export async function decryptFile(
  encryptedBuffer: ArrayBuffer,
  fileKey: CryptoKey,
  encParams: { iv: string }
): Promise<Uint8Array> {
  const input = new Uint8Array(encryptedBuffer);
  if (input.length < 4) throw new Error("CORRUPTED_FILE");

  const chunkCount = new DataView(input.buffer).getUint32(0, false);
  const baseIv = fromBase64(encParams.iv);
  const encChunkSize = CHUNK_SIZE + 16; // AES-GCM adds 16-byte auth tag

  const decryptedChunks: Uint8Array[] = [];
  let offset = 4;

  for (let i = 0; i < chunkCount; i++) {
    const remaining = input.length - offset;
    const size = i === chunkCount - 1 ? remaining : Math.min(encChunkSize, remaining);
    if (size <= 0) throw new Error("CORRUPTED_FILE");

    const chunkIv = new Uint8Array(baseIv);
    new DataView(chunkIv.buffer).setUint32(8, new DataView(chunkIv.buffer).getUint32(8) ^ i, false);

    try {
      const dec = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: chunkIv },
        fileKey,
        input.slice(offset, offset + size)
      );
      decryptedChunks.push(new Uint8Array(dec));
    } catch {
      throw new Error("CORRUPTED_FILE");
    }
    offset += size;
  }

  const totalBytes = decryptedChunks.reduce((s, c) => s + c.length, 0);
  const result = new Uint8Array(totalBytes);
  let writeOffset = 0;
  for (const chunk of decryptedChunks) {
    result.set(chunk, writeOffset);
    writeOffset += chunk.length;
  }
  return result;
}
