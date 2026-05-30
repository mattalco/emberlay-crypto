/**
 * Metadata encryption — encrypts/decrypts file names (and optionally other
 * metadata) using a single key derived from the MVK.
 *
 * Uses a dedicated HKDF-derived key so that metadata encryption is independent
 * of per-file content keys. One key derivation per session, then one AES-GCM
 * operation per file name — keeps the file list render fast.
 */

import { fromBase64, toBase64 } from "./encoding.js";

/**
 * Derive a metadata encryption key from the MVK using HKDF.
 *
 * @param mvk - 32-byte Master Vault Key
 * @returns AES-256-GCM CryptoKey for metadata encryption/decryption
 */
export async function deriveMetadataKey(mvk: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    mvk as unknown as ArrayBuffer,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("emberlay-metadata-v1"),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt a metadata string (e.g. file name) using AES-256-GCM.
 *
 * @param metadataKey - CryptoKey from deriveMetadataKey
 * @param plaintext - The string to encrypt
 * @returns Base64-encoded ciphertext and IV
 */
export async function encryptMetadata(
  metadataKey: CryptoKey,
  plaintext: string
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as unknown as ArrayBuffer },
    metadataKey,
    encoded as unknown as ArrayBuffer
  );
  return { ciphertext: toBase64(new Uint8Array(ciphertextBuffer)), iv: toBase64(iv) };
}

/**
 * Decrypt a metadata string (e.g. file name) using AES-256-GCM.
 *
 * @param metadataKey - CryptoKey from deriveMetadataKey
 * @param ciphertextB64 - Base64-encoded ciphertext
 * @param ivB64 - Base64-encoded 12-byte IV
 * @returns Decrypted plaintext string
 * @throws Error if decryption fails (wrong key or corrupted data)
 */
export async function decryptMetadata(
  metadataKey: CryptoKey,
  ciphertextB64: string,
  ivB64: string
): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(ivB64) as unknown as ArrayBuffer },
    metadataKey,
    fromBase64(ciphertextB64) as unknown as ArrayBuffer
  );
  return new TextDecoder().decode(plaintext);
}
