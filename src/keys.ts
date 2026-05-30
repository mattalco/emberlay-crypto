/**
 * Key derivation and MVK encryption/decryption.
 *
 * Core cryptographic operations for a zero-knowledge vault system.
 * All operations use the Web Crypto API and run in any environment that
 * supports it (browser main thread, Web Worker, or Cloudflare Worker).
 */

import { argon2id } from "@noble/hashes/argon2.js";
import { fromBase64, toBase64 } from "./encoding.js";

/**
 * Argon2id parameters supported by the system.
 *
 * - `DEFAULT_ARGON2_PARAMS` is what new accounts get (passphrase setup, change,
 *   reset). Update this constant to raise the cost for new accounts — existing
 *   users continue to use the params stored alongside their encrypted key until
 *   they change their passphrase, at which point they upgrade to the new default.
 * - `LEGACY_ARGON2_PARAMS` documents the historical default. Kept for clarity
 *   and backward compatibility in the test suite.
 */
export interface Argon2Params {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memoryCost: 131072, // 128 MiB
  timeCost: 3,
  parallelism: 1,
};

export const LEGACY_ARGON2_PARAMS: Argon2Params = {
  memoryCost: 65536, // 64 MiB — the original default
  timeCost: 3,
  parallelism: 1,
};

/**
 * Derive a Passphrase-Derived Key (PDK) from a passphrase using Argon2id.
 *
 * Params default to `DEFAULT_ARGON2_PARAMS` so callers in the encrypt path
 * (passphrase setup, change, reset) get the current cost. Decrypt callers
 * MUST pass the params that were used at encrypt time — otherwise the derived
 * PDK will not match and decryption will fail with `WRONG_PASSPHRASE`.
 *
 * @param passphrase - The user's passphrase
 * @param saltB64 - Base64-encoded 16-byte salt
 * @param params - Argon2id cost parameters (defaults to current system default)
 * @returns 32-byte PDK
 */
export function deriveKey(
  passphrase: string,
  saltB64: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS
): Uint8Array {
  const salt = fromBase64(saltB64);
  const passphraseBytes = new TextEncoder().encode(passphrase);
  return argon2id(passphraseBytes, salt, {
    m: params.memoryCost,
    t: params.timeCost,
    p: params.parallelism,
    dkLen: 32,
  });
}

/**
 * Encrypt the MVK with a PDK using AES-256-GCM.
 *
 * @param mvk - 32-byte Master Vault Key
 * @param pdk - 32-byte Passphrase-Derived Key
 * @returns Base64-encoded ciphertext and IV
 */
export async function encryptMVK(
  mvk: Uint8Array,
  pdk: Uint8Array
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey(
    "raw",
    pdk as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as unknown as ArrayBuffer },
    key,
    mvk as unknown as ArrayBuffer
  );
  return { ciphertext: toBase64(new Uint8Array(ciphertextBuffer)), iv: toBase64(iv) };
}

/**
 * Decrypt the MVK from its encrypted form using a PDK.
 *
 * @param ciphertextB64 - Base64-encoded AES-GCM ciphertext
 * @param ivB64 - Base64-encoded 12-byte IV
 * @param pdk - 32-byte Passphrase-Derived Key
 * @returns 32-byte MVK
 * @throws Error with message "WRONG_PASSPHRASE" if decryption fails
 */
export async function decryptMVK(
  ciphertextB64: string,
  ivB64: string,
  pdk: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    pdk as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(ivB64) as unknown as ArrayBuffer },
      key,
      fromBase64(ciphertextB64) as unknown as ArrayBuffer
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("WRONG_PASSPHRASE");
  }
}

/**
 * Derive a per-file encryption key from the MVK using HKDF.
 *
 * @param mvk - 32-byte Master Vault Key
 * @param fileId - Unique file identifier (used as HKDF info)
 * @returns AES-256-GCM CryptoKey for file encryption/decryption
 */
export async function deriveFileKey(mvk: Uint8Array, fileId: string): Promise<CryptoKey> {
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
      info: new TextEncoder().encode(fileId),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}
