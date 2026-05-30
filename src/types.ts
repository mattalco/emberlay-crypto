/**
 * Message protocol types for the CryptoWorker.
 *
 * These define the request/response shapes passed between the main thread
 * and the Web Worker via postMessage.
 */

import type { FileEncParams } from "./files.js";
import type { Argon2Params } from "./keys.js";

export type CryptoRequest =
  | {
      type: "deriveKey";
      id: string;
      passphrase: string;
      salt: string;
      params?: Argon2Params;
    }
  | { type: "encryptMVK"; id: string; mvk: Uint8Array; pdk: Uint8Array }
  | { type: "decryptMVK"; id: string; ciphertext: string; iv: string; pdk: Uint8Array }
  | { type: "deriveFileKey"; id: string; mvk: Uint8Array; fileId: string }
  | { type: "encryptFile"; id: string; fileBuffer: ArrayBuffer; fileKey: CryptoKey }
  | {
      type: "encryptChunk";
      id: string;
      fileKey: CryptoKey;
      baseIv: Uint8Array;
      chunkData: ArrayBuffer;
      chunkIndex: number;
    }
  | {
      type: "decryptFile";
      id: string;
      encryptedBuffer: ArrayBuffer;
      fileKey: CryptoKey;
      encParams: {
        iv: string;
        keyDerivation: { algorithm: string; hash: string; salt: string; info: string };
      };
    };

export type CryptoResponse =
  | { type: "deriveKey"; id: string; pdk: Uint8Array }
  | { type: "encryptMVK"; id: string; ciphertext: string; iv: string }
  | { type: "decryptMVK"; id: string; mvk: Uint8Array }
  | { type: "deriveFileKey"; id: string; fileKey: CryptoKey }
  | { type: "encryptFile"; id: string; encrypted: Uint8Array; encParams: FileEncParams }
  | { type: "encryptChunk"; id: string; encrypted: Uint8Array }
  | { type: "decryptFile"; id: string; decrypted: Uint8Array }
  | { type: "error"; id: string; message: string };
