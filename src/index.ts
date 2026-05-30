// Core crypto operations

// Worker client (Promise-based wrapper)
export { CryptoWorkerClient } from "./client.js";
// Constant-time comparison
export { constantTimeEqual } from "./compare.js";
// Encoding utilities
export { fromBase64, fromHex, toBase64, toHex } from "./encoding.js";
export type { FileEncParams } from "./files.js";
export { decryptFile, encryptFile } from "./files.js";
export type { Argon2Params } from "./keys.js";
export {
  DEFAULT_ARGON2_PARAMS,
  decryptMVK,
  deriveFileKey,
  deriveKey,
  encryptMVK,
  LEGACY_ARGON2_PARAMS,
} from "./keys.js";
export { decryptMetadata, deriveMetadataKey, encryptMetadata } from "./metadata.js";

// Worker message handler
export { handleCryptoMessage } from "./worker.js";

// Worker message types
export type { CryptoRequest, CryptoResponse } from "./types.js";
