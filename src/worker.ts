/**
 * CryptoWorker message handler — import this in your Web Worker entry point.
 *
 * Usage (in your app's worker file):
 *   import { handleCryptoMessage } from "@emberlay/crypto/worker";
 *   self.onmessage = (event) => handleCryptoMessage(event, self);
 *
 * This keeps the worker as a classic worker (no top-level exports from the
 * worker file itself) while sharing all crypto logic.
 */

import { decryptFile, encryptFile } from "./files.js";
import { decryptMVK, deriveFileKey, deriveKey, encryptMVK } from "./keys.js";
import type { CryptoRequest } from "./types.js";

export async function handleCryptoMessage(
  event: MessageEvent<CryptoRequest>,
  ctx: { postMessage: (msg: unknown, options?: StructuredSerializeOptions) => void }
): Promise<void> {
  const req = event.data;
  try {
    switch (req.type) {
      case "deriveKey": {
        const pdk = deriveKey(req.passphrase, req.salt, req.params);
        ctx.postMessage({ type: "deriveKey", id: req.id, pdk }, { transfer: [pdk.buffer] });
        break;
      }
      case "encryptMVK": {
        const { ciphertext, iv } = await encryptMVK(req.mvk, req.pdk);
        ctx.postMessage({ type: "encryptMVK", id: req.id, ciphertext, iv });
        break;
      }
      case "decryptMVK": {
        const mvk = await decryptMVK(req.ciphertext, req.iv, req.pdk);
        ctx.postMessage({ type: "decryptMVK", id: req.id, mvk }, { transfer: [mvk.buffer] });
        break;
      }
      case "deriveFileKey": {
        const fileKey = await deriveFileKey(req.mvk, req.fileId);
        ctx.postMessage({ type: "deriveFileKey", id: req.id, fileKey });
        break;
      }
      case "encryptFile": {
        const { encrypted, encParams } = await encryptFile(req.fileBuffer, req.fileKey);
        ctx.postMessage(
          { type: "encryptFile", id: req.id, encrypted, encParams },
          { transfer: [encrypted.buffer] }
        );
        break;
      }
      case "encryptChunk": {
        const chunkIv = new Uint8Array(req.baseIv);
        const dv = new DataView(chunkIv.buffer);
        dv.setUint32(8, dv.getUint32(8, false) ^ req.chunkIndex, false);
        const encrypted = new Uint8Array(
          await crypto.subtle.encrypt({ name: "AES-GCM", iv: chunkIv }, req.fileKey, req.chunkData)
        );
        ctx.postMessage(
          { type: "encryptChunk", id: req.id, encrypted },
          { transfer: [encrypted.buffer] }
        );
        break;
      }
      case "decryptFile": {
        const decrypted = await decryptFile(req.encryptedBuffer, req.fileKey, req.encParams);
        ctx.postMessage(
          { type: "decryptFile", id: req.id, decrypted },
          { transfer: [decrypted.buffer] }
        );
        break;
      }
      default:
        ctx.postMessage({
          type: "error",
          id: (req as { id: string }).id,
          message: "Unknown request type",
        });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown crypto error";
    console.error("[crypto-worker] error", message);
    ctx.postMessage({ type: "error", id: req.id, message });
  }
}
