/**
 * CryptoWorkerClient — typed Promise-based wrapper around a Web Worker.
 *
 * Each app provides its own Worker instance (since Worker bundling is
 * app/bundler-specific). This class handles the message protocol.
 *
 * Usage:
 *   const worker = new Worker(new URL("./crypto.worker.ts", import.meta.url));
 *   const client = new CryptoWorkerClient(worker);
 *   const pdk = await client.deriveKey(passphrase, salt);
 */

import type { FileEncParams } from "./files.js";
import type { CryptoRequest, CryptoResponse } from "./types.js";

export class CryptoWorkerClient {
  private worker: Worker;
  private pending = new Map<
    string,
    { resolve: (v: CryptoResponse) => void; reject: (e: Error) => void }
  >();

  constructor(worker: Worker) {
    this.worker = worker;

    this.worker.onmessage = (event: MessageEvent<CryptoResponse>) => {
      const res = event.data;
      const handler = this.pending.get(res.id);
      if (!handler) return;
      this.pending.delete(res.id);
      if (res.type === "error") {
        handler.reject(new Error(res.message));
      } else {
        handler.resolve(res);
      }
    };

    this.worker.onerror = (event) => {
      console.error("[CryptoWorkerClient] worker error", event.message);
      for (const [, handler] of this.pending) {
        handler.reject(new Error(`CryptoWorker crashed: ${event.message}`));
      }
      this.pending.clear();
    };
  }

  private send<T extends CryptoResponse>(req: CryptoRequest): Promise<T> {
    return new Promise((resolve, reject) => {
      this.pending.set(req.id, {
        resolve: resolve as (v: CryptoResponse) => void,
        reject,
      });
      this.worker.postMessage(req);
    });
  }

  async deriveKey(
    passphrase: string,
    salt: string,
    params?: import("./keys.js").Argon2Params
  ): Promise<Uint8Array> {
    const req: CryptoRequest = {
      type: "deriveKey",
      id: crypto.randomUUID(),
      passphrase,
      salt,
      ...(params ? { params } : {}),
    };
    const res = await this.send<Extract<CryptoResponse, { type: "deriveKey" }>>(req);
    return res.pdk;
  }

  async encryptMVK(mvk: Uint8Array, pdk: Uint8Array): Promise<{ ciphertext: string; iv: string }> {
    const res = await this.send<Extract<CryptoResponse, { type: "encryptMVK" }>>({
      type: "encryptMVK",
      id: crypto.randomUUID(),
      mvk,
      pdk,
    });
    return { ciphertext: res.ciphertext, iv: res.iv };
  }

  async decryptMVK(ciphertext: string, iv: string, pdk: Uint8Array): Promise<Uint8Array> {
    const res = await this.send<Extract<CryptoResponse, { type: "decryptMVK" }>>({
      type: "decryptMVK",
      id: crypto.randomUUID(),
      ciphertext,
      iv,
      pdk,
    });
    return res.mvk;
  }

  async deriveFileKey(mvk: Uint8Array, fileId: string): Promise<CryptoKey> {
    const res = await this.send<Extract<CryptoResponse, { type: "deriveFileKey" }>>({
      type: "deriveFileKey",
      id: crypto.randomUUID(),
      mvk,
      fileId,
    });
    return res.fileKey;
  }

  async encryptFile(
    fileBuffer: ArrayBuffer,
    fileKey: CryptoKey
  ): Promise<{ encrypted: Uint8Array; encParams: FileEncParams }> {
    const res = await this.send<Extract<CryptoResponse, { type: "encryptFile" }>>({
      type: "encryptFile",
      id: crypto.randomUUID(),
      fileBuffer,
      fileKey,
    });
    return { encrypted: res.encrypted, encParams: res.encParams };
  }

  async encryptChunk(
    fileKey: CryptoKey,
    baseIv: Uint8Array,
    chunkData: ArrayBuffer,
    chunkIndex: number
  ): Promise<Uint8Array> {
    const res = await this.send<Extract<CryptoResponse, { type: "encryptChunk" }>>({
      type: "encryptChunk",
      id: crypto.randomUUID(),
      fileKey,
      baseIv,
      chunkData,
      chunkIndex,
    });
    return res.encrypted;
  }

  async decryptFile(
    encryptedBuffer: ArrayBuffer,
    fileKey: CryptoKey,
    encParams: {
      iv: string;
      keyDerivation: { algorithm: string; hash: string; salt: string; info: string };
    }
  ): Promise<Uint8Array> {
    const res = await this.send<Extract<CryptoResponse, { type: "decryptFile" }>>({
      type: "decryptFile",
      id: crypto.randomUUID(),
      encryptedBuffer,
      fileKey,
      encParams,
    });
    return res.decrypted;
  }

  terminate(): void {
    this.worker.terminate();
  }
}
