/**
 * Tests for CryptoWorkerClient message protocol.
 */

import { describe, expect, it, vi } from "vitest";
import { CryptoWorkerClient } from "./client.js";

// ---------------------------------------------------------------------------
// Mock Worker
// ---------------------------------------------------------------------------

function createMockWorker() {
  const listeners: {
    onmessage: ((event: MessageEvent) => void) | null;
    onerror: ((event: ErrorEvent) => void) | null;
  } = { onmessage: null, onerror: null };

  const worker = {
    postMessage: vi.fn(),
    terminate: vi.fn(),
    set onmessage(fn: ((event: MessageEvent) => void) | null) {
      listeners.onmessage = fn;
    },
    get onmessage() {
      return listeners.onmessage;
    },
    set onerror(fn: ((event: ErrorEvent) => void) | null) {
      listeners.onerror = fn;
    },
    get onerror() {
      return listeners.onerror;
    },
  } as unknown as Worker;

  return {
    worker,
    simulateMessage(data: unknown) {
      listeners.onmessage?.({ data } as MessageEvent);
    },
    simulateError(message: string) {
      listeners.onerror?.({ message } as ErrorEvent);
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Safely extract the nth posted message from the mock worker. */
function getPostedMessage(worker: Worker, index = 0): Record<string, unknown> {
  const calls = (worker.postMessage as ReturnType<typeof vi.fn>).mock.calls;
  const call = calls[index];
  if (!call) throw new Error(`No postMessage call at index ${index}`);
  return call[0] as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constructor and message routing
// ---------------------------------------------------------------------------

describe("CryptoWorkerClient", () => {
  it("posts a message to the worker on deriveKey", () => {
    const { worker } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    // Don't await — just verify the message was posted
    client.deriveKey("pass", "salt");

    expect(worker.postMessage).toHaveBeenCalledTimes(1);
    const msg = getPostedMessage(worker);
    expect(msg.type).toBe("deriveKey");
    expect(msg.passphrase).toBe("pass");
    expect(msg.salt).toBe("salt");
    expect(msg.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it("resolves deriveKey when worker responds", async () => {
    const { worker, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const promise = client.deriveKey("pass", "salt");

    const msg = getPostedMessage(worker);
    const pdk = new Uint8Array([1, 2, 3]);
    simulateMessage({ type: "deriveKey", id: msg.id, pdk });

    const result = await promise;
    expect(result).toEqual(pdk);
  });

  it("resolves encryptMVK with ciphertext and iv", async () => {
    const { worker, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const mvk = new Uint8Array(32);
    const pdk = new Uint8Array(32);
    const promise = client.encryptMVK(mvk, pdk);

    const msg = getPostedMessage(worker);
    simulateMessage({ type: "encryptMVK", id: msg.id, ciphertext: "ct", iv: "iv" });

    const result = await promise;
    expect(result).toEqual({ ciphertext: "ct", iv: "iv" });
  });

  it("resolves decryptMVK with mvk bytes", async () => {
    const { worker, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const pdk = new Uint8Array(32);
    const promise = client.decryptMVK("ct", "iv", pdk);

    const msg = getPostedMessage(worker);
    const mvk = new Uint8Array([9, 8, 7]);
    simulateMessage({ type: "decryptMVK", id: msg.id, mvk });

    const result = await promise;
    expect(result).toEqual(mvk);
  });

  it("rejects when worker responds with error type", async () => {
    const { worker, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const promise = client.deriveKey("pass", "salt");

    const msg = getPostedMessage(worker);
    simulateMessage({ type: "error", id: msg.id, message: "something broke" });

    await expect(promise).rejects.toThrow("something broke");
  });

  it("ignores messages with unknown ids", async () => {
    const { worker, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const promise = client.deriveKey("pass", "salt");

    // Send a response with a wrong id — should be ignored
    simulateMessage({ type: "deriveKey", id: "wrong-id", pdk: new Uint8Array(32) });

    // Now send the correct one
    const msg = getPostedMessage(worker);
    const pdk = new Uint8Array([5, 6, 7]);
    simulateMessage({ type: "deriveKey", id: msg.id, pdk });

    const result = await promise;
    expect(result).toEqual(pdk);
  });
});

// ---------------------------------------------------------------------------
// Worker error (onerror)
// ---------------------------------------------------------------------------

describe("CryptoWorkerClient onerror", () => {
  it("rejects all pending promises when worker crashes", async () => {
    const { worker, simulateError } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const p1 = client.deriveKey("a", "b");
    const p2 = client.encryptMVK(new Uint8Array(32), new Uint8Array(32));

    simulateError("Worker crashed");

    await expect(p1).rejects.toThrow("CryptoWorker crashed: Worker crashed");
    await expect(p2).rejects.toThrow("CryptoWorker crashed: Worker crashed");
  });

  it("clears pending map after crash", async () => {
    const { worker, simulateError, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const p1 = client.deriveKey("a", "b");
    const msg = getPostedMessage(worker);

    simulateError("crash");
    await expect(p1).rejects.toThrow();

    // A late response for the old id should not throw or resolve anything
    simulateMessage({ type: "deriveKey", id: msg.id, pdk: new Uint8Array(32) });
    // No error thrown — the handler was already cleaned up
  });
});

// ---------------------------------------------------------------------------
// Multiple concurrent requests
// ---------------------------------------------------------------------------

describe("CryptoWorkerClient concurrent requests", () => {
  it("routes responses to the correct pending promise", async () => {
    const { worker, simulateMessage } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    const p1 = client.deriveKey("first", "s1");
    const p2 = client.deriveKey("second", "s2");

    const msg1 = getPostedMessage(worker, 0);
    const msg2 = getPostedMessage(worker, 1);

    // Respond out of order
    const pdk2 = new Uint8Array([2, 2, 2]);
    const pdk1 = new Uint8Array([1, 1, 1]);
    simulateMessage({ type: "deriveKey", id: msg2.id, pdk: pdk2 });
    simulateMessage({ type: "deriveKey", id: msg1.id, pdk: pdk1 });

    expect(await p1).toEqual(pdk1);
    expect(await p2).toEqual(pdk2);
  });
});

// ---------------------------------------------------------------------------
// terminate
// ---------------------------------------------------------------------------

describe("CryptoWorkerClient terminate", () => {
  it("calls worker.terminate()", () => {
    const { worker } = createMockWorker();
    const client = new CryptoWorkerClient(worker);

    client.terminate();
    expect(worker.terminate).toHaveBeenCalledTimes(1);
  });
});
