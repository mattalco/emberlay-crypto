/**
 * Tests for base64 and hex encoding utilities.
 */

import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { fromBase64, fromHex, toBase64, toHex } from "./encoding.js";

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

describe("toBase64 / fromBase64", () => {
  it("round-trips a known value", () => {
    const input = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const encoded = toBase64(input);
    expect(encoded).toBe("SGVsbG8=");
    expect(fromBase64(encoded)).toEqual(input);
  });

  it("handles empty array", () => {
    const empty = new Uint8Array(0);
    const encoded = toBase64(empty);
    expect(encoded).toBe("");
    expect(fromBase64(encoded)).toEqual(empty);
  });

  it("handles single byte", () => {
    const single = new Uint8Array([255]);
    expect(fromBase64(toBase64(single))).toEqual(single);
  });

  it("property: any Uint8Array survives a round-trip", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), (bytes) => {
        const decoded = fromBase64(toBase64(bytes));
        expect(decoded).toEqual(bytes);
      }),
      { numRuns: 200 }
    );
  });

  it("property: toBase64 output contains only valid base64 characters", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 256 }), (bytes) => {
        const encoded = toBase64(bytes);
        expect(encoded).toMatch(/^[A-Za-z0-9+/=]*$/);
      }),
      { numRuns: 200 }
    );
  });
});

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

describe("toHex / fromHex", () => {
  it("round-trips a known value", () => {
    const input = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const hex = toHex(input);
    expect(hex).toBe("DE AD BE EF");
    expect(fromHex(hex)).toEqual(input);
  });

  it("handles empty array", () => {
    const empty = new Uint8Array(0);
    expect(toHex(empty)).toBe("");
    expect(fromHex("")).toEqual(empty);
  });

  it("fromHex handles lowercase input", () => {
    expect(fromHex("deadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("fromHex handles input without spaces", () => {
    expect(fromHex("DEADBEEF")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("property: any Uint8Array survives a hex round-trip", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 256 }), (bytes) => {
        const decoded = fromHex(toHex(bytes));
        expect(decoded).toEqual(bytes);
      }),
      { numRuns: 200 }
    );
  });

  it("property: toHex output is uppercase hex pairs separated by spaces", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (bytes) => {
        const hex = toHex(bytes);
        expect(hex).toMatch(/^([0-9A-F]{2})( [0-9A-F]{2})*$/);
      }),
      { numRuns: 200 }
    );
  });
});
