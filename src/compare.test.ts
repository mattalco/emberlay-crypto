/**
 * Tests for constant-time comparison.
 */

import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { constantTimeEqual } from "./compare.js";

describe("constantTimeEqual", () => {
  it("returns true for identical arrays", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    expect(constantTimeEqual(a, a)).toBe(true);
  });

  it("returns true for equal but distinct arrays", () => {
    const a = new Uint8Array([10, 20, 30]);
    const b = new Uint8Array([10, 20, 30]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("returns false when content differs", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("returns false when lengths differ", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("returns true for two empty arrays", () => {
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it("returns false for empty vs non-empty", () => {
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array([1]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array(0))).toBe(false);
  });

  it("returns false when only the last byte differs", () => {
    const a = new Uint8Array([0, 0, 0, 0, 1]);
    const b = new Uint8Array([0, 0, 0, 0, 2]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("property: an array always equals itself", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 256 }), (bytes) => {
        expect(constantTimeEqual(bytes, bytes)).toBe(true);
      }),
      { numRuns: 200 }
    );
  });

  it("property: an array equals its copy", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 256 }), (bytes) => {
        const copy = new Uint8Array(bytes);
        expect(constantTimeEqual(bytes, copy)).toBe(true);
      }),
      { numRuns: 200 }
    );
  });

  it("property: flipping any bit produces inequality", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 256 }), fc.nat(), (bytes, rawIndex) => {
        const index = rawIndex % bytes.length;
        const modified = new Uint8Array(bytes);
        modified[index] = (modified[index] ?? 0) ^ 0x01;
        expect(constantTimeEqual(bytes, modified)).toBe(false);
      }),
      { numRuns: 200 }
    );
  });
});
