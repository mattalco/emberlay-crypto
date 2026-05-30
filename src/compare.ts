/**
 * Constant-time comparison of two Uint8Arrays.
 * Returns true if both arrays have the same length and identical bytes.
 * Uses a bitwise OR accumulator to avoid timing side-channels.
 *
 * When lengths differ, still iterates over the longer buffer to avoid
 * leaking length information via timing.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const maxLen = Math.max(a.length, b.length);
  let mismatch = a.length !== b.length ? 1 : 0;

  for (let i = 0; i < maxLen; i++) {
    const byteA = i < a.length ? (a[i] ?? 0) : 0;
    const byteB = i < b.length ? (b[i] ?? 0) : 0;
    mismatch |= byteA ^ byteB;
  }

  return mismatch === 0;
}
