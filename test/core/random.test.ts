import { describe, expect, it, vi } from 'vitest';
import { IV_BYTES, SEED_BYTES } from '../../src/core/constants.js';
import { randomBytes } from '../../src/core/random.js';

describe('random constants', () => {
  it('uses a 32-byte seed and a 12-byte IV', () => {
    expect(SEED_BYTES).toBe(32);
    expect(IV_BYTES).toBe(12);
  });
});

describe('randomBytes', () => {
  it('returns a Uint8Array of the requested length', () => {
    const bytes = randomBytes(16);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(16);
  });

  it('fills the buffer through crypto.getRandomValues', () => {
    const spy = vi.spyOn(crypto, 'getRandomValues').mockImplementation((buffer) => {
      const bytes = buffer as Uint8Array;
      bytes.set([1, 2, 3, 4]);
      return buffer;
    });

    expect(Array.from(randomBytes(4))).toEqual([1, 2, 3, 4]);
    expect(spy).toHaveBeenCalledOnce();

    spy.mockRestore();
  });

  it('produces different output across calls', () => {
    expect(Array.from(randomBytes(32))).not.toEqual(Array.from(randomBytes(32)));
  });

  it('accepts the Web Crypto per-call limit', () => {
    expect(randomBytes(65536)).toHaveLength(65536);
  });

  it('rejects a length that is not a positive integer', () => {
    for (const length of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => randomBytes(length)).toThrow(
        new RangeError(`randomBytes: length must be a positive integer, got ${length}`),
      );
    }
  });

  it('rejects a length above the Web Crypto per-call limit', () => {
    expect(() => randomBytes(65537)).toThrow(
      new RangeError('randomBytes: length 65537 exceeds the 65536-byte Web Crypto limit'),
    );
  });
});
