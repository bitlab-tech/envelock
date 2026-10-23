import { describe, expect, it } from 'vitest';
import { SALT_BYTES, SEED_BYTES } from '../../src/core/constants.js';
import { toBase64Url } from '../../src/core/encoding.js';
import { generateApiKey, parseApiKey } from '../../src/identity/apiKey.js';

const combine = (seed: Uint8Array, salt: Uint8Array) => {
  const combined = new Uint8Array(seed.length + salt.length);
  combined.set(seed, 0);
  combined.set(salt, seed.length);
  return combined;
};

describe('generateApiKey', () => {
  it('returns a 32-byte seed, a 32-byte salt, and a prefixed display key', () => {
    const { seed, salt, displayKey } = generateApiKey('ev');

    expect(seed).toHaveLength(SEED_BYTES);
    expect(salt).toHaveLength(SALT_BYTES);
    expect(displayKey).toBe(`ev_${toBase64Url(combine(seed, salt))}`);
  });

  it('omits the separator when the prefix is empty', () => {
    const { seed, salt, displayKey } = generateApiKey('');

    expect(displayKey).toBe(toBase64Url(combine(seed, salt)));
    expect(parseApiKey(displayKey, '')).toEqual({ seed, salt });
  });

  it('generates a different seed and salt each call', () => {
    const first = generateApiKey('ev');
    const second = generateApiKey('ev');

    expect(Array.from(first.seed)).not.toEqual(Array.from(second.seed));
    expect(Array.from(first.salt)).not.toEqual(Array.from(second.salt));
  });
});

describe('parseApiKey', () => {
  it('returns the seed and salt from a generated display key', () => {
    const { seed, salt, displayKey } = generateApiKey('ev');

    expect(parseApiKey(displayKey, 'ev')).toEqual({ seed, salt });
  });

  it('rejects a key whose prefix does not match', () => {
    const { displayKey } = generateApiKey('event');

    expect(() => parseApiKey(displayKey, 'ev')).toThrow(new Error('invalid key format'));
    expect(() => parseApiKey('no-separator', 'ev')).toThrow(new Error('invalid key format'));
  });

  it('rejects a secret that does not decode to 64 bytes', () => {
    expect(() => parseApiKey('ev_YQ', 'ev')).toThrow(new Error('invalid key length'));
  });

  it('rejects a secret that is not base64url', () => {
    expect(() => parseApiKey('ev_A', 'ev')).toThrow(
      new Error('fromBase64Url: invalid base64url length (1)'),
    );
    expect(() => parseApiKey('ev_!!!!', 'ev')).toThrow('Invalid character');
  });
});
