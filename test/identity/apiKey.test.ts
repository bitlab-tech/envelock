import { describe, expect, it } from 'vitest';
import { SEED_BYTES } from '../../src/core/constants.js';
import { toBase64Url } from '../../src/core/encoding.js';
import { generateApiKey, parseApiKey } from '../../src/identity/apiKey.js';

describe('generateApiKey', () => {
  it('returns a 32-byte seed and a prefixed base64url display key', () => {
    const { seed, displayKey } = generateApiKey('ev');

    expect(seed).toHaveLength(SEED_BYTES);
    expect(displayKey).toBe(`ev_${toBase64Url(seed)}`);
  });

  it('omits the separator when the prefix is empty', () => {
    const { seed, displayKey } = generateApiKey('');

    expect(displayKey).toBe(toBase64Url(seed));
    expect(parseApiKey(displayKey, '')).toEqual(seed);
  });

  it('generates a different seed each call', () => {
    const first = generateApiKey('ev');
    const second = generateApiKey('ev');

    expect(Array.from(first.seed)).not.toEqual(Array.from(second.seed));
  });
});

describe('parseApiKey', () => {
  it('returns the seed from a generated display key', () => {
    const { seed, displayKey } = generateApiKey('ev');

    expect(parseApiKey(displayKey, 'ev')).toEqual(seed);
  });

  it('rejects a key whose prefix does not match', () => {
    const { displayKey } = generateApiKey('event');

    expect(() => parseApiKey(displayKey, 'ev')).toThrow(new Error('invalid key format'));
    expect(() => parseApiKey('no-separator', 'ev')).toThrow(new Error('invalid key format'));
  });

  it('rejects a secret that does not decode to 32 bytes', () => {
    expect(() => parseApiKey('ev_YQ', 'ev')).toThrow(new Error('invalid key length'));
  });

  it('rejects a secret that is not base64url', () => {
    expect(() => parseApiKey('ev_A', 'ev')).toThrow(
      new Error('fromBase64Url: invalid base64url length (1)'),
    );
    expect(() => parseApiKey('ev_!!!!', 'ev')).toThrow('Invalid character');
  });
});
