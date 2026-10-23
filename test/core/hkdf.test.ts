import { describe, expect, it } from 'vitest';
import { HASH_BYTES, HKDF_INFO, KEK_BYTES, MAX_INFO_BYTES, SALT_BYTES, SEED_BYTES } from '../../src/core/constants.js';
import { fromHex } from '../../src/core/encoding.js';
import { hkdf } from '../../src/core/hkdf.js';

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
const seed = bytes(SEED_BYTES, 0x0b);
const salt = Uint8Array.from({ length: SALT_BYTES }, (_, index) => index);
const info = new TextEncoder().encode('envelock');

describe('hkdf', () => {
  it('matches HKDF for SHA-256, SHA-384, and SHA-512', async () => {
    await expect(hkdf(salt, seed, info, 'SHA-256', 256)).resolves.toEqual(
      fromHex('2205e3fbe3fb7d2d0a292d3a68ef8635cf77896298856cc421bf65f5972d7866'),
    );
    await expect(hkdf(salt, seed, info, 'SHA-384', 384)).resolves.toEqual(
      fromHex('c0246202cd23d20876b6253dc4ec4415e301c5b89d39773c9efe3814ed77ab9598dd5e6d55449d1f6e1997689197d082'),
    );
    await expect(hkdf(salt, seed, info, 'SHA-512', 512)).resolves.toEqual(
      fromHex('b8c63588476d10adb72f23f3c026845277aa80dda891ab391060d28161000ee9466c0e8519614fe614c58aab5841e4e436d1742f8d8901553a713859ea1d5a7d'),
    );
  });

  it('treats length as bits', async () => {
    const derived = await hkdf(salt, seed, info, 'SHA-256', 128);

    expect(derived).toEqual(fromHex('2205e3fbe3fb7d2d0a292d3a68ef8635'));
  });

  it('accepts an empty salt', async () => {
    const derived = await hkdf(new Uint8Array(), seed, info, 'SHA-256', 256);

    expect(derived).toEqual(fromHex('c68a893f332b954e147e1b20843f2cf0bac9bc1f2e489c1f7bedd255bb3fa487'));
  });

  it('changes the output when salt, seed, info, or hash changes', async () => {
    const original = await hkdf(salt, seed, info, 'SHA-256', KEK_BYTES * 8);
    const otherSalt = await hkdf(bytes(SALT_BYTES, 1), seed, info, 'SHA-256', KEK_BYTES * 8);
    const otherSeed = await hkdf(salt, bytes(SEED_BYTES, 1), info, 'SHA-256', KEK_BYTES * 8);
    const otherInfo = await hkdf(salt, seed, new Uint8Array([1]), 'SHA-256', KEK_BYTES * 8);
    const otherHash = await hkdf(salt, seed, info, 'SHA-512', KEK_BYTES * 8);

    expect(Array.from(original)).not.toEqual(Array.from(otherSalt));
    expect(Array.from(original)).not.toEqual(Array.from(otherSeed));
    expect(Array.from(original)).not.toEqual(Array.from(otherInfo));
    expect(Array.from(original)).not.toEqual(Array.from(otherHash));
  });

  it('accepts info at the 64-byte limit and length at the hash limit', async () => {
    const atInfoLimit = await hkdf(salt, seed, bytes(MAX_INFO_BYTES, 2), 'SHA-256', KEK_BYTES * 8);
    const maxBits = 255 * HASH_BYTES['SHA-256'] * 8;
    const atLengthLimit = await hkdf(salt, seed, info, 'SHA-256', maxBits);

    expect(atInfoLimit).toHaveLength(KEK_BYTES);
    expect(atLengthLimit).toHaveLength(maxBits / 8);
  });

  it('keeps distinct HKDF info labels', () => {
    expect(HKDF_INFO).toEqual({
      SIGNING_SEED: 'signing-v1',
      KEK_SEED: 'kek-v1',
      ITEM_KEK_PREFIX: 'kek-item-v1:',
    });
  });

  it('rejects salt, seed, info, and length outside the documented bounds', async () => {
    const shortSalt = bytes(SALT_BYTES - 1, 0);
    const maxBits = 255 * HASH_BYTES['SHA-384'] * 8;

    await expect(hkdf(shortSalt, seed, info, 'SHA-256', KEK_BYTES * 8)).rejects.toThrow(
      `salt must be empty or ${SALT_BYTES} bytes, got ${shortSalt.length}`,
    );
    await expect(hkdf(salt, bytes(SEED_BYTES - 1, 0), info, 'SHA-256', KEK_BYTES * 8)).rejects.toThrow(
      `seed must be ${SEED_BYTES} bytes`,
    );
    await expect(hkdf(salt, seed, new Uint8Array(), 'SHA-256', KEK_BYTES * 8)).rejects.toThrow(
      'info must not be empty — domain separation requires a non-empty label',
    );
    await expect(hkdf(salt, seed, bytes(MAX_INFO_BYTES + 1, 0), 'SHA-256', KEK_BYTES * 8)).rejects.toThrow(
      `info must be less than or equal to ${MAX_INFO_BYTES} bytes`,
    );
    await expect(hkdf(salt, seed, info, 'SHA-256', 7)).rejects.toThrow(
      'length must be a positive multiple of 8, got 7',
    );
    await expect(hkdf(salt, seed, info, 'SHA-384', maxBits + 8)).rejects.toThrow(
      `length must be less than or equal to ${maxBits} bits, got ${maxBits + 8}`,
    );
  });
});
