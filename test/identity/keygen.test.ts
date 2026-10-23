import { describe, expect, it } from 'vitest';
import { HKDF_INFO, SALT_BYTES, SEED_BYTES } from '../../src/core/constants.js';
import { encode } from '../../src/core/encoding.js';
import { hkdf } from '../../src/core/hkdf.js';
import { deriveKekSeed, deriveSigningSeed, generateMainSeed, generateSalt } from '../../src/identity/keygen.js';

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
const mainSeed = bytes(SEED_BYTES, 0x0b);
const mainSalt = Uint8Array.from({ length: SALT_BYTES }, (_, index) => index);

describe('random identity material', () => {
  it('uses the seed and salt sizes', () => {
    expect(generateMainSeed()).toHaveLength(SEED_BYTES);
    expect(generateSalt()).toHaveLength(SALT_BYTES);
  });
});

describe('derived identity keys', () => {
  it('derives the signing seed with the signing label', async () => {
    const derived = await deriveSigningSeed(mainSalt, mainSeed);

    expect(derived).toHaveLength(SEED_BYTES);
    expect(derived).toEqual(
      await hkdf(mainSalt, mainSeed, encode(HKDF_INFO.SIGNING_SEED), 'SHA-256', SEED_BYTES * 8),
    );
  });

  it('derives the KEK seed with the KEK label', async () => {
    const derived = await deriveKekSeed(mainSalt, mainSeed);

    expect(derived).toHaveLength(SEED_BYTES);
    expect(derived).toEqual(
      await hkdf(mainSalt, mainSeed, encode(HKDF_INFO.KEK_SEED), 'SHA-256', SEED_BYTES * 8),
    );
    expect(Array.from(derived)).not.toEqual(Array.from(await deriveSigningSeed(mainSalt, mainSeed)));
  });
});
