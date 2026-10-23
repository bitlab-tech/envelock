import { HKDF_INFO, SALT_BYTES, SEED_BYTES } from '../core/constants.js';
import { encode } from '../core/encoding.js';
import { hkdf } from '../core/hkdf.js';
import { randomBytes } from '../core/random.js';

/**
 * Generate a main seed.
 * @returns A random seed.
 */
function generateMainSeed(): Uint8Array<ArrayBuffer> {
  return randomBytes(SEED_BYTES);
}

/**
 * Generate a salt.
 * @returns A random salt.
 */
function generateSalt(): Uint8Array<ArrayBuffer> {
  return randomBytes(SALT_BYTES);
}

/**
 * Derive a signing seed from a main salt and main seed.
 * @param mainSalt - The main salt.
 * @param mainSeed - The main seed.
 * @returns The derived signing seed.
 */
async function deriveSigningSeed(
  mainSalt: Uint8Array<ArrayBuffer>,
  mainSeed: Uint8Array<ArrayBuffer>
): Promise<Uint8Array<ArrayBuffer>> {
  return await hkdf(mainSalt, mainSeed, encode(HKDF_INFO.SIGNING_SEED), "SHA-256", SEED_BYTES * 8);
}

/**
 * Derive a KEK seed from a main salt and main seed.
 * @param mainSalt - The main salt.
 * @param mainSeed - The main seed.
 * @returns The derived KEK seed.
 */
async function deriveKekSeed(
  mainSalt: Uint8Array<ArrayBuffer>,
  mainSeed: Uint8Array<ArrayBuffer>
): Promise<Uint8Array<ArrayBuffer>> {
  return await hkdf(mainSalt, mainSeed, encode(HKDF_INFO.KEK_SEED), "SHA-256", SEED_BYTES * 8);
}

export {
  generateMainSeed,
  generateSalt,
  deriveSigningSeed,
  deriveKekSeed
};
