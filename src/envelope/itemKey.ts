import { hkdf } from "../core/hkdf.js";
import { encode } from "../core/encoding.js";
import { DEK_BYTES, HKDF_INFO, KEK_BYTES } from "../core/constants.js";
import { randomBytes } from "../core/random.js";

/**
 * Derive an item KEK from an item salt, KEK seed, and item UUID.
 * @param itemSalt - The item salt.
 * @param kekSeed - The KEK seed.
 * @param itemUuid - The item UUID.
 * @returns The derived item KEK.
 */
async function deriveItemKek(
  itemSalt: Uint8Array<ArrayBuffer>,
  kekSeed: Uint8Array<ArrayBuffer>,
  itemUuid: string
): Promise<Uint8Array<ArrayBuffer>> {
  return await hkdf(itemSalt, kekSeed, encode(HKDF_INFO.ITEM_KEK_PREFIX + itemUuid), "SHA-256", KEK_BYTES * 8);
}

/**
 * Generate a random UUID.
 * @returns A random UUID.
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Generate a random DEK.
 * @returns A random DEK.
 */
function generateDEK(): Uint8Array<ArrayBuffer> {
  return randomBytes(DEK_BYTES);
}

export { deriveItemKek, generateUUID, generateDEK };