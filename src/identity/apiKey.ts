import { SALT_BYTES, SEED_BYTES } from "../core/constants.js";
import { fromBase64Url, toBase64Url } from "../core/encoding.js";
import { generateMainSeed, generateSalt } from "./keygen.js";

/**
 * Generate an API key and return the seed, salt, and display key.
 * @param prefix - The prefix of the display key.
 * @returns The seed, salt, and display key.
 */
function generateApiKey(
  prefix: string
): { seed: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, displayKey: string } {
  const seed = generateMainSeed();
  const salt = generateSalt();
  const combined = new Uint8Array(seed.length + salt.length);
  combined.set(seed, 0);
  combined.set(salt, seed.length);
  const displayKey = (prefix ? `${prefix}_` : "") + toBase64Url(combined);
  return { seed, salt, displayKey };
}

/**
 * Parse an API key and return the seed and salt.
 * @param displayKey - The display key to parse.
 * @param prefix - The prefix of the display key.
 * @returns The seed and salt.
 * @throws {Error} If the display key is invalid.
 */
function parseApiKey(
  displayKey: string,
  prefix: string
): { seed: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer> } {
  const prefixString = prefix ? `${prefix}_` : "";
  if (!displayKey.startsWith(prefixString)) throw new Error("invalid key format");
  const combined = fromBase64Url(displayKey.slice(prefixString.length));
  if (combined.length !== SEED_BYTES + SALT_BYTES) throw new Error("invalid key length");
  return { seed: combined.slice(0, SEED_BYTES), salt: combined.slice(SEED_BYTES) };
}

export { generateApiKey, parseApiKey };