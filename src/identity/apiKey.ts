import { SEED_BYTES } from "../core/constants.js";
import { fromBase64Url, toBase64Url } from "../core/encoding.js";
import { generateMainSeed } from "./keygen.js";

/**
 * Generate an API key and return the seed and display key.
 * @param prefix - The prefix of the display key.
 * @returns The seed and display key.
 */
function generateApiKey(prefix: string): { seed: Uint8Array<ArrayBuffer>, displayKey: string } {
  const prefixString = prefix ? `${prefix}_` : "";
  const seed = generateMainSeed();
  const displayKey = prefixString + toBase64Url(seed);
  return { seed, displayKey };
}

/**
 * Parse an API key and return the seed.
 * @param displayKey - The display key to parse.
 * @param prefix - The prefix of the display key.
 * @returns The seed.
 * @throws {Error} If the display key is invalid.
 */
function parseApiKey(displayKey: string, prefix: string): Uint8Array<ArrayBuffer> {
  const prefixString = prefix ? `${prefix}_` : "";
  if (!displayKey.startsWith(prefixString)) {
    throw new Error("invalid key format");
  }
  const secretPart = displayKey.slice(prefixString.length);
  const seed = fromBase64Url(secretPart);
  if (seed.length !== SEED_BYTES) {
    throw new Error("invalid key length");
  }
  return seed;
}

export { generateApiKey, parseApiKey };