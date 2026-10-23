import { SALT_BYTES, SEED_BYTES, MAX_INFO_BYTES, HashFunction, HASH_BYTES } from "./constants.js";

/**
 * Derive a key using the HKDF algorithm.
 * @param salt - The salt to use for the HKDF derivation. Must be 32 bytes.
 * @param seed - The seed to use for the HKDF derivation. Must be 32 bytes.
 * @param info - The info to use for the HKDF derivation. Must be less than or equal to 64 bytes.
 * @param hash - The hash function to use. Must be "SHA-256", "SHA-384", or "SHA-512".
 *  The hash determines the maximum derivable length (see `length` below) but
 *  otherwise doesn't constrain which output sizes are valid.
 * @param length - The length of the key to derive in bits. Must be a multiple of 8 and less than
 *  or equal to `255*HashLen` per [RFC 5869](https://www.rfc-editor.org/info/rfc5869).
 * @returns The derived key.
 */
async function hkdf(
  salt: Uint8Array<ArrayBuffer>,
  seed: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
  hash: HashFunction,
  length: number
): Promise<Uint8Array<ArrayBuffer>> {
  if (salt.length !== 0 && salt.length !== SALT_BYTES) {
    throw new Error(`salt must be empty or ${SALT_BYTES} bytes, got ${salt.length}`);
  }
  if (seed.length !== SEED_BYTES) {
    throw new Error(`seed must be ${SEED_BYTES} bytes`);
  }
  if (info.length === 0) {
    throw new Error("info must not be empty — domain separation requires a non-empty label");
  }
  if (info.length > MAX_INFO_BYTES) {
    throw new Error(`info must be less than or equal to ${MAX_INFO_BYTES} bytes`);
  }
  if (!Number.isInteger(length) || length <= 0 || length % 8 !== 0) {
    throw new Error(`length must be a positive multiple of 8, got ${length}`);
  }
  const maxLengthBits = 255 * HASH_BYTES[hash] * 8;
  if (length > maxLengthBits) {
    throw new Error(`length must be less than or equal to ${maxLengthBits} bits, got ${length}`);
  }

  const seedKey = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
  const keyBits = await crypto.subtle.deriveBits(
    { name: "HKDF", salt, info, hash },
    seedKey,
    length,
  );
  return new Uint8Array(keyBits);
}

export { hkdf };