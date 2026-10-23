/**
 * Generate cryptographically secure random bytes using the Web Crypto API.
 * @param length - The number of random bytes to generate. Must be a positive
 *  integer no greater than 65536 (the [Web Crypto API's per-call limit](
 *  https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#exceptions)).
 * @returns A Uint8Array<ArrayBuffer> of `length` random bytes.
 * @throws {RangeError} If length is not a positive integer, or exceeds 65536.
 */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError(`randomBytes: length must be a positive integer, got ${length}`);
  }
  if (length > 65536) {
    throw new RangeError(`randomBytes: length ${length} exceeds the 65536-byte Web Crypto limit`);
  }
  return crypto.getRandomValues(new Uint8Array(length));
}
