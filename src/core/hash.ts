import { HashFunction } from "./constants.js";

/**
 * Compute the hash of a message and return the result as a Uint8Array<ArrayBuffer>.
 * @param message - The message to hash.
 * @param hashFunction - The hash function to use. Must be "SHA-256", "SHA-384", or "SHA-512".
 * @returns The hash of the message as a Uint8Array<ArrayBuffer>.
 */
export async function hash(
  message: Uint8Array<ArrayBuffer> | string,
  hashFunction: HashFunction
): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const digest = await crypto.subtle.digest(hashFunction, bytes);
  return new Uint8Array(digest);
}