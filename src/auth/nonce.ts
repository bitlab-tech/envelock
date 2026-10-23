import { generateUUID } from "../envelope/itemKey.js";

/**
 * Generate a random nonce (16 bytes).
 * @returns A random UUID (36 characters).
 */
export function generateNonce(): string {
  return generateUUID();
}