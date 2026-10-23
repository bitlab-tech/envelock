import { hash } from "../core/hash.js";
import { ENVELOCK_NONCE_HEADER, ENVELOCK_TIMESTAMP_HEADER } from "../core/constants.js";
import { toHex } from "../core/encoding.js";

/**
 * Build the canonical string for a request.
 * @param request - The request to build the canonical string for.
 * @returns The canonical string.
 * @throws {Error} If the method, path, timestamp, or nonce is not present.
 */
export async function buildCanonicalString(request: Request): Promise<string> {
  const { method, headers } = request;
  if (!method) {
    throw new Error("Method is required");
  }
  const url = new URL(request.url);
  const path = url.pathname + url.search;
  if (!path) {
    throw new Error("Path is required");
  }
  const timestamp = headers.get(ENVELOCK_TIMESTAMP_HEADER);
  if (!timestamp) {
    throw new Error("Timestamp header is required");
  }
  const nonce = headers.get(ENVELOCK_NONCE_HEADER);
  if (!nonce) {
    throw new Error("Nonce header is required");
  }
  const bodyBytes = new Uint8Array(await request.clone().arrayBuffer());
  const bodyHash = toHex(await hash(bodyBytes, "SHA-256"));
  return `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`; 
}