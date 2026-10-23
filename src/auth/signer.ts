import { buildCanonicalString } from "./canonicalRequest.js";
import { signEd25519 } from "../identity/ed25519.js";
import { toHex } from "../core/encoding.js";
import { ENVELOCK_AUTH_HEADER, ENVELOCK_NONCE_HEADER, ENVELOCK_TIMESTAMP_HEADER } from "../core/constants.js";
import { generateNonce } from "./nonce.js";

/**
 * Sign a request and return the signed request.
 * @param request - The request to sign.
 * @param privateKey - The private key to use for signing.
 * @returns The signed request.
 * @throws {Error} If the timestamp or nonce is not present.
 * @throws {Error} If the canonical string is not present.
 * @throws {Error} If the signature is not present.
 * @throws {Error} If the request is not a valid request.
 * @throws {Error} If the private key is not a valid private key.
 * @throws {Error} If the public key is not a valid public key.
 * @throws {Error} If the signature is not a valid signature.
 * @throws {Error} If the request is not a valid request.
 */
export async function signRequest(request: Request, privateKey: Uint8Array<ArrayBuffer>): Promise<Request> {
  request.headers.set(ENVELOCK_TIMESTAMP_HEADER, Date.now().toString());
  request.headers.set(ENVELOCK_NONCE_HEADER, generateNonce());
  const canonicalString = await buildCanonicalString(request);
  const signature = signEd25519(privateKey, new TextEncoder().encode(canonicalString));
  request.headers.set(ENVELOCK_AUTH_HEADER, toHex(signature));
  return request;
}