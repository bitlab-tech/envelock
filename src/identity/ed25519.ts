import { ED25519_KEY_BYTES, ED25519_SIGNATURE_BYTES, SEED_BYTES } from "../core/constants.js";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from '@noble/hashes/sha2.js';
import { Ed25519KeyPair } from "../types.js";
ed25519.hashes.sha512 = sha512;

/**
 * Generate an Ed25519 key pair from a signing seed.
 * @param signingSeed 
 * @returns The Ed25519 key pair.
 * @throws {Error} If the signing seed is not the correct length.
 */
async function generateEd25519KeyPair(
  signingSeed: Uint8Array<ArrayBuffer>
): Promise<Ed25519KeyPair> {
  if (signingSeed.length !== SEED_BYTES) {
    throw new Error(`Signing seed must be ${SEED_BYTES} bytes`);
  }
  return ed25519.keygen(signingSeed);
}

/**
 * Sign a message with an Ed25519 secret key.
 * @param secretKey - The secret key to sign the message with.
 * @param message - The message to sign.
 * @returns The signature.
 * @throws {Error} If the secret key is not the correct length.
 */
function signEd25519(
  secretKey: Uint8Array<ArrayBuffer>,
  message: Uint8Array<ArrayBuffer>
): Uint8Array<ArrayBuffer> {
  if (secretKey.length !== ED25519_KEY_BYTES) {
    throw new Error(`Secret key must be ${ED25519_KEY_BYTES} bytes`);
  }
  return ed25519.sign(message, secretKey);
}

/**
 * Verify an Ed25519 signature.
 * @param publicKey - The public key to verify the signature with.
 * @param message - The message to verify.
 * @param signature - The signature to verify.
 * @returns True if the signature is valid, false otherwise.
 * @throws {Error} If the public key is not the correct length.
 */
function verifyEd25519(
  publicKey: Uint8Array<ArrayBuffer>,
  message: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>
): boolean {
  if (publicKey.length !== ED25519_KEY_BYTES) {
    throw new Error(`Public key must be ${ED25519_KEY_BYTES} bytes`);
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new Error(`Signature must be ${ED25519_SIGNATURE_BYTES} bytes`);
  }
  return ed25519.verify(signature, message, publicKey);
}

export { generateEd25519KeyPair, signEd25519, verifyEd25519 };