import { AES_GCM_KEY_BYTES, IV_BYTES } from "./constants.js";
import { randomBytes } from "./random.js";

/**
 * Encrypt a plaintext using AES-GCM.
 * @param plaintext - The plaintext to encrypt.
 * @param key - The key to use for the encryption.
 * @param aad - The additional data to use for the encryption.
 * @returns The blob that contains the IV and ciphertext.
 */
async function aesGcmEncrypt(
  plaintext: Uint8Array<ArrayBuffer>,
  key: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (key.length !== AES_GCM_KEY_BYTES) throw new Error(`key must be ${AES_GCM_KEY_BYTES} bytes`);
  const iv = randomBytes(IV_BYTES);
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    cryptoKey,
    plaintext,
  ));
  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return out;
}

/**
 * Decrypt a ciphertext using AES-GCM.
 * @param blob - The blob that contains the IV and ciphertext.
 * @param key - The key to use for the decryption.
 * @param aad - The additional data to use for the decryption.
 * @returns The decrypted plaintext as an Uint8Array<ArrayBuffer>.
 */
async function aesGcmDecrypt(
  blob: Uint8Array<ArrayBuffer>,
  key: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (blob.length < IV_BYTES) throw new Error(`blob must be at least ${IV_BYTES} bytes`);
  if (key.length !== AES_GCM_KEY_BYTES) throw new Error(`key must be ${AES_GCM_KEY_BYTES} bytes`);
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const iv = blob.slice(0, IV_BYTES);
  const ciphertext = blob.slice(IV_BYTES);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    cryptoKey,
    ciphertext
  ));
  return plaintext;
}

export { aesGcmEncrypt, aesGcmDecrypt };