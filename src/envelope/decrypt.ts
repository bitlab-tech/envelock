import { aesGcmDecrypt } from "../core/aes.js";
import { SALT_BYTES, KEK_BYTES, IV_BYTES } from "../core/constants.js";
import { encode } from "../core/encoding.js";
import { deriveItemKek } from "./itemKey.js";

/**
 * Decrypt a DEK using AES-GCM.
 * @param decryptData - The data to use for the decryption.
 * @returns The decrypted DEK as an Uint8Array<ArrayBuffer>.
 */
async function decryptDEK(decryptData: {
  itemUuid: string,
  itemSalt: Uint8Array<ArrayBuffer>,
  encryptedDEK: Uint8Array<ArrayBuffer>,
  kekSeed: Uint8Array<ArrayBuffer>,
}): Promise<Uint8Array<ArrayBuffer>> {
  const { itemUuid, itemSalt, encryptedDEK, kekSeed } = decryptData;
  if (itemUuid.length === 0) throw new Error(`itemUuid must be a non-empty string`);
  if (itemSalt.length !== SALT_BYTES) throw new Error(`itemSalt must be ${SALT_BYTES} bytes`);
  if (encryptedDEK.length < IV_BYTES) throw new Error(`encryptedDEK must be at least ${IV_BYTES} bytes`);
  if (kekSeed.length !== KEK_BYTES) throw new Error(`kekSeed must be ${KEK_BYTES} bytes`);
  const itemKek = await deriveItemKek(itemSalt, kekSeed, itemUuid);
  const aad = encode(itemUuid);
  return await aesGcmDecrypt(encryptedDEK, itemKek, aad);
}

/**
 * Decrypt a ciphertext using AES-GCM.
 * @param decryptData - The data to use for the decryption.
 * @returns The decrypted plaintext as an Uint8Array<ArrayBuffer>.
 */
async function decryptItem(decryptData: {
  itemUuid: string,
  itemSalt: Uint8Array<ArrayBuffer>,
  encryptedDEK: Uint8Array<ArrayBuffer>,
  blob: Uint8Array<ArrayBuffer>,
  kekSeed: Uint8Array<ArrayBuffer>,
}): Promise<Uint8Array<ArrayBuffer>> {
  const { itemUuid, itemSalt, encryptedDEK, blob, kekSeed } = decryptData;
  if (itemUuid.length === 0) throw new Error(`itemUuid must be a non-empty string`);
  if (itemSalt.length !== SALT_BYTES) throw new Error(`itemSalt must be ${SALT_BYTES} bytes`);
  if (encryptedDEK.length < IV_BYTES) throw new Error(`encryptedDEK must be at least ${IV_BYTES} bytes`);
  if (blob.length < IV_BYTES) throw new Error(`blob must be at least ${IV_BYTES} bytes`);
  if (kekSeed.length !== KEK_BYTES) throw new Error(`kekSeed must be ${KEK_BYTES} bytes`);
  const itemKek = await deriveItemKek(itemSalt, kekSeed, itemUuid);
  const aad = encode(itemUuid);
  const dek = await aesGcmDecrypt(encryptedDEK, itemKek, aad);
  return await aesGcmDecrypt(blob, dek, aad);
}

export { decryptDEK, decryptItem };