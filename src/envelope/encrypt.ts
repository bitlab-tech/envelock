import { aesGcmEncrypt } from "../core/aes.js";
import { DEK_BYTES, KEK_BYTES, SALT_BYTES } from "../core/constants.js";
import { encode } from "../core/encoding.js";
import { generateSalt } from "../identity/keygen.js";
import { EncryptedItem } from "../types.js";
import { deriveItemKek, generateDEK, generateUUID } from "./itemKey.js";

/**
 * Encrypt a DEK using AES-GCM.
 * @param encryptData - The data to use for the encryption.
 * @returns The encrypted DEK blob.
 */
async function encryptDEK(encryptData: {
  dek: Uint8Array<ArrayBuffer>,
  kekSeed: Uint8Array<ArrayBuffer>,
  itemSalt: Uint8Array<ArrayBuffer>,
  itemUuid: string,
}): Promise<Uint8Array<ArrayBuffer>> {
  const { dek, kekSeed, itemSalt, itemUuid } = encryptData;
  if (dek.length !== DEK_BYTES) throw new Error(`dek must be ${DEK_BYTES} bytes`);
  if (kekSeed.length !== KEK_BYTES) throw new Error(`kekSeed must be ${KEK_BYTES} bytes`);
  if (itemSalt.length !== SALT_BYTES) throw new Error(`itemSalt must be ${SALT_BYTES} bytes`);
  if (itemUuid.length === 0) throw new Error(`itemUuid must be a non-empty string`);
  const itemKek = await deriveItemKek(itemSalt, kekSeed, itemUuid);
  const aad = encode(itemUuid);
  return await aesGcmEncrypt(dek, itemKek, aad);
}

/**
 * Encrypt a plaintext using AES-GCM.
 * @param encryptData - The data to use for the encryption.
 * @returns The encrypted item.
 */
async function encryptItem(encryptData: {
  plaintext: Uint8Array<ArrayBuffer>,
  kekSeed: Uint8Array<ArrayBuffer>
}): Promise<EncryptedItem> {
  const { plaintext, kekSeed } = encryptData;
  if (plaintext.length === 0) throw new Error(`plaintext must not be empty`);
  if (kekSeed.length !== KEK_BYTES) throw new Error(`kekSeed must be ${KEK_BYTES} bytes`);
  const itemSalt = generateSalt();
  const itemUuid = generateUUID();
  const itemKek = await deriveItemKek(itemSalt, kekSeed, itemUuid);
  const dek = generateDEK();
  const aad = encode(itemUuid);
  const blob = await aesGcmEncrypt(plaintext, dek, aad);
  const encryptedDEK = await aesGcmEncrypt(dek, itemKek, aad);
  return { blob, itemSalt, itemUuid, encryptedDEK };
}

export { encryptDEK, encryptItem };