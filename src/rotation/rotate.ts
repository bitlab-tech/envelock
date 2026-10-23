import { decryptDEK } from "../envelope/decrypt.js";
import { encryptDEK } from "../envelope/encrypt.js";
import { WrappedDekRecord } from "../types.js";

/**
 * Rotate the wrapped DEKs for a given set of encrypted items.
 * @param wrappedDekRecords - The wrapped DEK records to rotate.
 * @param oldKekSeed - The old KEK seed.
 * @param newKekSeed - The new KEK seed.
 * @returns The new wrapped DEK records.
 */
async function rotate(
  wrappedDekRecords: WrappedDekRecord[],
  oldKekSeed: Uint8Array<ArrayBuffer>,
  newKekSeed: Uint8Array<ArrayBuffer>,
): Promise<WrappedDekRecord[]> {
  const newWrappedDekRecords: WrappedDekRecord[] = [];
  for (const wrappedDekRecord of wrappedDekRecords) {
    const decryptedDEK = await decryptDEK({
      itemUuid: wrappedDekRecord.itemUuid,
      itemSalt: wrappedDekRecord.itemSalt,
      encryptedDEK: wrappedDekRecord.encryptedDEK,
      kekSeed: oldKekSeed,
    });
    const encryptedWrappedDek = await encryptDEK({
      itemUuid: wrappedDekRecord.itemUuid,
      itemSalt: wrappedDekRecord.itemSalt,
      dek: decryptedDEK,
      kekSeed: newKekSeed,
    });
    newWrappedDekRecords.push({
      itemUuid: wrappedDekRecord.itemUuid,
      itemSalt: wrappedDekRecord.itemSalt,
      encryptedDEK: encryptedWrappedDek,
    });
  }
  return newWrappedDekRecords;
}

export { rotate };