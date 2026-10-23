/**
 * A record that contains the secret key and public key.
 * This is used to store the Ed25519 key pair.
 */
type Ed25519KeyPair = {
  secretKey: Uint8Array<ArrayBuffer>;
  publicKey: Uint8Array<ArrayBuffer>;
}

/**
 * A record that contains the item UUID, item salt, and encrypted DEK.
 * This is used to store the wrapped DEKs for a given encrypted item.
 */
type WrappedDekRecord = {
  itemUuid: string;
  itemSalt: Uint8Array<ArrayBuffer>;
  encryptedDEK: Uint8Array<ArrayBuffer>;
}

/**
 * A record that contains the blob, item salt, item UUID, and encrypted DEK.
 * This is used to store the encrypted item.
 */
type EncryptedItem = WrappedDekRecord & {
  blob: Uint8Array<ArrayBuffer>;
}

export type { Ed25519KeyPair, WrappedDekRecord, EncryptedItem };