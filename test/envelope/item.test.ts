import { describe, expect, it } from 'vitest';
import { DEK_BYTES, IV_BYTES, KEK_BYTES, SALT_BYTES } from '../../src/core/constants.js';
import { decryptDEK, decryptItem } from '../../src/envelope/decrypt.js';
import { encryptDEK, encryptItem } from '../../src/envelope/encrypt.js';

const plaintext = new TextEncoder().encode('secret item');
const kekSeed = new Uint8Array(KEK_BYTES).fill(4);

describe('encryptItem and decryptItem', () => {
  it('round-trips an item under its KEK seed', async () => {
    const encrypted = await encryptItem({ plaintext, kekSeed });
    const decrypted = await decryptItem({ ...encrypted, kekSeed });

    expect(encrypted.itemSalt).toHaveLength(SALT_BYTES);
    expect(encrypted.itemUuid).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(encrypted.blob.length).toBeGreaterThan(IV_BYTES);
    expect(encrypted.encryptedDEK.length).toBeGreaterThan(IV_BYTES);
    expect(decrypted).toEqual(plaintext);
  });

  it('rejects empty plaintext or a KEK seed of the wrong size', async () => {
    await expect(encryptItem({ plaintext: new Uint8Array(), kekSeed })).rejects.toThrow(
      'plaintext must not be empty',
    );
    await expect(encryptItem({ plaintext, kekSeed: new Uint8Array(KEK_BYTES - 1) })).rejects.toThrow(
      `kekSeed must be ${KEK_BYTES} bytes`,
    );
  });

  it('rejects decrypt inputs that are the wrong size', async () => {
    const encrypted = await encryptItem({ plaintext, kekSeed });

    await expect(decryptItem({ ...encrypted, kekSeed: new Uint8Array(KEK_BYTES - 1) })).rejects.toThrow(
      `kekSeed must be ${KEK_BYTES} bytes`,
    );
    await expect(decryptItem({ ...encrypted, kekSeed, itemSalt: new Uint8Array(SALT_BYTES - 1) })).rejects.toThrow(
      `itemSalt must be ${SALT_BYTES} bytes`,
    );
    await expect(decryptItem({ ...encrypted, kekSeed, blob: new Uint8Array(IV_BYTES - 1) })).rejects.toThrow(
      `blob must be at least ${IV_BYTES} bytes`,
    );
    await expect(decryptItem({ ...encrypted, kekSeed, encryptedDEK: new Uint8Array(IV_BYTES - 1) })).rejects.toThrow(
      `encryptedDEK must be at least ${IV_BYTES} bytes`,
    );
  });

  it('rejects a changed item UUID, KEK seed, or ciphertext', async () => {
    const encrypted = await encryptItem({ plaintext, kekSeed });
    const tampered = new Uint8Array(encrypted.blob);
    tampered[tampered.length - 1] ^= 0x01;

    await expect(decryptItem({ ...encrypted, kekSeed, itemUuid: '22222222-2222-4222-8222-222222222222' })).rejects.toThrow();
    await expect(decryptItem({ ...encrypted, kekSeed: new Uint8Array(KEK_BYTES).fill(9) })).rejects.toThrow();
    await expect(decryptItem({ ...encrypted, kekSeed, blob: tampered })).rejects.toThrow();
  });

  it('rejects an empty item UUID', async () => {
    const encrypted = await encryptItem({ plaintext, kekSeed });

    await expect(decryptItem({ ...encrypted, kekSeed, itemUuid: '' })).rejects.toThrow(
      'itemUuid must be a non-empty string',
    );
  });
});

describe('encryptDEK and decryptDEK', () => {
  const dek = new Uint8Array(DEK_BYTES).fill(3);
  const itemSalt = new Uint8Array(SALT_BYTES).fill(5);
  const itemUuid = '11111111-1111-4111-8111-111111111111';

  it('round-trips a DEK under the item KEK', async () => {
    const encryptedDEK = await encryptDEK({ dek, kekSeed, itemSalt, itemUuid });

    expect(encryptedDEK.length).toBeGreaterThan(IV_BYTES);
    expect(await decryptDEK({ itemUuid, itemSalt, encryptedDEK, kekSeed })).toEqual(dek);
  });

  it('rejects an empty UUID or a DEK, salt, or KEK seed of the wrong size', async () => {
    await expect(encryptDEK({ dek, kekSeed, itemSalt, itemUuid: '' })).rejects.toThrow(
      'itemUuid must be a non-empty string',
    );
    await expect(encryptDEK({ dek: new Uint8Array(DEK_BYTES - 1), kekSeed, itemSalt, itemUuid })).rejects.toThrow(
      `dek must be ${DEK_BYTES} bytes`,
    );
    await expect(encryptDEK({ dek, kekSeed, itemSalt: new Uint8Array(SALT_BYTES - 1), itemUuid })).rejects.toThrow(
      `itemSalt must be ${SALT_BYTES} bytes`,
    );
    await expect(decryptDEK({
      itemUuid,
      itemSalt,
      encryptedDEK: new Uint8Array(IV_BYTES - 1),
      kekSeed,
    })).rejects.toThrow(`encryptedDEK must be at least ${IV_BYTES} bytes`);
  });
});
