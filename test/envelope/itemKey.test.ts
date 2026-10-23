import { describe, expect, it, vi } from 'vitest';
import { DEK_BYTES, HKDF_INFO, KEK_BYTES, SALT_BYTES, SEED_BYTES } from '../../src/core/constants.js';
import { encode } from '../../src/core/encoding.js';
import { hkdf } from '../../src/core/hkdf.js';
import { deriveItemKek, generateDEK, generateUUID } from '../../src/envelope/itemKey.js';

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);

describe('item key material', () => {
  it('returns a DEK of the configured size', () => {
    expect(generateDEK()).toHaveLength(DEK_BYTES);
  });

  it('returns a UUID from crypto.randomUUID', () => {
    const spy = vi.spyOn(crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111');

    expect(generateUUID()).toBe('11111111-1111-4111-8111-111111111111');
    expect(spy).toHaveBeenCalledOnce();

    spy.mockRestore();
  });

  it('derives an item KEK from the KEK seed, item salt, and item UUID', async () => {
    const kekSeed = bytes(SEED_BYTES, 0x0b);
    const itemSalt = bytes(SALT_BYTES, 3);
    const itemUuid = '11111111-1111-4111-8111-111111111111';
    const derived = await deriveItemKek(itemSalt, kekSeed, itemUuid);

    expect(derived).toHaveLength(KEK_BYTES);
    expect(derived).toEqual(
      await hkdf(
        itemSalt,
        kekSeed,
        encode(HKDF_INFO.ITEM_KEK_PREFIX + itemUuid),
        'SHA-256',
        KEK_BYTES * 8,
      ),
    );
    expect(Array.from(derived)).not.toEqual(
      Array.from(await deriveItemKek(itemSalt, kekSeed, '22222222-2222-4222-8222-222222222222')),
    );
  });
});
