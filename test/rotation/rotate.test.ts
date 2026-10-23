import { describe, expect, it } from 'vitest';
import { KEK_BYTES } from '../../src/core/constants.js';
import { decryptItem } from '../../src/envelope/decrypt.js';
import { encryptItem } from '../../src/envelope/encrypt.js';
import { rotate } from '../../src/rotation/rotate.js';

const plaintext = new TextEncoder().encode('secret item');
const oldKekSeed = new Uint8Array(KEK_BYTES).fill(4);
const newKekSeed = new Uint8Array(KEK_BYTES).fill(9);

describe('rotate', () => {
  it('returns an empty list when there are no items', async () => {
    await expect(rotate([], oldKekSeed, newKekSeed)).resolves.toEqual([]);
  });

  it('rewraps each DEK under the new KEK seed and keeps the item identity', async () => {
    const first = await encryptItem({ plaintext, kekSeed: oldKekSeed });
    const second = await encryptItem({ plaintext: new TextEncoder().encode('other'), kekSeed: oldKekSeed });
    const rotated = await rotate(
      [first, second].map(({ itemUuid, itemSalt, encryptedDEK }) => ({ itemUuid, itemSalt, encryptedDEK })),
      oldKekSeed,
      newKekSeed,
    );

    expect(rotated.map((item) => item.itemUuid)).toEqual([first.itemUuid, second.itemUuid]);
    expect(rotated[0].itemSalt).toEqual(first.itemSalt);
    expect(rotated[1].itemSalt).toEqual(second.itemSalt);
    expect(Array.from(rotated[0].encryptedDEK)).not.toEqual(Array.from(first.encryptedDEK));

    expect(await decryptItem({ ...first, encryptedDEK: rotated[0].encryptedDEK, kekSeed: newKekSeed })).toEqual(
      plaintext,
    );
    await expect(decryptItem({ ...first, encryptedDEK: rotated[0].encryptedDEK, kekSeed: oldKekSeed })).rejects.toThrow();
  });

  it('stops when an item cannot be unwrapped with the old KEK seed', async () => {
    const item = await encryptItem({ plaintext, kekSeed: oldKekSeed });

    await expect(rotate(
      [{ itemUuid: item.itemUuid, itemSalt: item.itemSalt, encryptedDEK: item.encryptedDEK }],
      newKekSeed,
      oldKekSeed,
    )).rejects.toThrow();
  });
});
