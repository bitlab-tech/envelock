import { describe, expect, it } from 'vitest';
import { aesGcmDecrypt, aesGcmEncrypt } from '../../src/core/aes.js';
import { AES_GCM_KEY_BYTES, IV_BYTES } from '../../src/core/constants.js';

const key = new Uint8Array(AES_GCM_KEY_BYTES).fill(7);
const otherKey = new Uint8Array(AES_GCM_KEY_BYTES).fill(8);
const plaintext = new TextEncoder().encode('payload');
const aad = new TextEncoder().encode('item');
const TAG_BYTES = 16;

describe('aesGcmEncrypt and aesGcmDecrypt', () => {
  it('round-trips plaintext and binds it to the additional data', async () => {
    const blob = await aesGcmEncrypt(plaintext, key, aad);

    expect(blob.length).toBe(IV_BYTES + plaintext.length + TAG_BYTES);
    expect(await aesGcmDecrypt(blob, key, aad)).toEqual(plaintext);
    await expect(aesGcmDecrypt(blob, key, new TextEncoder().encode('other'))).rejects.toThrow();
  });

  it('uses a fresh IV for each encryption', async () => {
    const first = await aesGcmEncrypt(plaintext, key, aad);
    const second = await aesGcmEncrypt(plaintext, key, aad);

    expect(Array.from(first.subarray(0, IV_BYTES))).not.toEqual(Array.from(second.subarray(0, IV_BYTES)));
  });

  it('rejects a bad key, a short blob, or a tampered ciphertext', async () => {
    const blob = await aesGcmEncrypt(plaintext, key, aad);
    const tampered = new Uint8Array(blob);
    tampered[tampered.length - 1] ^= 0x01;

    await expect(aesGcmEncrypt(plaintext, new Uint8Array(AES_GCM_KEY_BYTES - 1), aad)).rejects.toThrow(
      `key must be ${AES_GCM_KEY_BYTES} bytes`,
    );
    await expect(aesGcmDecrypt(new Uint8Array(IV_BYTES - 1), key, aad)).rejects.toThrow(
      `blob must be at least ${IV_BYTES} bytes`,
    );
    await expect(aesGcmDecrypt(blob, otherKey, aad)).rejects.toThrow();
    await expect(aesGcmDecrypt(tampered, key, aad)).rejects.toThrow();
  });
});
