import { describe, expect, it, vi } from 'vitest';
import { EnvelopeClient } from '../src/index.js';
import type { EncryptedItem } from '../src/types.js';
import {
  buildCanonicalString,
  ENVELOCK_AUTH_HEADER,
  ENVELOCK_NONCE_HEADER,
  ENVELOCK_TIMESTAMP_HEADER,
  fromBase64Url,
  fromHex,
  toBase64Url,
  verifyEd25519,
} from '../src/shared/index.js';

const prefix = 'myapp';
const firstPlaintext = new TextEncoder().encode('first secret');
const secondPlaintext = new TextEncoder().encode('second secret');

type StoredItem = {
  itemUuid: string;
  itemSalt: string;
  blob: string;
  encryptedDEK: string;
};

const storeItem = (item: EncryptedItem): StoredItem => ({
  itemUuid: item.itemUuid,
  itemSalt: toBase64Url(item.itemSalt),
  blob: toBase64Url(item.blob),
  encryptedDEK: toBase64Url(item.encryptedDEK),
});

const loadItem = (stored: StoredItem): EncryptedItem => ({
  itemUuid: stored.itemUuid,
  itemSalt: fromBase64Url(stored.itemSalt),
  blob: fromBase64Url(stored.blob),
  encryptedDEK: fromBase64Url(stored.encryptedDEK),
});

describe('stored items survive a new session', () => {
  it('decrypts records restored from the display key alone', async () => {
    const { client, displayKey } = await EnvelopeClient.create(prefix);
    const storedPublicKey = toBase64Url(client.getPublicKey());
    const stored = [firstPlaintext, secondPlaintext].map(async (plaintext) =>
      storeItem(await client.encryptItem(plaintext)),
    );
    const records = await Promise.all(stored);

    const resumed = await EnvelopeClient.fromApiKey(displayKey, prefix);

    expect(toBase64Url(resumed.getPublicKey())).toBe(storedPublicKey);
    expect(await resumed.decryptItem(loadItem(records[0]))).toEqual(firstPlaintext);
    expect(await resumed.decryptItem(loadItem(records[1]))).toEqual(secondPlaintext);
  });

  it('rejects a swapped item id, a changed blob, or a changed wrapped DEK', async () => {
    const { client, displayKey } = await EnvelopeClient.create(prefix);
    const first = storeItem(await client.encryptItem(firstPlaintext));
    const second = storeItem(await client.encryptItem(secondPlaintext));
    const resumed = await EnvelopeClient.fromApiKey(displayKey, prefix);
    const loaded = loadItem(first);
    const tamperedBlob = new Uint8Array(loaded.blob);
    const tamperedDek = new Uint8Array(loaded.encryptedDEK);
    tamperedBlob[tamperedBlob.length - 1] ^= 0x01;
    tamperedDek[tamperedDek.length - 1] ^= 0x01;

    await expect(resumed.decryptItem({ ...loaded, itemUuid: second.itemUuid })).rejects.toThrow();
    await expect(resumed.decryptItem({ ...loaded, blob: tamperedBlob })).rejects.toThrow();
    await expect(resumed.decryptItem({ ...loaded, encryptedDEK: tamperedDek })).rejects.toThrow();
  });
});

describe('a server can verify a signed request', () => {
  it('accepts the stored public key and rejects a changed body, path, or key', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111');
    const { client, displayKey } = await EnvelopeClient.create(prefix);
    const storedPublicKey = fromBase64Url(toBase64Url(client.getPublicKey()));
    const request = new Request('https://api.example.com/v1/items?x=1', {
      method: 'POST',
      body: JSON.stringify({ name: 'item' }),
    });

    const signed = await client.signRequest(request);
    const signature = fromHex(signed.headers.get(ENVELOCK_AUTH_HEADER) ?? '');
    const canonical = await buildCanonicalString(signed);
    const headers = [
      signed.headers.get(ENVELOCK_AUTH_HEADER),
      signed.headers.get(ENVELOCK_TIMESTAMP_HEADER),
      signed.headers.get(ENVELOCK_NONCE_HEADER),
    ].join('\n');

    expect(verifyEd25519(storedPublicKey, new TextEncoder().encode(canonical), signature)).toBe(true);
    expect(headers.includes(displayKey)).toBe(false);
    expect(await signed.clone().text()).not.toContain(displayKey);

    const changedBody = new Request(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: JSON.stringify({ name: 'other' }),
    });
    const changedPath = new Request('https://api.example.com/v1/other', {
      method: signed.method,
      headers: signed.headers,
      body: JSON.stringify({ name: 'item' }),
    });
    const otherKey = (await EnvelopeClient.create(prefix)).client.getPublicKey();

    expect(verifyEd25519(
      storedPublicKey,
      new TextEncoder().encode(await buildCanonicalString(changedBody)),
      signature,
    )).toBe(false);
    expect(verifyEd25519(
      storedPublicKey,
      new TextEncoder().encode(await buildCanonicalString(changedPath)),
      signature,
    )).toBe(false);
    expect(verifyEd25519(otherKey, new TextEncoder().encode(canonical), signature)).toBe(false);

    vi.restoreAllMocks();
  });
});

describe('rotation leaves the ciphertext in place', () => {
  it('decrypts with the new key and keeps the stored blob', async () => {
    const { client } = await EnvelopeClient.create(prefix);
    const { client: next, displayKey: nextKey } = await EnvelopeClient.create(prefix);
    const item = await client.encryptItem(firstPlaintext);
    const storedBlob = toBase64Url(item.blob);

    const [wrapped] = await client.rotate(next, [item]);
    const resumed = await EnvelopeClient.fromApiKey(nextKey, prefix);

    expect(toBase64Url(item.blob)).toBe(storedBlob);
    expect(wrapped.itemSalt).toEqual(item.itemSalt);
    expect(toBase64Url(resumed.getPublicKey())).not.toBe(toBase64Url(client.getPublicKey()));
    expect(await resumed.decryptItem({ ...item, encryptedDEK: wrapped.encryptedDEK })).toEqual(firstPlaintext);
    await expect(client.decryptItem({ ...item, encryptedDEK: wrapped.encryptedDEK })).rejects.toThrow();
  });
});

describe('a wrong key cannot recover data', () => {
  it('rejects a truncated key, the wrong prefix, or another user\'s key', async () => {
    const { client, displayKey } = await EnvelopeClient.create(prefix);
    const item = await client.encryptItem(firstPlaintext);
    const { displayKey: otherKey } = await EnvelopeClient.create(prefix);
    const intruder = await EnvelopeClient.fromApiKey(otherKey, prefix);

    await expect(EnvelopeClient.fromApiKey(displayKey.slice(0, -4), prefix)).rejects.toThrow(
      'invalid key length',
    );
    await expect(EnvelopeClient.fromApiKey(displayKey, 'other')).rejects.toThrow('invalid key format');
    await expect(intruder.decryptItem(item)).rejects.toThrow();
    await expect(client.encryptItem(new Uint8Array())).rejects.toThrow('Plaintext is empty');
  });
});
