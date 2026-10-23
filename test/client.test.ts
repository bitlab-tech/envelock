import { describe, expect, it, vi } from 'vitest';
import { buildCanonicalString } from '../src/auth/canonicalRequest.js';
import { EnvelopeClient } from '../src/client.js';
import {
  ED25519_KEY_BYTES,
  ENVELOCK_AUTH_HEADER,
  ENVELOCK_NONCE_HEADER,
  ENVELOCK_TIMESTAMP_HEADER,
  SALT_BYTES,
} from '../src/core/constants.js';
import { fromHex } from '../src/core/encoding.js';
import { generateApiKey, parseApiKey } from '../src/identity/apiKey.js';
import { verifyEd25519 } from '../src/identity/ed25519.js';
import { generateSalt } from '../src/identity/keygen.js';

const plaintext = new TextEncoder().encode('secret item');
const prefix = 'ev';
const nonce = '11111111-1111-4111-8111-111111111111';

describe('EnvelopeClient.create', () => {
  it('returns a display key, a 32-byte salt, and a public key', async () => {
    const { client, displayKey, mainSalt } = await EnvelopeClient.create(prefix);

    expect(displayKey.startsWith(`${prefix}_`)).toBe(true);
    expect(parseApiKey(displayKey, prefix)).toHaveLength(32);
    expect(mainSalt).toHaveLength(SALT_BYTES);
    expect(client.getPublicKey()).toHaveLength(ED25519_KEY_BYTES);
  });

  it('encrypts an item that the same client can decrypt', async () => {
    const { client } = await EnvelopeClient.create(prefix);
    const item = await client.encryptItem(plaintext);

    expect(await client.decryptItem(item)).toEqual(plaintext);
  });

  it('rejects empty plaintext', async () => {
    const { client } = await EnvelopeClient.create(prefix);

    await expect(client.encryptItem(new Uint8Array())).rejects.toThrow('Plaintext is empty');
  });

  it('signs a request with the client public key', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    vi.spyOn(crypto, 'randomUUID').mockReturnValue(nonce);
    const { client } = await EnvelopeClient.create(prefix);
    const request = new Request('https://example.com/v1/items?x=1', { method: 'POST', body: 'hello' });

    const signed = await client.signRequest(request);
    const canonical = await buildCanonicalString(signed);
    const signature = fromHex(signed.headers.get(ENVELOCK_AUTH_HEADER) ?? '');

    expect(signed.headers.get(ENVELOCK_TIMESTAMP_HEADER)).toBe('1700000000000');
    expect(signed.headers.get(ENVELOCK_NONCE_HEADER)).toBe(nonce);
    expect(verifyEd25519(client.getPublicKey(), new TextEncoder().encode(canonical), signature)).toBe(true);

    vi.restoreAllMocks();
  });
});

describe('EnvelopeClient.fromApiKey', () => {
  it('restores the client from the display key and salt returned by create', async () => {
    const { client, displayKey, mainSalt } = await EnvelopeClient.create(prefix);
    const restored = await EnvelopeClient.fromApiKey(displayKey, mainSalt, prefix);
    const item = await client.encryptItem(plaintext);

    expect(restored.getPublicKey()).toEqual(client.getPublicKey());
    expect(await restored.decryptItem(item)).toEqual(plaintext);
  });

  it('restores a client that can decrypt items from the same key and salt', async () => {
    const { seed, displayKey } = generateApiKey(prefix);
    const mainSalt = generateSalt();
    const first = await EnvelopeClient.fromApiKey(displayKey, mainSalt, prefix);
    const second = await EnvelopeClient.fromApiKey(displayKey, mainSalt, prefix);
    const item = await first.encryptItem(plaintext);

    expect(seed).toHaveLength(32);
    expect(mainSalt).toHaveLength(SALT_BYTES);
    expect(second.getPublicKey()).toEqual(first.getPublicKey());
    expect(await second.decryptItem(item)).toEqual(plaintext);
  });

  it('restores a key that has no prefix', async () => {
    const { displayKey } = generateApiKey('');
    const mainSalt = generateSalt();
    const client = await EnvelopeClient.fromApiKey(displayKey, mainSalt, '');
    const item = await client.encryptItem(plaintext);

    expect(displayKey.startsWith('_')).toBe(false);
    expect(await client.decryptItem(item)).toEqual(plaintext);
  });

  it('rejects a missing key, salt, or prefix', async () => {
    const { displayKey } = generateApiKey(prefix);
    const mainSalt = generateSalt();

    await expect(EnvelopeClient.fromApiKey(undefined as unknown as string, mainSalt, prefix)).rejects.toThrow(
      'Invalid parameters',
    );
    await expect(EnvelopeClient.fromApiKey(displayKey, new Uint8Array(SALT_BYTES - 1), prefix)).rejects.toThrow(
      'Invalid parameters',
    );
    await expect(EnvelopeClient.fromApiKey(displayKey, mainSalt, undefined as unknown as string)).rejects.toThrow(
      'Invalid parameters',
    );
  });

  it('rejects a display key whose prefix does not match', async () => {
    const { displayKey } = generateApiKey('event');

    await expect(EnvelopeClient.fromApiKey(displayKey, generateSalt(), prefix)).rejects.toThrow(
      'invalid key format',
    );
  });
});

describe('EnvelopeClient.rotate', () => {
  it('rewraps items so the next client can decrypt them', async () => {
    const { client } = await EnvelopeClient.create(prefix);
    const { client: next } = await EnvelopeClient.create(prefix);
    const item = await client.encryptItem(plaintext);

    const [wrapped] = await client.rotate(next, [item]);
    const decrypted = await next.decryptItem({ ...item, encryptedDEK: wrapped.encryptedDEK });

    expect(wrapped.itemUuid).toBe(item.itemUuid);
    expect(wrapped.itemSalt).toEqual(item.itemSalt);
    expect(decrypted).toEqual(plaintext);
    await expect(client.decryptItem({ ...item, encryptedDEK: wrapped.encryptedDEK })).rejects.toThrow();
  });
});
