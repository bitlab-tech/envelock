import { describe, expect, it, vi } from 'vitest';
import { buildCanonicalString } from '../../src/auth/canonicalRequest.js';
import { signRequest } from '../../src/auth/signer.js';
import {
  ENVELOCK_AUTH_HEADER,
  ENVELOCK_NONCE_HEADER,
  ENVELOCK_TIMESTAMP_HEADER,
} from '../../src/core/constants.js';
import { fromHex } from '../../src/core/encoding.js';
import { generateEd25519KeyPair, verifyEd25519 } from '../../src/identity/ed25519.js';

const seed = new Uint8Array(32).fill(4);
const nonce = '11111111-1111-4111-8111-111111111111';

describe('signRequest', () => {
  it('stamps the timestamp and nonce, then sets a signature over the canonical request', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    vi.spyOn(crypto, 'randomUUID').mockReturnValue(nonce);
    const { secretKey, publicKey } = await generateEd25519KeyPair(seed);
    const request = new Request('https://example.com/v1/items?x=1', { method: 'POST', body: 'hello' });

    const signed = await signRequest(request, secretKey);
    const canonical = await buildCanonicalString(signed);
    const signature = fromHex(signed.headers.get(ENVELOCK_AUTH_HEADER) ?? '');

    expect(signed).toBe(request);
    expect(signed.headers.get(ENVELOCK_TIMESTAMP_HEADER)).toBe('1700000000000');
    expect(signed.headers.get(ENVELOCK_NONCE_HEADER)).toBe(nonce);
    expect(canonical).toBe(
      [
        'POST',
        '/v1/items?x=1',
        '1700000000000',
        nonce,
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      ].join('\n'),
    );
    expect(verifyEd25519(publicKey, new TextEncoder().encode(canonical), signature)).toBe(true);

    vi.restoreAllMocks();
  });

  it('rejects a private key of the wrong size', async () => {
    const request = new Request('https://example.com/v1/items', { method: 'GET' });

    await expect(signRequest(request, new Uint8Array(31))).rejects.toThrow('Secret key must be 32 bytes');
  });
});
