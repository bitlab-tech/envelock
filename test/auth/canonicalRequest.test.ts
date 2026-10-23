import { describe, expect, it } from 'vitest';
import { buildCanonicalString } from '../../src/auth/canonicalRequest.js';
import { ENVELOCK_NONCE_HEADER, ENVELOCK_TIMESTAMP_HEADER } from '../../src/core/constants.js';

const timestamp = '1700000000000';
const nonce = '11111111-1111-4111-8111-111111111111';

function request(body?: BodyInit, path = '/v1/items?x=1'): Request {
  const value = new Request(`https://example.com${path}`, { method: 'POST', body });
  value.headers.set(ENVELOCK_TIMESTAMP_HEADER, timestamp);
  value.headers.set(ENVELOCK_NONCE_HEADER, nonce);
  return value;
}

describe('buildCanonicalString', () => {
  it('joins the method, path, timestamp, nonce, and SHA-256 body hash', async () => {
    const canonical = await buildCanonicalString(request('hello'));

    expect(canonical).toBe(
      [
        'POST',
        '/v1/items?x=1',
        timestamp,
        nonce,
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      ].join('\n'),
    );
  });

  it('hashes an empty body', async () => {
    const canonical = await buildCanonicalString(request(undefined, '/v1/items'));

    expect(canonical.endsWith('\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe(
      true,
    );
  });

  it('requires the timestamp and nonce headers', async () => {
    const missingTimestamp = new Request('https://example.com/v1/items', { method: 'POST' });
    missingTimestamp.headers.set(ENVELOCK_NONCE_HEADER, nonce);
    const missingNonce = new Request('https://example.com/v1/items', { method: 'POST' });
    missingNonce.headers.set(ENVELOCK_TIMESTAMP_HEADER, timestamp);

    await expect(buildCanonicalString(missingTimestamp)).rejects.toThrow('Timestamp header is required');
    await expect(buildCanonicalString(missingNonce)).rejects.toThrow('Nonce header is required');
  });
});
