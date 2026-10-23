import { describe, expect, it } from 'vitest';
import { HASH_BYTES } from '../../src/core/constants.js';
import { toHex } from '../../src/core/encoding.js';
import { hash } from '../../src/core/hash.js';

describe('hash', () => {
  it('matches SHA-256, SHA-384, and SHA-512 for the same message', async () => {
    expect(toHex(await hash('abc', 'SHA-256'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(toHex(await hash('abc', 'SHA-384'))).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    );
    expect(toHex(await hash('abc', 'SHA-512'))).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    );
  });

  it('hashes a string and the same UTF-8 bytes to the same digest', async () => {
    const fromString = await hash('hello', 'SHA-256');
    const fromBytes = await hash(new TextEncoder().encode('hello'), 'SHA-256');

    expect(toHex(fromString)).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    expect(fromBytes).toEqual(fromString);
    expect(fromString).toHaveLength(HASH_BYTES['SHA-256']);
  });

  it('hashes an empty message', async () => {
    expect(toHex(await hash(new Uint8Array(), 'SHA-256'))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});
