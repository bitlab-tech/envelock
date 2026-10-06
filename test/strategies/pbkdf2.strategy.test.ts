import crypto from 'crypto';
import { describe, expect, it } from 'vitest';
import { PBKDF2Strategy } from '../../src/core/strategies/pbkdf2.strategy';

const FAST = { iterations: 1_000, keyLength: 32, saltLength: 16 };

describe('PBKDF2Strategy', () => {
  it('matches Node pbkdf2 for the same inputs', async () => {
    const strategy = new PBKDF2Strategy(FAST);
    const salt = Buffer.from('fixed-salt-value');
    const derived = await strategy.derive('api-key', salt);
    const expected = crypto.pbkdf2Sync('api-key', salt, 1_000, 32, 'sha256');

    expect(derived.equals(expected)).toBe(true);
  });

  it('is stable for the same secret and salt, and changes when either changes', async () => {
    const strategy = new PBKDF2Strategy(FAST);
    const salt = strategy.generateSalt();
    const first = await strategy.derive('secret', salt);
    const second = await strategy.derive('secret', salt);
    const otherSecret = await strategy.derive('other', salt);
    const otherSalt = await strategy.derive('secret', strategy.generateSalt());

    expect(first.equals(second)).toBe(true);
    expect(first.equals(otherSecret)).toBe(false);
    expect(first.equals(otherSalt)).toBe(false);
  });

  it('treats a UTF-8 string and the same bytes as the same secret', async () => {
    const strategy = new PBKDF2Strategy(FAST);
    const salt = Buffer.alloc(16, 3);
    const fromString = await strategy.derive('secret', salt);
    const fromBuffer = await strategy.derive(Buffer.from('secret', 'utf8'), salt);

    expect(fromString.equals(fromBuffer)).toBe(true);
  });

  it('honors key length, digest, and salt length', async () => {
    const strategy = new PBKDF2Strategy({
      iterations: 100,
      keyLength: 16,
      digest: 'sha512',
      saltLength: 8,
    });
    const salt = strategy.generateSalt();
    const derived = await strategy.derive('secret', salt);

    expect(salt).toHaveLength(8);
    expect(derived).toHaveLength(16);
    expect(
      derived.equals(crypto.pbkdf2Sync('secret', salt, 100, 16, 'sha512')),
    ).toBe(true);
  });
});
