import crypto from 'crypto';
import { describe, expect, it } from 'vitest';
import { ScryptStrategy } from '../../src/core/strategies/scrypt.strategy';

const FAST = { N: 16, r: 1, p: 1, keyLength: 32, saltLength: 16 };

describe('ScryptStrategy', () => {
  it('matches Node scrypt for the same inputs', async () => {
    const strategy = new ScryptStrategy(FAST);
    const salt = Buffer.from('scrypt-salt-bytes');
    const derived = await strategy.derive('password', salt);
    const expected = crypto.scryptSync('password', salt, 32, {
      N: 16,
      r: 1,
      p: 1,
      maxmem: 128 * 16 * 1 * 1 * 2,
    });

    expect(derived.equals(expected)).toBe(true);
  });

  it('is stable for the same secret and salt, and changes when either changes', async () => {
    const strategy = new ScryptStrategy(FAST);
    const salt = strategy.generateSalt();
    const first = await strategy.derive('secret', salt);
    const second = await strategy.derive(Buffer.from('secret'), salt);
    const other = await strategy.derive('other', salt);

    expect(first.equals(second)).toBe(true);
    expect(first.equals(other)).toBe(false);
    expect(salt).toHaveLength(16);
    expect(first).toHaveLength(32);
  });

  it('honors a custom key length', async () => {
    const strategy = new ScryptStrategy({ ...FAST, keyLength: 16 });
    const derived = await strategy.derive('secret', Buffer.alloc(16, 1));

    expect(derived).toHaveLength(16);
  });
});
