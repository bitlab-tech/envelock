import { describe, expect, it } from 'vitest';
import { Argon2idStrategy } from '../../src/core/strategies/argon2id.strategy';

const FAST = {
  memoryCost: 1024,
  timeCost: 2,
  parallelism: 1,
  keyLength: 32,
  saltLength: 16,
};

describe('Argon2idStrategy', () => {
  it('derives a stable raw key and changes it when the salt changes', async () => {
    const strategy = new Argon2idStrategy(FAST);
    const salt = strategy.generateSalt();
    const first = await strategy.derive('secret', salt);
    const second = await strategy.derive(Buffer.from('secret', 'utf8'), salt);
    const otherSalt = await strategy.derive('secret', strategy.generateSalt());

    expect(Buffer.isBuffer(first)).toBe(true);
    expect(first).toHaveLength(32);
    expect(salt).toHaveLength(16);
    expect(first.equals(second)).toBe(true);
    expect(first.equals(otherSalt)).toBe(false);
  });

  it('honors a custom hash length', async () => {
    const strategy = new Argon2idStrategy({ ...FAST, keyLength: 16 });
    const derived = await strategy.derive('secret', Buffer.alloc(16, 2));

    expect(derived).toHaveLength(16);
  });
});
