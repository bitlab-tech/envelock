import { describe, expect, it } from 'vitest';
import * as envelock from '../src/index';

describe('public exports', () => {
  it('exposes the core, strategies, defaults, and NestJS entry points', () => {
    expect(envelock.EnvelopeCore).toBeTypeOf('function');
    expect(envelock.PBKDF2Strategy).toBeTypeOf('function');
    expect(envelock.ScryptStrategy).toBeTypeOf('function');
    expect(envelock.Argon2idStrategy).toBeTypeOf('function');
    expect(envelock.EnvelopeEncryptionModule).toBeTypeOf('function');
    expect(envelock.EnvelopeEncryptionService).toBeTypeOf('function');
    expect(envelock.ENVELOPE_DEFAULTS).toMatchObject({
      AES_ALGORITHM: 'aes-256-gcm',
      AES_IV_LENGTH: 12,
      KEY_LENGTH: 32,
      API_KEY_SECRET_LENGTH: 32,
    });
    expect(typeof envelock.ENVELOPE_CONFIG).toBe('symbol');
  });
});
