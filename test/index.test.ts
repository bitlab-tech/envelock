import { describe, expect, it } from 'vitest';
import * as envault from '../src/index';

describe('public exports', () => {
  it('exposes the core, strategies, defaults, and NestJS entry points', () => {
    expect(envault.EnvelopeCore).toBeTypeOf('function');
    expect(envault.PBKDF2Strategy).toBeTypeOf('function');
    expect(envault.ScryptStrategy).toBeTypeOf('function');
    expect(envault.Argon2idStrategy).toBeTypeOf('function');
    expect(envault.EnvelopeEncryptionModule).toBeTypeOf('function');
    expect(envault.EnvelopeEncryptionService).toBeTypeOf('function');
    expect(envault.ENVELOPE_DEFAULTS).toMatchObject({
      AES_ALGORITHM: 'aes-256-gcm',
      AES_IV_LENGTH: 12,
      KEY_LENGTH: 32,
      API_KEY_SECRET_LENGTH: 32,
    });
    expect(typeof envault.ENVELOPE_CONFIG).toBe('symbol');
  });
});
