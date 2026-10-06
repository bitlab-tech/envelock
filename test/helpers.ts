import crypto from 'crypto';
import { EnvelopeCore } from '../src/core/envelope.core';
import { EnvelopeConfig } from '../src/core/envelope.types';
import { KDFStrategy } from '../src/core/strategies/kdf-strategy.interface';

/** Fast, deterministic stand-in so core tests do not pay real KDF cost. */
export class FakeKdfStrategy implements KDFStrategy {
  lastDerived: Buffer | null = null;
  readonly saltLength: number;

  constructor(saltLength = 16) {
    this.saltLength = saltLength;
  }

  generateSalt(): Buffer {
    return crypto.randomBytes(this.saltLength);
  }

  async derive(secret: string | Buffer, salt: Buffer): Promise<Buffer> {
    const key = crypto.createHash('sha256').update(secret).update(salt).digest();
    this.lastDerived = key;
    return key;
  }
}

export function createEnvelope(
  overrides: Partial<EnvelopeConfig> & {
    strategy?: KDFStrategy;
  } = {},
): { envelope: EnvelopeCore; strategy: KDFStrategy } {
  const strategy = overrides.strategy ?? new FakeKdfStrategy();
  const envelope = new EnvelopeCore({
    apiKey: overrides.apiKey ?? { prefix: 'ev' },
    kdf: overrides.kdf ?? { strategy },
    aes: overrides.aes,
  });
  return { envelope, strategy };
}
