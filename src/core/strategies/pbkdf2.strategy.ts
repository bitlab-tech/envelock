import crypto from 'crypto';
import { promisify } from 'util';
import { KDFStrategy } from './kdf-strategy.interface';

const pbkdf2Async = promisify(crypto.pbkdf2);

export interface PBKDF2Options {
  /** Default: 600_000 — OWASP recommended minimum for PBKDF2-HMAC-SHA256 */
  iterations?: number;
  /** Default: 32 (256 bits) */
  keyLength?: number;
  /** Default: 'sha256' */
  digest?: string;
  /** Default: 32 (256 bits) */
  saltLength?: number;
}

/**
 * PBKDF2 — zero external dependencies, built into Node.js `crypto`.
 *
 * Not memory-hard, so it is vulnerable to GPU/ASIC parallelized brute force.
 * Only appropriate for high-entropy secrets (API keys, tokens) where the
 * keyspace itself makes brute force infeasible regardless of KDF speed.
 *
 * Do NOT use for low-entropy secrets like user-chosen passwords —
 * use ScryptStrategy or Argon2idStrategy instead.
 */
export class PBKDF2Strategy implements KDFStrategy {
  private readonly iterations: number;
  private readonly keyLength: number;
  private readonly digest: string;
  private readonly saltLength: number;

  constructor(options: PBKDF2Options = {}) {
    this.iterations = options.iterations ?? 600_000;
    this.keyLength = options.keyLength ?? 32;
    this.digest = options.digest ?? 'sha256';
    this.saltLength = options.saltLength ?? 32;
  }

  async derive(secret: string | Buffer, salt: Buffer): Promise<Buffer> {
    return pbkdf2Async(
      secret,
      salt,
      this.iterations,
      this.keyLength,
      this.digest,
    );
  }

  generateSalt(): Buffer {
    return crypto.randomBytes(this.saltLength);
  }
}