import crypto from 'crypto';
import { promisify } from 'util';
import { KDFStrategy } from './kdf-strategy.interface';

const scryptAsync = promisify(crypto.scrypt) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: crypto.ScryptOptions,
) => Promise<Buffer>;

export interface ScryptOptions {
  /** CPU/memory cost parameter. Default: 16384 (2^14) */
  N?: number;
  /** Block size parameter. Default: 8 */
  r?: number;
  /** Parallelization parameter. Default: 1 */
  p?: number;
  /** Default: 32 (256 bits) */
  keyLength?: number;
  /** Default: 32 (256 bits) */
  saltLength?: number;
  /**
   * Max memory scrypt is allowed to use, in bytes.
   * Must be >= 128 * N * r. Default is computed automatically with headroom.
   */
  maxmem?: number;
}

/**
 * scrypt — memory-hard, built into Node.js `crypto`, zero external dependencies.
 *
 * Stronger than PBKDF2 against GPU/ASIC attacks due to memory hardness.
 * A solid default for password-based key derivation when you want to avoid
 * the native-binding dependency that Argon2id requires.
 */
export class ScryptStrategy implements KDFStrategy {
  private readonly N: number;
  private readonly r: number;
  private readonly p: number;
  private readonly keyLength: number;
  private readonly saltLength: number;
  private readonly maxmem: number;

  constructor(options: ScryptOptions = {}) {
    this.N = options.N ?? 16384;
    this.r = options.r ?? 8;
    this.p = options.p ?? 1;
    this.keyLength = options.keyLength ?? 32;
    this.saltLength = options.saltLength ?? 32;
    // Default maxmem with headroom above the 128*N*r*p requirement
    this.maxmem = options.maxmem ?? 128 * this.N * this.r * this.p * 2;
  }

  async derive(secret: string | Buffer, salt: Buffer): Promise<Buffer> {
    return scryptAsync(secret, salt, this.keyLength, {
      N: this.N,
      r: this.r,
      p: this.p,
      maxmem: this.maxmem,
    });
  }

  generateSalt(): Buffer {
    return crypto.randomBytes(this.saltLength);
  }
}