import crypto from 'crypto';
import { KDFStrategy } from './kdf-strategy.interface';

export interface Argon2idOptions {
  /** Memory cost in KiB. Default: 65536 (64 MB) */
  memoryCost?: number;
  /** Time cost (iterations). Default: 3 */
  timeCost?: number;
  /** Degree of parallelism. Default: 1 */
  parallelism?: number;
  /** Default: 32 (256 bits) */
  keyLength?: number;
  /** Default: 32 (256 bits) */
  saltLength?: number;
}

// Lazily loaded — argon2 is an optional dependency with native bindings.
// Only required if the consumer actually instantiates Argon2idStrategy.
type Argon2Module = typeof import('argon2');
let argon2Module: Argon2Module | undefined;

function loadArgon2(): Argon2Module {
  if (argon2Module) return argon2Module;

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    argon2Module = require('argon2') as Argon2Module;
    return argon2Module;
  } catch {
    throw new Error(
      '[envault] Argon2idStrategy requires the optional "argon2" package. ' +
        'Install it with: npm install argon2',
    );
  }
}

/**
 * Argon2id — current OWASP-recommended KDF, winner of the Password Hashing
 * Competition. Memory-hard and resistant to both GPU/ASIC and side-channel
 * attacks (hybrid of Argon2i and Argon2d).
 *
 * Requires the optional `argon2` package (native bindings) — install it
 * separately: `npm install argon2`. Not bundled as a hard dependency so
 * consumers who only need PBKDF2 or scrypt avoid the native build step.
 *
 * Note: memory cost impacts latency and per-request RAM usage. Tune
 * memoryCost/timeCost against your expected concurrency.
 */
export class Argon2idStrategy implements KDFStrategy {
  private readonly memoryCost: number;
  private readonly timeCost: number;
  private readonly parallelism: number;
  private readonly keyLength: number;
  private readonly saltLength: number;

  constructor(options: Argon2idOptions = {}) {
    this.memoryCost = options.memoryCost ?? 65536; // 64 MB
    this.timeCost = options.timeCost ?? 3;
    this.parallelism = options.parallelism ?? 1;
    this.keyLength = options.keyLength ?? 32;
    this.saltLength = options.saltLength ?? 32;
  }

  async derive(secret: string | Buffer, salt: Buffer): Promise<Buffer> {
    const argon2 = loadArgon2();

    const secretBuffer =
      typeof secret === 'string' ? Buffer.from(secret, 'utf8') : secret;

    return argon2.hash(secretBuffer, {
      type: argon2.argon2id,
      salt,
      memoryCost: this.memoryCost,
      timeCost: this.timeCost,
      parallelism: this.parallelism,
      hashLength: this.keyLength,
      raw: true,
    }) as Promise<Buffer>;
  }

  generateSalt(): Buffer {
    return crypto.randomBytes(this.saltLength);
  }
}