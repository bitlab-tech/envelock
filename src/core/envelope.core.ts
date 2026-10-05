import crypto, { CipherGCM, DecipherGCM } from 'crypto';
import {
  EnvelopeConfig,
  EncryptedPayload,
  KeyMaterial,
  GeneratedApiKey,
} from './envelope.types';
import { ENVELOPE_DEFAULTS } from './envelope.constants';

export class EnvelopeCore {
  private readonly algorithm: string;
  private readonly ivLength: number;
  private readonly keyLength: number;

  constructor(private readonly config: EnvelopeConfig) {
    this.algorithm = config.aes?.algorithm ?? ENVELOPE_DEFAULTS.AES_ALGORITHM;
    this.ivLength = config.aes?.ivLength ?? ENVELOPE_DEFAULTS.AES_IV_LENGTH;
    this.keyLength = config.aes?.keyLength ?? ENVELOPE_DEFAULTS.KEY_LENGTH;
  }

  // -------------------------
  // API key
  // -------------------------

  /**
   * Generates a new API key and its SHA-256 hash.
   * The raw apiKey is returned once and never stored — caller must return
   * it to the user immediately and persist only the hash.
   */
  generateApiKey(): GeneratedApiKey {
    const secretLength =
      this.config.apiKey.secretLength ??
      ENVELOPE_DEFAULTS.API_KEY_SECRET_LENGTH;

    const secret = crypto.randomBytes(secretLength).toString('base64url');
    const apiKey = `${this.config.apiKey.prefix}_${secret}`;
    const hash = this.hashApiKey(apiKey);

    return { apiKey, hash };
  }

  /**
   * SHA-256 hash of the raw API key.
   * Safe for high-entropy keys — used for DB lookup only.
   */
  hashApiKey(apiKey: string): string {
    return crypto.createHash('sha256').update(apiKey).digest('hex');
  }

  // -------------------------
  // KDF
  // -------------------------

  /**
   * Generates a new random salt via the configured KDF strategy.
   * Call once at key creation time and persist alongside the encrypted DEK.
   */
  generateSalt(): Buffer {
    return this.config.kdf.strategy.generateSalt();
  }

  /**
   * Derives a KEK from any high-entropy secret and a salt.
   * The secret can be an API key, token, password, or any entropy source.
   * Never persists the KEK — caller is responsible for zeroing it after use.
   */
  async deriveKEK(secret: string | Buffer, salt: Buffer): Promise<Buffer> {
    return this.config.kdf.strategy.derive(secret, salt);
  }

  // -------------------------
  // DEK
  // -------------------------

  /**
   * Generates a new random DEK.
   * Should be generated once per API key and stored encrypted via encryptDEK.
   */
  generateDEK(): Buffer {
    return crypto.randomBytes(this.keyLength);
  }

  /**
   * Encrypts a DEK with a KEK using AES-256-GCM.
   * Store the returned EncryptedPayload — never store the raw DEK.
   */
  encryptDEK(dek: Buffer, kek: Buffer): EncryptedPayload {
    return this.encrypt(dek, kek);
  }

  /**
   * Decrypts an encrypted DEK using a KEK.
   * Caller must zero out the returned DEK buffer after use.
   */
  decryptDEK(payload: EncryptedPayload, kek: Buffer): Buffer {
    return this.decrypt(payload, kek);
  }

  // -------------------------
  // AES-256-GCM
  // -------------------------

  /**
   * Encrypts arbitrary data with a key using AES-256-GCM.
   * A fresh random IV is generated per call.
   * The authTag provides integrity — decryption will throw if data is tampered.
   */
  encrypt(data: Buffer, key: Buffer): EncryptedPayload {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv) as CipherGCM;

    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { ciphertext, iv, authTag };
  }

  /**
   * Decrypts an EncryptedPayload with a key using AES-256-GCM.
   * Throws if the authTag does not match — indicates tampering or wrong key.
   */
  decrypt(payload: EncryptedPayload, key: Buffer): Buffer {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      key,
      payload.iv,
    ) as DecipherGCM;
    decipher.setAuthTag(payload.authTag);

    return Buffer.concat([
      decipher.update(payload.ciphertext),
      decipher.final(),
    ]);
  }

  // -------------------------
  // High-level bootstrap
  // -------------------------

  /**
   * Full key material generation — call once at API key creation time.
   * Generates salt, derives KEK, generates DEK, encrypts DEK with KEK.
   * KEK and raw DEK are zeroed from memory before returning.
   * Persist the returned KeyMaterial alongside the API key hash.
   */
  async generateKeyMaterial(secret: string | Buffer): Promise<KeyMaterial> {
    const salt = this.generateSalt();
    const kek = await this.deriveKEK(secret, salt);
    const dek = this.generateDEK();

    const encryptedDek = this.encryptDEK(dek, kek);

    // Zero out sensitive material — only encryptedDek leaves this method
    dek.fill(0);
    kek.fill(0);

    return { salt, encryptedDek };
  }

  /**
   * Resolves the DEK for an active request.
   * Re-derives KEK from secret + salt, decrypts DEK, zeros KEK.
   * Caller MUST zero the returned DEK buffer after use:
   *   const dek = await envelope.resolveDataKey(secret, material);
   *   try { ... } finally { dek.fill(0); }
   */
  async resolveDataKey(
    secret: string | Buffer,
    material: KeyMaterial,
  ): Promise<Buffer> {
    const kek = await this.deriveKEK(secret, material.salt);

    try {
      return this.decryptDEK(material.encryptedDek, kek);
    } finally {
      // KEK is always zeroed regardless of success or failure
      kek.fill(0);
    }
  }
}