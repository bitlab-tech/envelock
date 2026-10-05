export interface KDFStrategy {
  /**
   * Derives a key from a secret and salt.
   * The secret can be any high-entropy source — API key, token, password, etc.
   * Low-entropy secrets (e.g. user-chosen passwords) should use a
   * memory-hard strategy (ScryptStrategy or Argon2idStrategy).
   */
  derive(secret: string | Buffer, salt: Buffer): Promise<Buffer>;

  /**
   * Generates a new random salt sized appropriately for this strategy.
   */
  generateSalt(): Buffer;
}