import type { KDFStrategy } from './strategies/kdf-strategy.interface';

export type { KDFStrategy } from './strategies/kdf-strategy.interface';

export interface EncryptedPayload {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export interface KeyMaterial {
  salt: Buffer;
  encryptedDek: EncryptedPayload;
}

export interface GeneratedApiKey {
  apiKey: string;
  hash: string;
}

export interface AesConfig {
  algorithm?: string;   // default: 'aes-256-gcm'
  ivLength?: number;    // default: 12
  keyLength?: number;   // default: 32
}

export interface ApiKeyConfig {
  prefix: string;
  secretLength?: number;  // default: 32
}

export interface EnvelopeConfig {
  apiKey: ApiKeyConfig;
  kdf: {
    strategy: KDFStrategy;
  };
  aes?: AesConfig;
}