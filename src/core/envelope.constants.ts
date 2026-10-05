export const ENVELOPE_DEFAULTS = {
  AES_ALGORITHM: 'aes-256-gcm',
  AES_IV_LENGTH: 12,    // 96 bits — GCM standard
  KEY_LENGTH: 32,       // 256 bits
  API_KEY_SECRET_LENGTH: 32,
} as const;

// NestJS injection token
export const ENVELOPE_CONFIG = Symbol('ENVELOPE_CONFIG');