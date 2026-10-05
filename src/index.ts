// Core — framework agnostic
export { EnvelopeCore } from './core/envelope.core';
export type {
  EnvelopeConfig,
  EncryptedPayload,
  KeyMaterial,
  GeneratedApiKey,
  KDFStrategy,
  AesConfig,
  ApiKeyConfig,
} from './core/envelope.types';
export { ENVELOPE_DEFAULTS, ENVELOPE_CONFIG } from './core/envelope.constants';

// KDF strategies
export { PBKDF2Strategy } from './core/strategies/pbkdf2.strategy';
export type { PBKDF2Options } from './core/strategies/pbkdf2.strategy';
export { ScryptStrategy } from './core/strategies/scrypt.strategy';
export type { ScryptOptions } from './core/strategies/scrypt.strategy';
export { Argon2idStrategy } from './core/strategies/argon2id.strategy';
export type { Argon2idOptions } from './core/strategies/argon2id.strategy';

// NestJS — optional, requires @nestjs/common as a peer dependency
export { EnvelopeEncryptionModule } from './nestjs/envelope.module';
export type {
  EnvelopeModuleOptions,
  EnvelopeModuleAsyncOptions,
} from './nestjs/envelope.module';
export { EnvelopeEncryptionService } from './nestjs/envelope.service';