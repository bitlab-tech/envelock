import { Inject, Injectable } from '@nestjs/common';
import { EnvelopeCore } from '../core/envelope.core';
import { EnvelopeConfig } from '../core/envelope.types';
import { ENVELOPE_CONFIG } from '../core/envelope.constants';

/**
 * Injectable NestJS wrapper around EnvelopeCore.
 * Adds no behavior of its own — purely makes the framework-agnostic
 * core available via NestJS dependency injection.
 */
@Injectable()
export class EnvelopeEncryptionService extends EnvelopeCore {
  constructor(@Inject(ENVELOPE_CONFIG) config: EnvelopeConfig) {
    super(config);
  }
}