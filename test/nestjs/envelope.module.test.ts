import { describe, expect, it } from 'vitest';
import { ENVELOPE_CONFIG } from '../../src/core/envelope.constants';
import { EnvelopeConfig } from '../../src/core/envelope.types';
import { EnvelopeEncryptionModule } from '../../src/nestjs/envelope.module';
import { EnvelopeEncryptionService } from '../../src/nestjs/envelope.service';
import { EnvelopeCore } from '../../src/core/envelope.core';
import { FakeKdfStrategy } from '../helpers';

function config(): EnvelopeConfig {
  return {
    apiKey: { prefix: 'ev' },
    kdf: { strategy: new FakeKdfStrategy() },
  };
}

describe('EnvelopeEncryptionModule', () => {
  it('registers a global module and keeps isGlobal out of the injected config', () => {
    const options = { ...config(), isGlobal: true as const };
    const dynamic = EnvelopeEncryptionModule.forRoot(options);
    const provider = dynamic.providers?.[0] as {
      provide: symbol;
      useValue: EnvelopeConfig & { isGlobal?: boolean };
    };

    expect(dynamic.module).toBe(EnvelopeEncryptionModule);
    expect(dynamic.global).toBe(true);
    expect(dynamic.exports).toEqual([EnvelopeEncryptionService]);
    expect(provider.provide).toBe(ENVELOPE_CONFIG);
    expect(provider.useValue).toEqual(configShape(options));
    expect(provider.useValue).not.toHaveProperty('isGlobal');
  });

  it('can be registered as a non-global module', () => {
    const dynamic = EnvelopeEncryptionModule.forRoot({
      ...config(),
      isGlobal: false,
    });

    expect(dynamic.global).toBe(false);
  });

  it('wires an async factory, its imports, and its inject list', () => {
    const imports = [{ module: class ConfigModule {} }];
    const inject = ['CONFIG'];
    const useFactory = () => config();
    const dynamic = EnvelopeEncryptionModule.forRootAsync({
      isGlobal: false,
      imports,
      inject,
      useFactory,
    });
    const provider = dynamic.providers?.[0] as {
      provide: symbol;
      useFactory: typeof useFactory;
      inject: unknown[];
    };

    expect(dynamic.global).toBe(false);
    expect(dynamic.imports).toBe(imports);
    expect(dynamic.exports).toEqual([EnvelopeEncryptionService]);
    expect(provider.provide).toBe(ENVELOPE_CONFIG);
    expect(provider.useFactory).toBe(useFactory);
    expect(provider.inject).toBe(inject);
  });

  it('defaults async registration to global and empty imports/inject', () => {
    const dynamic = EnvelopeEncryptionModule.forRootAsync({
      useFactory: () => config(),
    });
    const provider = dynamic.providers?.[0] as { inject: unknown[] };

    expect(dynamic.global).toBe(true);
    expect(dynamic.imports).toEqual([]);
    expect(provider.inject).toEqual([]);
  });
});

describe('EnvelopeEncryptionService', () => {
  it('is EnvelopeCore constructed with the injected config', async () => {
    const service = new EnvelopeEncryptionService(config());
    const { apiKey, hash } = service.generateApiKey();
    const material = await service.generateKeyMaterial(apiKey);
    const dek = await service.resolveDataKey(apiKey, material);

    expect(service).toBeInstanceOf(EnvelopeCore);
    expect(hash).toBe(service.hashApiKey(apiKey));
    expect(dek).toHaveLength(32);
    dek.fill(0);
  });
});

function configShape(options: EnvelopeConfig): EnvelopeConfig {
  return {
    apiKey: options.apiKey,
    kdf: options.kdf,
  };
}
