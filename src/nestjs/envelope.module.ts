import { DynamicModule, Module, Provider } from '@nestjs/common';
import { EnvelopeEncryptionService } from './envelope.service';
import { ENVELOPE_CONFIG } from '../core/envelope.constants';
import { EnvelopeConfig } from '../core/envelope.types';

export interface EnvelopeModuleAsyncOptions {
  /** Whether the registering module should be marked global. Default: true */
  isGlobal?: boolean;
  useFactory: (
    ...args: any[]
  ) => EnvelopeConfig | Promise<EnvelopeConfig>;
  inject?: any[];
  /** Modules to import so useFactory's injected dependencies are resolvable */
  imports?: any[];
}

export interface EnvelopeModuleOptions extends EnvelopeConfig {
  /** Whether the registering module should be marked global. Default: true */
  isGlobal?: boolean;
}

@Module({})
export class EnvelopeEncryptionModule {
  /**
   * Register with a static config object.
   *
   * @example
   * EnvelopeEncryptionModule.forRoot({
   *   apiKey: { prefix: 'aidh' },
   *   kdf: { strategy: new PBKDF2Strategy() },
   * });
   */
  static forRoot(options: EnvelopeModuleOptions): DynamicModule {
    const { isGlobal = true, ...config } = options;

    const configProvider: Provider = {
      provide: ENVELOPE_CONFIG,
      useValue: config,
    };

    return {
      module: EnvelopeEncryptionModule,
      global: isGlobal,
      providers: [configProvider, EnvelopeEncryptionService],
      exports: [EnvelopeEncryptionService],
    };
  }

  /**
   * Register with an async factory — e.g. to pull config from ConfigService.
   *
   * @example
   * EnvelopeEncryptionModule.forRootAsync({
   *   imports: [ConfigModule],
   *   useFactory: (config: ConfigService) => ({
   *     apiKey: { prefix: config.get('API_KEY_PREFIX') },
   *     kdf: { strategy: new PBKDF2Strategy() },
   *   }),
   *   inject: [ConfigService],
   * });
   */
  static forRootAsync(options: EnvelopeModuleAsyncOptions): DynamicModule {
    const { isGlobal = true, imports = [], useFactory, inject = [] } = options;

    const configProvider: Provider = {
      provide: ENVELOPE_CONFIG,
      useFactory,
      inject,
    };

    return {
      module: EnvelopeEncryptionModule,
      global: isGlobal,
      imports,
      providers: [configProvider, EnvelopeEncryptionService],
      exports: [EnvelopeEncryptionService],
    };
  }
}