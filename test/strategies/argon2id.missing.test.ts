import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { Argon2idStrategy } from '../../src/core/strategies/argon2id.strategy';

const nodeRequire = createRequire(__filename);
const nodeModule = nodeRequire('module') as typeof import('module') & {
  _load: (request: string, parent: unknown, isMain: boolean) => unknown;
};

const originalLoad = nodeModule._load;

describe('Argon2idStrategy without argon2', () => {
  afterEach(() => {
    nodeModule._load = originalLoad;
  });

  it('throws an install hint when derive is called', async () => {
    nodeModule._load = (request, parent, isMain) => {
      if (request === 'argon2') {
        const error = new Error("Cannot find module 'argon2'") as NodeJS.ErrnoException;
        error.code = 'MODULE_NOT_FOUND';
        throw error;
      }
      return originalLoad(request, parent, isMain);
    };

    const strategy = new Argon2idStrategy();

    await expect(
      strategy.derive('secret', Buffer.alloc(16, 1)),
    ).rejects.toThrow(/optional "argon2" package/);
  });
});
