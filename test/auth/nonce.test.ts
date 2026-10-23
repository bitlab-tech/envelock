import { describe, expect, it, vi } from 'vitest';
import { generateNonce } from '../../src/auth/nonce.js';

describe('generateNonce', () => {
  it('returns a UUID from crypto.randomUUID', () => {
    const spy = vi.spyOn(crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111');

    expect(generateNonce()).toBe('11111111-1111-4111-8111-111111111111');
    expect(spy).toHaveBeenCalledOnce();

    spy.mockRestore();
  });
});
