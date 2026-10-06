import crypto from 'crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EnvelopeCore } from '../src/core/envelope.core';
import { createEnvelope, FakeKdfStrategy } from './helpers';

describe('EnvelopeCore', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('generateApiKey / hashApiKey', () => {
    it('builds a prefixed key and a matching SHA-256 hash', () => {
      const { envelope } = createEnvelope();
      const { apiKey, hash } = envelope.generateApiKey();

      expect(apiKey.startsWith('ev_')).toBe(true);
      expect(hash).toBe(envelope.hashApiKey(apiKey));
      expect(hash).toBe(
        crypto.createHash('sha256').update(apiKey).digest('hex'),
      );
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('encodes the configured number of random bytes as base64url', () => {
      const { envelope } = createEnvelope({
        apiKey: { prefix: 'aidh', secretLength: 24 },
      });
      const { apiKey } = envelope.generateApiKey();
      const secret = apiKey.slice('aidh_'.length);

      expect(apiKey.startsWith('aidh_')).toBe(true);
      expect(Buffer.from(secret, 'base64url')).toHaveLength(24);
    });

    it('returns a different key on each call', () => {
      const { envelope } = createEnvelope();
      const first = envelope.generateApiKey();
      const second = envelope.generateApiKey();

      expect(first.apiKey).not.toBe(second.apiKey);
      expect(first.hash).not.toBe(second.hash);
    });

    it('hashes the same input to the same digest', () => {
      const { envelope } = createEnvelope();
      expect(envelope.hashApiKey('ev_static')).toBe(
        envelope.hashApiKey('ev_static'),
      );
    });
  });

  describe('KDF helpers', () => {
    it('delegates salt generation and KEK derivation to the strategy', async () => {
      const strategy = new FakeKdfStrategy(16);
      const generateSalt = vi.spyOn(strategy, 'generateSalt');
      const derive = vi.spyOn(strategy, 'derive');
      const envelope = new EnvelopeCore({
        apiKey: { prefix: 'ev' },
        kdf: { strategy },
      });

      const salt = envelope.generateSalt();
      const kek = await envelope.deriveKEK('secret', salt);

      expect(generateSalt).toHaveBeenCalledOnce();
      expect(salt).toHaveLength(16);
      expect(derive).toHaveBeenCalledWith('secret', salt);
      expect(kek).toHaveLength(32);
      expect(kek.equals(strategy.lastDerived!)).toBe(true);
    });
  });

  describe('DEK and AES-GCM', () => {
    it('generates a DEK of the configured key length', () => {
      const { envelope } = createEnvelope({
        aes: { algorithm: 'aes-128-gcm', keyLength: 16 },
      });

      expect(envelope.generateDEK()).toHaveLength(16);
    });

    it('round-trips plaintext and uses a fresh IV each time', () => {
      const { envelope } = createEnvelope();
      const key = envelope.generateDEK();
      const data = Buffer.from('payload');

      const first = envelope.encrypt(data, key);
      const second = envelope.encrypt(data, key);

      expect(first.iv).toHaveLength(12);
      expect(first.authTag).toHaveLength(16);
      expect(first.iv.equals(second.iv)).toBe(false);
      expect(envelope.decrypt(first, key).equals(data)).toBe(true);
      expect(envelope.decryptDEK(envelope.encryptDEK(data, key), key).equals(data)).toBe(
        true,
      );
    });

    it('honors a custom IV length', () => {
      const { envelope } = createEnvelope({ aes: { ivLength: 16 } });
      const payload = envelope.encrypt(Buffer.from('x'), envelope.generateDEK());

      expect(payload.iv).toHaveLength(16);
    });

    it('rejects a wrong key, a flipped ciphertext byte, and a flipped auth tag', () => {
      const { envelope } = createEnvelope();
      const key = envelope.generateDEK();
      const payload = envelope.encrypt(Buffer.from('secret'), key);

      const tamperedCipher = {
        ...payload,
        ciphertext: Buffer.from(payload.ciphertext),
      };
      tamperedCipher.ciphertext[0] ^= 0xff;

      const tamperedTag = {
        ...payload,
        authTag: Buffer.from(payload.authTag),
      };
      tamperedTag.authTag[0] ^= 0xff;

      expect(() => envelope.decrypt(payload, envelope.generateDEK())).toThrow(
        /authenticate/i,
      );
      expect(() => envelope.decrypt(tamperedCipher, key)).toThrow(/authenticate/i);
      expect(() => envelope.decrypt(tamperedTag, key)).toThrow(/authenticate/i);
    });
  });

  describe('key material', () => {
    it('unwraps the same DEK that was wrapped at creation', async () => {
      const { envelope } = createEnvelope();
      const { apiKey } = envelope.generateApiKey();
      const material = await envelope.generateKeyMaterial(apiKey);

      expect(material.salt).toHaveLength(16);
      expect(material.encryptedDek.ciphertext.length).toBeGreaterThan(0);

      const dek = await envelope.resolveDataKey(apiKey, material);
      try {
        const plain = Buffer.from('user data');
        const encrypted = envelope.encrypt(plain, dek);
        expect(envelope.decrypt(encrypted, dek).equals(plain)).toBe(true);
      } finally {
        dek.fill(0);
      }
    });

    it('accepts a Buffer secret equivalent to the same UTF-8 string', async () => {
      const { envelope } = createEnvelope();
      const secret = 'ev_buffer-secret';
      const material = await envelope.generateKeyMaterial(secret);
      const dek = await envelope.resolveDataKey(Buffer.from(secret, 'utf8'), material);

      expect(dek).toHaveLength(32);
      dek.fill(0);
    });

    it('refuses to unwrap with a different secret', async () => {
      const { envelope } = createEnvelope();
      const material = await envelope.generateKeyMaterial('original-secret');

      await expect(
        envelope.resolveDataKey('other-secret', material),
      ).rejects.toThrow(/authenticate/i);
    });

    it('zeroes the KEK and the raw DEK before returning key material', async () => {
      const strategy = new FakeKdfStrategy();
      const envelope = new EnvelopeCore({
        apiKey: { prefix: 'ev' },
        kdf: { strategy },
      });
      const deks: Buffer[] = [];
      const randomBytes = crypto.randomBytes.bind(crypto);

      vi.spyOn(crypto, 'randomBytes').mockImplementation((size: number) => {
        const buf = randomBytes(size);
        if (size === 32) deks.push(buf);
        return buf;
      });

      await envelope.generateKeyMaterial('secret');

      expect(strategy.lastDerived!.every((byte) => byte === 0)).toBe(true);
      expect(deks.length).toBeGreaterThan(0);
      expect(deks.every((dek) => dek.every((byte) => byte === 0))).toBe(true);
    });

    it('zeroes the KEK when unwrapping fails', async () => {
      const strategy = new FakeKdfStrategy();
      const envelope = new EnvelopeCore({
        apiKey: { prefix: 'ev' },
        kdf: { strategy },
      });
      const material = await envelope.generateKeyMaterial('secret');
      material.encryptedDek.authTag[0] ^= 0xff;

      await expect(envelope.resolveDataKey('secret', material)).rejects.toThrow(
        /authenticate/i,
      );
      expect(strategy.lastDerived!.every((byte) => byte === 0)).toBe(true);
    });
  });
});
