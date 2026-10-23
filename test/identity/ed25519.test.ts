import { describe, expect, it } from 'vitest';
import { ED25519_KEY_BYTES, ED25519_SIGNATURE_BYTES, SEED_BYTES } from '../../src/core/constants.js';
import { fromHex } from '../../src/core/encoding.js';
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from '../../src/identity/ed25519.js';

const rfc8032 = {
  seed: fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
  publicKey: fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
  message: new Uint8Array(),
  signature: fromHex(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  ),
};

describe('generateEd25519KeyPair', () => {
  it('derives the RFC 8032 public key and keeps the seed as the secret key', async () => {
    const keys = await generateEd25519KeyPair(rfc8032.seed);

    expect(keys.secretKey).toEqual(rfc8032.seed);
    expect(keys.publicKey).toEqual(rfc8032.publicKey);
  });

  it('rejects a signing seed that is not 32 bytes', async () => {
    await expect(generateEd25519KeyPair(new Uint8Array(31))).rejects.toThrow(
      new Error(`Signing seed must be ${SEED_BYTES} bytes`),
    );
  });
});

describe('signEd25519 and verifyEd25519', () => {
  it('reproduces the RFC 8032 empty-message signature', () => {
    const signature = signEd25519(rfc8032.seed, rfc8032.message);

    expect(signature).toEqual(rfc8032.signature);
    expect(signature).toHaveLength(64);
    expect(verifyEd25519(rfc8032.publicKey, rfc8032.message, signature)).toBe(true);
  });

  it('rejects a different message, public key, or signature', async () => {
    const other = await generateEd25519KeyPair(new Uint8Array(32).fill(7));
    const signature = signEd25519(rfc8032.seed, rfc8032.message);
    const tampered = new Uint8Array(signature);
    tampered[0] ^= 0x01;

    expect(verifyEd25519(rfc8032.publicKey, new Uint8Array([1]), signature)).toBe(false);
    expect(verifyEd25519(other.publicKey, rfc8032.message, signature)).toBe(false);
    expect(verifyEd25519(rfc8032.publicKey, rfc8032.message, tampered)).toBe(false);
  });

  it('rejects a secret key, public key, or signature of the wrong size', async () => {
    const keys = await generateEd25519KeyPair(rfc8032.seed);

    expect(() => signEd25519(new Uint8Array(ED25519_KEY_BYTES - 1), rfc8032.message)).toThrow(
      new Error(`Secret key must be ${ED25519_KEY_BYTES} bytes`),
    );
    expect(() => verifyEd25519(new Uint8Array(ED25519_KEY_BYTES - 1), rfc8032.message, rfc8032.signature)).toThrow(
      new Error(`Public key must be ${ED25519_KEY_BYTES} bytes`),
    );
    expect(() => verifyEd25519(keys.publicKey, rfc8032.message, new Uint8Array(ED25519_SIGNATURE_BYTES - 1))).toThrow(
      new Error(`Signature must be ${ED25519_SIGNATURE_BYTES} bytes`),
    );
  });
});
