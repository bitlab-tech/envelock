import { describe, expect, it } from 'vitest';
import { encode, fromBase64Url, fromHex, toBase64Url, toHex } from '../../src/core/encoding.js';

const bytes = (...values: number[]) => Uint8Array.from(values);

describe('base64url', () => {
  it('encodes known byte sequences without padding', () => {
    expect(toBase64Url(bytes())).toBe('');
    expect(toBase64Url(bytes(0x00))).toBe('AA');
    expect(toBase64Url(bytes(0xfb))).toBe('-w');
    expect(toBase64Url(bytes(0xff))).toBe('_w');
    expect(toBase64Url(bytes(0x00, 0x10))).toBe('ABA');
    expect(toBase64Url(new TextEncoder().encode('hello'))).toBe('aGVsbG8');
  });

  it('round-trips every byte value, including buffers larger than one chunk', () => {
    const allBytes = Uint8Array.from({ length: 256 }, (_, index) => index);
    const acrossChunks = Uint8Array.from({ length: 0x8000 + 10 }, (_, index) => index % 256);

    expect(fromBase64Url(toBase64Url(allBytes))).toEqual(allBytes);
    expect(fromBase64Url(toBase64Url(acrossChunks))).toEqual(acrossChunks);
    expect(toBase64Url(allBytes)).not.toMatch(/[+/=]/);
  });

  it('decodes unpadded and padded base64url', () => {
    expect(Array.from(fromBase64Url(''))).toEqual([]);
    expect(Array.from(fromBase64Url('-w'))).toEqual([0xfb]);
    expect(Array.from(fromBase64Url('_w=='))).toEqual([0xff]);
  });

  it('rejects a base64url string whose length modulo 4 is 1', () => {
    expect(() => fromBase64Url('A')).toThrow(
      new Error('fromBase64Url: invalid base64url length (1)'),
    );
  });

  it('rejects a string that is not base64url', () => {
    expect(() => fromBase64Url('!!!!')).toThrow();
  });
});

describe('encode', () => {
  it('encodes a string as UTF-8', () => {
    expect(encode('hello')).toEqual(new TextEncoder().encode('hello'));
    expect(encode('')).toEqual(new Uint8Array());
  });
});

describe('hex', () => {
  it('encodes bytes as lowercase hex', () => {
    expect(toHex(bytes())).toBe('');
    expect(toHex(bytes(0x00, 0x0f, 0xff))).toBe('000fff');
  });

  it('decodes hex without regard to case', () => {
    expect(fromHex('')).toEqual(bytes());
    expect(fromHex('000FFF')).toEqual(bytes(0x00, 0x0f, 0xff));
  });

  it('round-trips every byte value', () => {
    const allBytes = Uint8Array.from({ length: 256 }, (_, index) => index);

    expect(fromHex(toHex(allBytes))).toEqual(allBytes);
  });

  it('rejects an odd length or a non-hex character', () => {
    expect(() => fromHex('abc')).toThrow(new Error('fromHex: invalid hex string "abc"'));
    expect(() => fromHex('0g')).toThrow(new Error('fromHex: invalid hex string "0g"'));
  });
});
