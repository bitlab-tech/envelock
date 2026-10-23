/**
 * Convert a Uint8Array to a base64url string.
 * @param bytes - The Uint8Array to convert.
 * @returns A base64url string.
 */
function toBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.slice(i, i + chunkSize));
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Convert a base64url string to a Uint8Array.
 * @param str - The base64url string to convert.
 * @returns A Uint8Array.
 * @throws {Error} If the base64url string is invalid.
 */
function fromBase64Url(str: string): Uint8Array<ArrayBuffer> {
  const remainder = str.length % 4;
  if (remainder === 1) {
    throw new Error(`fromBase64Url: invalid base64url length (${str.length})`);
  }
  const padded = (str.replace(/-/g, '+').replace(/_/g, '/'))
    .padEnd(str.length + (4 - remainder) % 4, '=');
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

/**
 * Convert a Uint8Array to a hex string.
 * @param bytes - The Uint8Array to convert.
 * @returns A hex string.
 */
function toHex(bytes: Uint8Array<ArrayBuffer>): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert a hex string to a Uint8Array.
 * @param hex - The hex string to convert.
 * @returns A Uint8Array.
 * @throws {Error} If the hex string is invalid.
 */
function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`fromHex: invalid hex string "${hex}"`);
  }
  const matches = hex.match(/.{2}/g) ?? [];
  return new Uint8Array(matches.map(b => parseInt(b, 16)));
}


/**
 * Encode a string to a Uint8Array.
 * @param s - The string to encode.
 * @returns A Uint8Array.
 */
const encode = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);

export { toBase64Url, fromBase64Url, toHex, fromHex, encode };