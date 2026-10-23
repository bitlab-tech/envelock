/**
 * The number of bytes in a seed.
 */
export const SEED_BYTES = 32;

/**
 * The number of bytes in a salt.
 */
export const SALT_BYTES = 32;

/**
 * The number of bytes in an IV.
 */
export const IV_BYTES = 12;

/**
 * Application-level sanity bound on HKDF info length (not a cryptographic
 * requirement - HKDF itself has no hard limit on info size). Prevents
 * accidentally passing oversized or malformed labels.
 */
export const MAX_INFO_BYTES = 64;

/**
 * The number of bytes in a KEK.
 */
export const KEK_BYTES = 32;

/**
 * The number of bytes in a DEK.
 */
export const DEK_BYTES = 32;

/**
 * The number of bytes in an AES-GCM key.
 */
export const AES_GCM_KEY_BYTES = 32;

/**
 * The number of bytes in an Ed25519 public or secret key.
 */
export const ED25519_KEY_BYTES = 32;

/**
 * The number of bytes in an Ed25519 signature.
 */
export const ED25519_SIGNATURE_BYTES = 64;

/**
 * The name of the Envelock timestamp header.
 */
export const ENVELOCK_TIMESTAMP_HEADER = "X-Envelock-Timestamp";

/**
 * The name of the Envelock nonce header.
 */
export const ENVELOCK_NONCE_HEADER = "X-Envelock-Nonce";

/**
 * The name of the Envelock signature header.
 */
export const ENVELOCK_AUTH_HEADER = "X-Envelock-Auth";

/**
 * The type of hash function used for HKDF.
 */
export type HashFunction = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * The number of bytes in the hash function output.
 */
export const HASH_BYTES = {
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
} as const;

/**
 * HKDF info labels for domain-separated key derivation. Each label must be
 * unique across the system. Reusing a label between two derivations that
 * are meant to be independent will collapse the domain separation they rely on.
 */
export const HKDF_INFO = {
  SIGNING_SEED: "signing-v1",
  KEK_SEED: "kek-v1",
  ITEM_KEK_PREFIX: "kek-item-v1:", // concatenated with itemUuid at call site
} as const;