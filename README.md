# envelock

Framework-agnostic envelope encryption for Node.js. A random data key encrypts your payload. A key derived from a secret encrypts that data key. The secret never has to be stored.

AES-256-GCM is built in. Key derivation is pluggable: PBKDF2 and scrypt ship with Node, Argon2id is optional. NestJS can inject the same core through a dynamic module.

The design is motivated by anonymous storage: systems that have no account and no server-side identity, only an API key. The write-up in [docs/README.md](docs/README.md) covers why plaintext storage, a server-managed key, and using the API key itself as the cipher key each fall short, and how an API-key-derived envelope (KEK wraps a random DEK, nothing long-lived is stored) provides per-user isolation, key rotation by re-wrapping, and the limits of that model.

## Install

```bash
npm install envelock
```

Argon2id needs the optional native package:

```bash
npm install argon2
```

NestJS usage needs `@nestjs/common` (optional peer dependency).

## How it works

```
secret (API key, token, …)
        │
        ▼
   KDF + salt  ──►  KEK          (derived per request, never stored)
        │
        ▼
   AES-256-GCM ──►  encrypted DEK   (persisted)
        │
        ▼
   AES-256-GCM ──►  ciphertext      (your data)
```

1. **Create.** Generate an API key, derive a key-encryption key (KEK) from it, generate a data-encryption key (DEK), and encrypt the DEK with the KEK.
2. **Store.** Persist the API key hash, the salt, and the encrypted DEK. Return the raw API key to the caller once.
3. **Use.** Hash the presented API key to look up the record, re-derive the KEK, decrypt the DEK, then encrypt or decrypt data. Zero the DEK when you are done.

GCM authentication tags reject a wrong key and tampered ciphertext.

## Quick start

```ts
import { EnvelopeCore, PBKDF2Strategy } from 'envelock';

const envelope = new EnvelopeCore({
  apiKey: { prefix: 'ev' },
  kdf: { strategy: new PBKDF2Strategy() },
});

// Once, when issuing a key
const { apiKey, hash } = envelope.generateApiKey();
const material = await envelope.generateKeyMaterial(apiKey);

// Persist `hash`, `material.salt`, and `material.encryptedDek`.
// Hand `apiKey` to the caller. Do not store it.

// On each request
const dek = await envelope.resolveDataKey(apiKey, material);
try {
  const encrypted = envelope.encrypt(Buffer.from('payload'), dek);
  const plain = envelope.decrypt(encrypted, dek);
} finally {
  dek.fill(0);
}
```

`EncryptedPayload` is three `Buffer`s: `ciphertext`, `iv`, and `authTag`. Encode them (for example base64) before writing to a database, and decode them before calling `decrypt` or `resolveDataKey`.

## NestJS

`EnvelopeEncryptionModule` is global by default and exports `EnvelopeEncryptionService`, which is `EnvelopeCore` with dependency injection.

```ts
import { Module } from '@nestjs/common';
import { EnvelopeEncryptionModule, PBKDF2Strategy } from 'envelock';

@Module({
  imports: [
    EnvelopeEncryptionModule.forRoot({
      apiKey: { prefix: 'ev' },
      kdf: { strategy: new PBKDF2Strategy() },
    }),
  ],
})
export class AppModule {}
```

Async registration, for example from `ConfigService`:

```ts
EnvelopeEncryptionModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    apiKey: { prefix: config.getOrThrow('API_KEY_PREFIX') },
    kdf: { strategy: new PBKDF2Strategy() },
  }),
});
```

Pass `isGlobal: false` when the module should stay local to the importing module.

```ts
constructor(private readonly envelope: EnvelopeEncryptionService) {}
```

## Choosing a KDF

| Strategy | Dependency | Use when |
| --- | --- | --- |
| `PBKDF2Strategy` | none | The secret is high-entropy (API keys, random tokens). Default is 600,000 iterations of HMAC-SHA256. |
| `ScryptStrategy` | none | You want a memory-hard KDF without a native addon. Default cost is `N = 16384`, `r = 8`, `p = 1`. |
| `Argon2idStrategy` | `argon2` | You want the memory-hard default for passwords. Default is 64 MiB, 3 iterations, parallelism 1. |

PBKDF2 is fast to attack on GPUs when the secret is a user-chosen password. Use scrypt or Argon2id for those secrets.

```ts
import { ScryptStrategy, Argon2idStrategy } from 'envelock';

new ScryptStrategy({ N: 16384, r: 8, p: 1 });
new Argon2idStrategy({ memoryCost: 65536, timeCost: 3, parallelism: 1 });
```

Instantiating `Argon2idStrategy` without `argon2` installed throws when `derive` runs, with a message that names the missing package.

## API

### `EnvelopeCore`

| Method | Returns | Role |
| --- | --- | --- |
| `generateApiKey()` | `{ apiKey, hash }` | Random key `{prefix}_{secret}` plus its SHA-256 hex hash. |
| `hashApiKey(apiKey)` | `string` | SHA-256 hex digest for lookup. |
| `generateKeyMaterial(secret)` | `{ salt, encryptedDek }` | Salt, KEK, DEK, and encrypted DEK. KEK and raw DEK are zeroed before return. |
| `resolveDataKey(secret, material)` | `Buffer` | Re-derives the KEK, decrypts the DEK, zeroes the KEK. Caller zeroes the DEK. |
| `encrypt(data, key)` | `EncryptedPayload` | AES-256-GCM with a fresh IV. |
| `decrypt(payload, key)` | `Buffer` | Throws when the auth tag does not match. |
| `generateDEK()` / `encryptDEK()` / `decryptDEK()` | | Lower-level DEK helpers. `generateKeyMaterial` and `resolveDataKey` cover the usual path. |
| `generateSalt()` / `deriveKEK(secret, salt)` | | Lower-level KDF helpers. |

### Config

```ts
interface EnvelopeConfig {
  apiKey: {
    prefix: string;
    secretLength?: number; // default 32 bytes, encoded base64url
  };
  kdf: {
    strategy: KDFStrategy;
  };
  aes?: {
    algorithm?: string; // default 'aes-256-gcm'
    ivLength?: number;  // default 12
    keyLength?: number; // default 32
  };
}
```

Bring your own `KDFStrategy` by implementing `derive(secret, salt)` and `generateSalt()`.

## What to persist

| Value | Store it? |
| --- | --- |
| Raw API key | No. Return it once. |
| API key hash | Yes. Lookup key. |
| Salt | Yes. Required to re-derive the KEK. |
| Encrypted DEK (`ciphertext`, `iv`, `authTag`) | Yes. |
| KEK or raw DEK | No. Derive and decrypt in memory, then `buffer.fill(0)`. |

## License

MIT
