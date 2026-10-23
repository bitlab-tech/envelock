# envelock

Framework-agnostic envelope encryption for the browser, with client-side key
derivation, Ed25519 request signing, and zero-knowledge storage: the server
never sees an API key, a derived key, or plaintext, at any point.

> **Design docs:** the reasoning and protocol behind this library live in
> [`docs/v1.md`](./docs/v1.md) (original design) and
> [`docs/v2.md`](./docs/v2.md) (fix-up addendum closing the API-key-in-transit
> gap, introducing Ed25519 request signing, and the current envelope
> encryption flow). This README covers how to *use* the library. Those docs
> cover *why* it's built this way, including the threat model, the
> alternatives considered and rejected, and the key rotation protocol.

## What this is

A user holds exactly one secret: an API key, generated client-side. The key
carries both the seed and the HKDF salt, so the salt never has to be stored
or sent to the server. From it, the library derives two independent things,
via domain-separated HKDF:

- An **Ed25519 keypair**, used to sign every request. Only the public key
  ever reaches the server.
- A **KEK seed**, used to derive a fresh, independent wrapping key for every
  item you encrypt. Each storage item gets its own random salt, its own random DEK,
  and its own AEAD-bound ciphertext.

The server authenticates requests by verifying signatures against a stored
public key, and persists only ciphertext and non-secret metadata (per-item
salts, wrapped keys, item IDs). The main salt stays inside the user's API
key. The server is never sent, and can never derive, anything capable of
decrypting user data. See [`docs/v2.md`](./docs/v2.md) for the
full protocol, diagrams, and the specific vulnerability this closes relative
to a naive "derive the key from the API key you send on every request"
design.

## Install

```bash
npm install envelock
```

Requires a runtime with the Web Crypto API (`crypto.subtle`,
`crypto.getRandomValues`, `crypto.randomUUID`): any modern browser, or
Node.js 20+.

## Quick start

### Register a new user

```typescript
import { EnvelopeClient } from "envelock";
import { toBase64Url } from "envelock/verify";

const { client, displayKey } = await EnvelopeClient.create("myapp");

// displayKey: show this to the user ONCE. It contains the seed and the main
// salt, so a later session can be restored from this string alone. There is
// no recovery if it is lost: see "Lost keys are unrecoverable, by design"
// below.
// The server only needs the public key.

await fetch("/api/register", {
  method: "POST",
  body: JSON.stringify({
    publicKey: toBase64Url(client.getPublicKey()),
  }),
});
```

### Resume a session

```typescript
const client = await EnvelopeClient.fromApiKey(
  displayKey, // what the user entered or pasted
  "myapp",    // the same prefix used at registration
);
```

### Sign a request

```typescript
const request = new Request("https://api.example.com/v1/items", {
  method: "POST",
  body: JSON.stringify({ ... }),
});

const signedRequest = await client.signRequest(request);
await fetch(signedRequest);
```

This attaches timestamp, nonce, and signature headers covering the method,
path, timestamp, nonce, and a hash of the exact request body. See
[`docs/v2.md`](./docs/v2.md) for the canonical string format and the
server-side verification/replay-protection design.

### Encrypt and decrypt an item

```typescript
const plaintext = new TextEncoder().encode("secret data");
const encrypted = await client.encryptItem(plaintext);
// { blob, itemSalt, itemUuid, encryptedDEK }
// blob and encryptedDEK are self-contained (IV prepended to each
// ciphertext): nothing else needs to be stored or transmitted alongside
// them beyond itemSalt and itemUuid.

const recovered = await client.decryptItem(encrypted);
// recovered equals plaintext: or decryptItem throws, if the ciphertext,
// AAD, or key material don't match (tampering, wrong item, wrong key).
```

### Rotate keys

```typescript
const { client: newClient, displayKey: newDisplayKey } =
  await EnvelopeClient.create("myapp");

// Show newDisplayKey to the user once. It already contains the new main salt.
// Fetch every item's { itemUuid, itemSalt, encryptedDEK } from your server first.
const rotatedItems = await client.rotate(newClient, existingItems);

// Submit rotatedItems and newClient.getPublicKey() to your server, signed with
// the OLD client (per the rotation protocol in docs/v2.md): the old key
// authorizes its own replacement, then is revoked. Do not send a main salt.
```

Rotation re-wraps every item's DEK under the new key without touching file
ciphertext or re-uploading anything: see the "Key Rotation" diagram in
[`docs/v2.md`](./docs/v2.md) for the full client/server sequence, including
why the submission step is still signed with the old key.

## Server-side verification

Import from the `envelock/verify` subpath: a deliberately narrow surface
containing only what a server needs to verify signed requests. It has no
access to signing, key derivation, or encryption functions. Those are only
reachable from the main `envelock` entry point, which is meant for
client-side use.

```typescript
import { buildCanonicalString, verifyEd25519 } from "envelock/verify";

// Rebuild the identical canonical string the client signed, from the
// request your server actually received: not from client-claimed values.
const canonical = await buildCanonicalString(request);

const isValid = verifyEd25519(
  storedPublicKey,
  new TextEncoder().encode(canonical),
  signatureFromHeader,
);
```

Your server is responsible for the surrounding checks that make this a
complete authentication scheme: timestamp tolerance validation, atomic
nonce-uniqueness enforcement, and looking up the stored public key for the
claimed sender. The full server-side flow, including why nonce handling
needs to be an atomic `(pubkey, nonce)` insert rather than a
check-then-write, is documented in [`docs/v2.md`](./docs/v2.md)'s
"Authentication" section and diagram.

**One practical note:** `buildCanonicalString` hashes the exact raw bytes of
the request body. Most server frameworks parse and consume the body stream
before your own middleware runs, which means you'll typically need to
configure raw-body capture ahead of the body parser on routes that verify
signed requests, so the bytes you hash match what the client actually sent.

## Why two entry points

| Import path | Contains | Intended for |
|---|---|---|
| `envelock` | `EnvelopeClient` and its full capability: key derivation, signing, encryption, rotation | Browser clients |
| `envelock/verify` | `buildCanonicalString`, `verifyEd25519`, and other pure, secret-free utilities | Backend servers |

This split is enforced by the package's `exports` map, not just by
convention: `envelock/client` or any other internal path is not resolvable
from outside the package. A server importing `envelock/verify` has no way to
reach key-derivation or signing code, even by accident.

## Security properties

Summarized from [`docs/v2.md`](./docs/v2.md): see that document for the
full reasoning and the specific attack each property closes:

- **The server never transmits, stores, or can derive anything capable of
  decrypting user data.** A full database and traffic compromise exposes
  only public keys, ciphertext, and non-secret per-item salts and IDs. The
  main salt is part of the user's API key and is not stored on the server.
- **No credential reuse window.** Requests are signed, not bearer-token
  authenticated. A captured signed request is useless outside its
  nonce/timestamp window.
- **Per-item isolation.** Every item has its own salt, its own randomly
  generated DEK, and its own AAD-bound ciphertext. A single leaked wrapped
  key exposes exactly one item, not a user's entire history.
- **Tamper-evidence via AAD.** Both AEAD operations (file encryption and
  DEK-wrapping) bind the item's own ID as associated data: a storage-layer
  swap between two valid ciphertexts fails decryption outright rather than
  silently succeeding against the wrong context.
- **Lost keys are unrecoverable, by design.** There is no account-recovery
  flow. A user who loses their API key loses access to their data
  permanently: any mechanism that could recover it would equally have
  allowed a party other than the user to decrypt their data, which defeats
  the purpose of the design. Show the key once at generation, and make sure
  your UI gets explicit confirmation it's been saved.

## Project structure

```
src/
├── core/        : primitives with no domain knowledge (random, encoding,
│                  hashing, HKDF, AES-GCM, shared constants)
├── identity/    : API key generation/parsing, Ed25519 keypair derivation
├── auth/        : canonical request strings, nonce generation, request signing
├── envelope/    : per-item key derivation, encryption, decryption
├── rotation/    : key rotation (unwrap-under-old, rewrap-under-new)
├── client.ts    : EnvelopeClient, the public client-facing API
├── types.ts     : shared type definitions
├── client/      : public export surface for browser consumers (re-exports client.ts)
└── shared/      : public export surface for server consumers (re-exports
                     only secret-free verification utilities)
```

`core/` has no awareness of API keys, items, or requests: it's reusable
cryptographic plumbing. Every layer above it adds domain meaning but never
reaches backward into a lower layer's internals. `identity/` is the only
place that ever handles the main seed or private key directly. Every other
module receives already-derived, scoped material.

## Development

```bash
npm install
npm run build        # compile to dist/
npm run dev           # compile in watch mode
npm run typecheck      # type-check src/ and test/
npm test                # run the test suite
npm run test:watch       # run tests in watch mode
```

## License

MIT