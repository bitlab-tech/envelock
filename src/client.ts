import { rotate } from "./rotation/rotate.js";
import { signRequest } from "./auth/signer.js";
import { decryptItem } from "./envelope/decrypt.js";
import { encryptItem } from "./envelope/encrypt.js";
import { generateEd25519KeyPair } from "./identity/ed25519.js";
import { generateApiKey, parseApiKey } from "./identity/apiKey.js";
import { deriveKekSeed, deriveSigningSeed } from "./identity/keygen.js";
import type { Ed25519KeyPair, EncryptedItem, WrappedDekRecord } from "./types.js";

function assert(condition: boolean, message?: string): asserts condition {
  if (!condition) throw new Error(message ?? "Assertion failed");
}

/**
 * The EnvelopeClient class is the main class for the Envelope SDK.
 * It is used to create a new client, or to create a client from an API key.
 * It is also used to sign requests, encrypt items, decrypt items, and rotate keys.
 *
 * @example
 * const client = await EnvelopeClient.create("my-api-key-prefix");
 * const request = await client.signRequest(new Request("https://example.com"));
 * const encryptedItem = await client.encryptItem(new Uint8Array([1, 2, 3, 4, 5]));
 * const decryptedItem = await client.decryptItem(encryptedItem);
 * const rotatedItems = await client.rotate(newClient, [encryptedItem]);
 */
export class EnvelopeClient {
  private mainSeed: Uint8Array<ArrayBuffer> | undefined = undefined;
  private mainSalt: Uint8Array<ArrayBuffer> | undefined = undefined;
  private signingSeed: Uint8Array<ArrayBuffer> | undefined = undefined;
  private signingKeyPair: Ed25519KeyPair | undefined = undefined;
  private kekSeed: Uint8Array<ArrayBuffer> | undefined = undefined;

  /**
   * Private constructor to prevent direct instantiation of the class.
   */
  private constructor() {}

  /**
   * Creates a new client with a new API key.
   * @param apiKeyPrefix - The prefix of the API key.
   * @returns A tuple containing the client, the display key, and the main salt.
   */
  static async create(
    apiKeyPrefix: string
  ): Promise<{ client: EnvelopeClient, displayKey: string, mainSalt: Uint8Array<ArrayBuffer> }> {
    const client = new EnvelopeClient();
    const { seed, salt, displayKey } = generateApiKey(apiKeyPrefix);
    client.mainSeed = seed;
    client.mainSalt = salt;
    client.signingSeed = await deriveSigningSeed(client.mainSalt, client.mainSeed);
    client.signingKeyPair = await generateEd25519KeyPair(client.signingSeed);
    client.kekSeed = await deriveKekSeed(client.mainSalt, client.mainSeed);
    return { client, displayKey, mainSalt: client.mainSalt };
  }

  /**
   * Creates a new client from an API key.
   * @param displayApiKey - The display API key.
   * @param apiKeyPrefix - The prefix of the API key.
   * @returns A new client.
   */
  static async fromApiKey(displayApiKey: string, apiKeyPrefix: string): Promise<EnvelopeClient> {
    const client = new EnvelopeClient();
    const { seed, salt } = parseApiKey(displayApiKey, apiKeyPrefix);
    client.mainSeed = seed;
    client.mainSalt = salt;
    client.signingSeed = await deriveSigningSeed(client.mainSalt, client.mainSeed);
    client.signingKeyPair = await generateEd25519KeyPair(client.signingSeed);
    client.kekSeed = await deriveKekSeed(client.mainSalt, client.mainSeed);
    return client;
  }

  /**
   * Signs a request.
   * @param request - The request to sign.
   * @returns The signed request.
   */
  async signRequest(request: Request): Promise<Request> {
    this.assertInitialized();
    return await signRequest(request, this.signingKeyPair!.secretKey);
  }

  /**
   * Encrypts an item.
   * @param plaintext - The plaintext to encrypt.
   * @returns The encrypted item.
   */
  async encryptItem(plaintext: Uint8Array<ArrayBuffer>): Promise<EncryptedItem> {
    this.assertInitialized();
    if (plaintext.length === 0) throw new Error("Plaintext is empty");
    return await encryptItem({ plaintext, kekSeed: this.kekSeed! });
  }

  /**
   * Decrypts an item.
   * @param item - The encrypted item to decrypt.
   * @returns The decrypted item.
   */
  async decryptItem(item: EncryptedItem): Promise<Uint8Array<ArrayBuffer>> {
    this.assertInitialized();
    return await decryptItem({
      ...item,
      kekSeed: this.kekSeed!,
    });
  }

  /**
   * Rotates the keys of a set of wrapped DEK records. This method performs only the cryptographic operations.
   * Any other operations (e.g. network, storage) must be performed by the caller.
   * @param newClient - The new client to use for the rotation.
   * @param items - The wrapped DEK records to rotate.
   * @returns The rotated wrapped DEK records.
   */
  async rotate(newClient: EnvelopeClient, items: WrappedDekRecord[]): Promise<WrappedDekRecord[]> {
    this.assertInitialized();
    newClient.assertInitialized();
    return await rotate(items, this.kekSeed!, newClient.kekSeed!);
  }

  /**
   * Gets the public key of the client.
   * @returns The public key.
   */
  getPublicKey(): Uint8Array<ArrayBuffer> {
    this.assertInitialized();
    return this.signingKeyPair!.publicKey;
  }

  /**
   * Asserts that the client is initialized.
   * @throws An error if the client is not initialized.
   */
  private assertInitialized(): void {
    assert(this.mainSeed !== undefined, "Main seed is not set. Please call create() or fromApiKey() first.");
    assert(this.mainSalt !== undefined, "Main salt is not set. Please call create() or fromApiKey() first.");
    assert(this.signingSeed !== undefined, "Signing seed is not set. Please call create() or fromApiKey() first.");
    assert(this.signingKeyPair !== undefined, "Signing key pair is not set. Please call create() or fromApiKey() first.");
    assert(this.kekSeed !== undefined, "KEK seed is not set. Please call create() or fromApiKey() first.");
  }
}