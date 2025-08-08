/**
 * ML-KEM-768, a post-quantum key encapsulation mechanism in WebAssembly,
 * based on mlkem-native <https://github.com/pq-code-package/mlkem-native>.
 *
 * Provides an API compatible with the WebCrypto API proposed in
 * "Modern Algorithms in the Web Cryptography API,"
 * Draft Community Group Report, 08 August 2025:
 * <https://twiss.github.io/webcrypto-modern-algos/>.
 *
 * mlkem-native license:
 * https://github.com/pq-code-package/mlkem-native/blob/main/LICENSE
 *
 * WASM wrapper license: MIT License
 * Copyright (c) 2023 Dmitry Chestnykh
 */
import MLKEM768Module from "./build/wasm-module.js";

const ALGORITHM_NAME = "ML-KEM-768";
const JWK_ALG = "MLKEM768";

export type MlKemAlgorithm =
  | { name: typeof ALGORITHM_NAME }
  | typeof ALGORITHM_NAME;

const KEY_USAGES = [
  "encapsulateKey",
  "encapsulateBits",
  "decapsulateKey",
  "decapsulateBits",
] as const;

export type MlKemKeyUsage = (typeof KEY_USAGES)[number];
export type MlKemKeyFormat = "raw-public" | "raw-seed" | "jwk";

class MlKemOperationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OperationError";
  }
}

class MlKemInvalidAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidAccessError";
  }
}

class MlKemNotSupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotSupportedError";
  }
}

class MlKemDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DataError";
  }
}

const _publicKeyData = Symbol();
const _privateSeed = Symbol();
const _privateSecretKey = Symbol();

class MlKemCryptoKey {
  #algorithm: MlKemAlgorithm;
  #type: Omit<KeyType, "secret">;
  #usages: MlKemKeyUsage[];
  #extractable: boolean;
  #publicKeyData: Uint8Array<ArrayBuffer>;
  #privateSeed: Uint8Array<ArrayBuffer> | null;
  #privateSecretKey: Uint8Array<ArrayBuffer> | null;

  constructor(
    algorithm: MlKemAlgorithm,
    type: Omit<KeyType, "secret">,
    usages: MlKemKeyUsage[],
    extractable: boolean,
    publicKeyData: Uint8Array<ArrayBuffer>,
    privateSeed: Uint8Array<ArrayBuffer> | null = null,
    privateSecretKey: Uint8Array<ArrayBuffer> | null = null
  ) {
    this.#algorithm = algorithm;
    this.#type = type;
    this.#usages = usages;
    this.#extractable = extractable;
    this.#publicKeyData = publicKeyData;
    this.#privateSeed = privateSeed;
    this.#privateSecretKey = privateSecretKey;
  }

  get algorithm() {
    return this.#algorithm;
  }

  get type() {
    return this.#type;
  }

  get usages() {
    return this.#usages;
  }

  get extractable() {
    return this.#extractable;
  }

  get [_publicKeyData]() {
    return this.#publicKeyData;
  }

  get [_privateSeed]() {
    return this.#privateSeed;
  }

  get [_privateSecretKey]() {
    return this.#privateSecretKey;
  }
}

export type { MlKemCryptoKey };

function toBase64url(data: Uint8Array<ArrayBuffer>): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64url(base64url: string): Uint8Array<ArrayBuffer> {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "===".slice((base64.length + 3) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

const PUBLICKEY_BYTES = 1184;
const SECRETKEY_BYTES = 2400;
const CIPHERTEXT_BYTES = 1088;
const SHARED_SECRET_BYTES = 32;
const KEYPAIR_RANDOM_BYTES = 64;
const ENC_RANDOM_BYTES = 32;

class MlKem768 {
  #module: any | undefined;

  async #getModule() {
    if (!this.#module) {
      this.#module = await MLKEM768Module();
    }
    return this.#module;
  }

  #checkAlgorithm(algorithm: MlKemAlgorithm) {
    const name =
      typeof algorithm === "string"
        ? algorithm
        : typeof algorithm === "object" && algorithm !== null
        ? algorithm.name
        : null;
    if (name !== ALGORITHM_NAME) {
      throw new TypeError("Unsupported algorithm");
    }
  }

  async #generateKeyPair(coins: Uint8Array<ArrayBuffer>) {
    const module = await this.#getModule();
    const stackSave = module.stackSave();
    try {
      const pkPtr = module.stackAlloc(PUBLICKEY_BYTES);
      const skPtr = module.stackAlloc(SECRETKEY_BYTES);
      const coinsPtr = module.stackAlloc(KEYPAIR_RANDOM_BYTES);

      module.HEAPU8.set(coins, coinsPtr);

      const result = module._mlkem768_keypair_derand(pkPtr, skPtr, coinsPtr);
      if (result !== 0) {
        throw new MlKemOperationError("Key generation failed");
      }

      const rawPublicKey = new Uint8Array(PUBLICKEY_BYTES);
      const rawSecretKey = new Uint8Array(SECRETKEY_BYTES);
      const rawSeed = new Uint8Array(coins);

      rawPublicKey.set(module.HEAPU8.subarray(pkPtr, pkPtr + PUBLICKEY_BYTES));
      rawSecretKey.set(module.HEAPU8.subarray(skPtr, skPtr + SECRETKEY_BYTES));

      module.HEAPU8.fill(0, pkPtr, pkPtr + PUBLICKEY_BYTES);
      module.HEAPU8.fill(0, skPtr, skPtr + SECRETKEY_BYTES);
      module.HEAPU8.fill(0, coinsPtr, coinsPtr + KEYPAIR_RANDOM_BYTES);
      return { rawPublicKey, rawSecretKey, rawSeed };
    } finally {
      module.stackRestore(stackSave);
    }
  }

  async generateKey(
    keyAlgorithm: MlKemAlgorithm,
    extractable: boolean,
    usages: MlKemKeyUsage[]
  ) {
    this.#checkAlgorithm(keyAlgorithm);

    // 1. If usages contains any entry which is not one of "encapsulateKey",
    // "encapsulateBits", "decapsulateKey" or "decapsulateBits", then throw a
    // SyntaxError.
    if (
      !Array.isArray(usages) ||
      usages.some((usage) => !KEY_USAGES.includes(usage))
    ) {
      throw new SyntaxError("Invalid key usages");
    }

    // 2. Generate an ML-KEM key pair, as described in Section 7.1 of
    // [FIPS-203], with the parameter set indicated by the name member of
    // normalizedAlgorithm.
    const { rawPublicKey, rawSecretKey, rawSeed } = await this.#generateKeyPair(
      crypto.getRandomValues(new Uint8Array(KEYPAIR_RANDOM_BYTES))
    );

    // 3. If the key generation step fails, then throw an OperationError.
    // (Handled by the #generateKeyPair method)

    // 4. Let algorithm be a new KeyAlgorithm object.
    // 5. Set the name attribute of algorithm to the name attribute of
    // normalizedAlgorithm.
    const algorithm = { name: ALGORITHM_NAME } as const;

    // 6. Let publicKey be a new CryptoKey representing the encapsulation key
    // of the generated key pair.
    // 7. Set the [[type]] internal slot of publicKey to "public".
    // 8. Set the [[algorithm]] internal slot of publicKey to algorithm.
    // 9. Set the [[extractable]] internal slot of publicKey to true.
    // 10. Set the [[usages]] internal slot of publicKey to be the usage
    // intersection of usages and [ "encapsulateKey", "encapsulateBits" ].
    const publicKey = new MlKemCryptoKey(
      algorithm,
      "public",
      usages.filter(
        (usage) => usage === "encapsulateKey" || usage === "encapsulateBits"
      ),
      true,
      rawPublicKey
    );

    // 11. Let privateKey be a new CryptoKey representing the decapsulation key
    // of the generated key pair.
    // 12. Set the [[type]] internal slot of privateKey to "private".
    // 13. Set the [[algorithm]] internal slot of privateKey to algorithm.
    // 14. Set the [[extractable]] internal slot of privateKey to extractable.
    // 15. Set the [[usages]] internal slot of privateKey to be the usage
    // intersection of usages and [ "decapsulateKey", "decapsulateBits" ].
    const privateKey = new MlKemCryptoKey(
      algorithm,
      "private",
      usages.filter(
        (usage) => usage === "decapsulateKey" || usage === "decapsulateBits"
      ),
      extractable,
      rawPublicKey,
      rawSeed,
      rawSecretKey
    );
    // 16. Let result be a new CryptoKeyPair dictionary.
    // 17. Set the publicKey attribute of result to be publicKey.
    // 18. Set the privateKey attribute of result to be privateKey.
    // 19. Return result.
    return {
      publicKey,
      privateKey,
    };
  }

  async exportKey(format: MlKemKeyFormat, key: MlKemCryptoKey) {
    // 1. If the underlying cryptographic key material represented by the
    // [[handle]] internal slot of key cannot be accessed, then throw an
    // OperationError.
    if (!key.extractable) {
      throw new MlKemOperationError("Key is not extractable");
    }

    // 2. If format is "raw-public":
    if (format === "raw-public") {
      // 2.1. If the [[type]] internal slot of key is not "public", then throw
      // an InvalidAccessError.
      if (key.type !== "public") {
        throw new TypeError("Expected key type to be 'public'");
      }
      // 2.2. Let data be a byte sequence containing the raw octets of the key
      // represented by the [[handle]] internal slot of key.
      // 2.3. Let result be data.
      return new Uint8Array(key[_publicKeyData]).buffer;
    }
    // 2. If format is "raw-seed":
    if (format === "raw-seed") {
      // 2.1 If the [[type]] internal slot of key is not "private", then throw
      // an InvalidAccessError.
      if (key.type !== "private") {
        throw new MlKemInvalidAccessError("Expected key type to be 'private'");
      }
      // 2.2 Let data be a byte sequence containing the concatenation of the d
      // and z seed variables of the key represented by the [[handle]] internal
      // slot of key.
      // 3.3. Let result be data.
      return new Uint8Array(key[_privateSeed]!).buffer;
    }
    // 2. If format is "jwk":
    if (format === "jwk") {
      // 2.1. Let jwk be a new JsonWebKey dictionary.
      const jwk = {
        // 2.2. Set the kty attribute of jwk to "AKP".
        kty: "AKP",
        // 2.3. Set the alg attribute of jwk to the alg value corresponding to
        // the name member of normalizedAlgorithm indicated in Section 8 of
        // [draft-ietf-jose-pqc-kem-01] (Figure 1).
        alg: JWK_ALG,
        // 2.4. Set the pub attribute of jwk to the base64url encoded public
        // key corresponding to the [[handle]] internal slot of key.
        pub: toBase64url(key[_publicKeyData]),
      } as any;
      // 2.5. If the [[type]] internal slot of key is "private":
      if (key.type === "private") {
        // 2.5.1. Set the priv attribute of jwk to the base64url encoded
        // private key corresponding to the [[handle]] internal slot of key.
        jwk.priv = toBase64url(key[_privateSeed]!);
      }
      // 2.6. Set the key_ops attribute of jwk to the usages attribute of key.
      jwk.key_ops = key.usages;
      // 2.7. Set the ext attribute of jwk to the [[extractable]] internal slot
      // of key.
      jwk.ext = key.extractable;

      // 2.8. Let result be jwk.
      return jwk as JsonWebKey;
    }
    // 2. Otherwise: throw a NotSupportedError.
    throw new MlKemNotSupportedError("Format not supported");
  }

  async importKey(
    format: MlKemKeyFormat,
    keyData: ArrayBuffer | ArrayBufferView<ArrayBuffer>,
    algorithm: MlKemAlgorithm,
    extractable: boolean,
    usages: MlKemKeyUsage[]
  ) {
    this.#checkAlgorithm(algorithm);
    // 1. If format is "raw-public":
    if (format === "raw-public") {
      // 1.1. If usages contains an entry which is not "encapsulateKey" or
      // "encapsulateBits" then throw a SyntaxError.
      if (
        !Array.isArray(usages) ||
        usages.some(
          (usage) => usage !== "encapsulateKey" && usage !== "encapsulateBits"
        )
      ) {
        throw new SyntaxError("Invalid key usages for public key");
      }
      // 1.2. Let data be keyData.
      const data = ArrayBuffer.isView(keyData)
        ? new Uint8Array(keyData.buffer, keyData.byteOffset, keyData.byteLength)
        : new Uint8Array(keyData);
      // 1.3. Let key be a new CryptoKey that represents the ML-KEM public key
      // data in data.
      // 1.4. Set the [[type]] internal slot of key to "public"
      // 1.5. Let algorithm be a new KeyAlgorithm.
      // 1.6. Set the name attribute of algorithm to the name attribute of
      // normalizedAlgorithm.
      // 1.7. Set the [[algorithm]] internal slot of key to algorithm.
      return new MlKemCryptoKey(
        { name: ALGORITHM_NAME } as MlKemAlgorithm,
        "public",
        usages,
        true, // extractable
        data
      );
    }
    if (format === "raw-seed") {
      // 1.1. If usages contains an entry which is not "decapsulateKey" or
      // "decapsulateBits" then throw a SyntaxError.
      if (
        !Array.isArray(usages) ||
        usages.some(
          (usage) => usage !== "decapsulateKey" && usage !== "decapsulateBits"
        )
      ) {
        throw new SyntaxError("Invalid key usages for private key");
      }
      // 1.2. Let data be keyData.
      const data = ArrayBuffer.isView(keyData)
        ? new Uint8Array(keyData.buffer, keyData.byteOffset, keyData.byteLength)
        : new Uint8Array(keyData);
      // 1.3. If the length in bits of data is not 512 then throw a DataError.
      if (data.length !== KEYPAIR_RANDOM_BYTES) {
        throw new MlKemDataError("Invalid key length");
      }
      // 1.4. Let privateKey be the result of performing the
      // ML-KEM.KeyGen_internal function described in Section 6.1 of [FIPS-203]
      // with the parameter set indicated by the name member of
      // normalizedAlgorithm, using the first 256 bits of data as d and the
      // last 256 bits of data as z.
      const { rawPublicKey, rawSecretKey, rawSeed } =
        await this.#generateKeyPair(data);
      // 1.5. Let key be a new CryptoKey that represents the ML-KEM private key
      // identified by privateKey.
      // 1.6. Set the [[type]] internal slot of key to "private"
      // 1.7. Let algorithm be a new KeyAlgorithm.
      // 1.8. Set the name attribute of algorithm to the name attribute of
      // normalizedAlgorithm.
      // 1.9. Set the [[algorithm]] internal slot of key to algorithm.
      return new MlKemCryptoKey(
        { name: ALGORITHM_NAME } as MlKemAlgorithm,
        "private",
        usages,
        true, // extractable
        rawPublicKey,
        rawSeed,
        rawSecretKey
      );
    }
    // 1. If format is "jwk":
    if (format === "jwk") {
      // 1.1.If keyData is a JsonWebKey dictionary:
      // Let jwk equal keyData.
      // Otherwise: Throw a DataError.
      if (typeof keyData !== "object" || keyData === null) {
        throw new MlKemDataError(
          "Expected keyData to be a JsonWebKey dictionary"
        );
      }
      const jwk = keyData as any;
      // 1.2. If the priv field of jwk is present and if usages contains an
      // entry which is not "decapsulateKey" or "decapsulateBits" then throw a
      // SyntaxError.
      if (
        jwk.priv &&
        usages.some(
          (usage) => usage !== "decapsulateKey" && usage !== "decapsulateBits"
        )
      ) {
        throw new SyntaxError("Invalid key usages for private key");
      }
      // 1.3. If the priv field of jwk is not present and if usages contains an
      // entry which is not "encapsulateKey" or "encapsulateBits" then throw a
      // SyntaxError.
      if (
        !jwk.priv &&
        usages.some(
          (usage) => usage !== "encapsulateKey" && usage !== "encapsulateBits"
        )
      ) {
        throw new SyntaxError("Invalid key usages for public key");
      }
      // 1.4. If the kty field of jwk is not "AKP", then throw a DataError.
      if (jwk.kty !== "AKP") {
        throw new MlKemDataError("Invalid key type");
      }
      // 1.5. If the alg field of jwk is not one of the alg values
      // corresponding to the name member of normalizedAlgorithm indicated in
      // Section 8 of [draft-ietf-jose-pqc-kem-01] (Figure 1 or 2), then throw
      // a DataError.
      if (jwk.alg !== JWK_ALG && jwk.alg !== "ML-KEM-768+A192KW") {
        throw new MlKemDataError("Invalid algorithm");
      }
      // 1.6. If usages is non-empty and the use field of jwk is present and is
      // not equal to "enc", then throw a DataError.
      if (usages.length > 0 && jwk.use && jwk.use !== "enc") {
        throw new MlKemDataError("Invalid key usage");
      }
      // 1.7. If the key_ops field of jwk is present, and is invalid according
      // to the requirements of JSON Web Key [JWK], or it does not contain all
      // of the specified usages values, then throw a DataError.
      if (
        (jwk.key_ops &&
          Array.isArray(jwk.key_ops) &&
          !Array.prototype.every.call(jwk.key_ops, (op: any) =>
            KEY_USAGES.includes(op)
          )) ||
        !Array.isArray(jwk.key_ops)
      ) {
        throw new MlKemDataError("Invalid key operations");
      }
      // 1.8. If the ext field of jwk is present and has the value false and
      // extractable is true, then throw a DataError.
      if (jwk.ext === false && extractable) {
        throw new MlKemDataError("Invalid key extractability");
      }
      // 1.9. If the priv field of jwk is present:
      if (jwk.priv) {
        // 1.9.1. If the priv attribute of jwk does not contain a valid
        // base64url encoded seed representing an ML-KEM private key, then
        // throw a DataError.
        try {
          const seedData = fromBase64url(jwk.priv);
          if (seedData.length !== KEYPAIR_RANDOM_BYTES) {
            throw new MlKemDataError("Invalid private key length");
          }
          // 1.9.2. Let key be a new CryptoKey object that represents the
          // ML-KEM private key identified by interpreting the priv attribute
          // of jwk as a base64url encoded seed.
          const { rawPublicKey, rawSecretKey, rawSeed } =
            await this.#generateKeyPair(seedData);
          // 1.9.3. Set the [[type]] internal slot of Key to "private".
          const key = new MlKemCryptoKey(
            { name: ALGORITHM_NAME } as MlKemAlgorithm,
            "private",
            usages,
            extractable,
            rawPublicKey,
            rawSeed,
            rawSecretKey
          );
          // 1.9.4. If the pub attribute of jwk does not contain the base64url
          // encoded public key representing the ML-KEM public key
          // corresponding to key, then throw a DataError.
          if (toBase64url(rawPublicKey) !== jwk.pub) {
            throw new MlKemDataError("Invalid public key data");
          }
          return key;
        } catch {
          throw new MlKemDataError("Invalid private key format");
        }
      } else {
        // 1.9.1. If the pub attribute of jwk does not contain a valid
        // base64url encoded public key representing an ML-KEM public key, then
        // throw a DataError.
        try {
          const publicKeyData = fromBase64url(jwk.pub);
          if (publicKeyData.length !== PUBLICKEY_BYTES) {
            throw new MlKemDataError("Invalid public key data");
          }
          // 1.9.2. Let key be a new CryptoKey object that represents the
          // ML-KEM public key identified by interpreting the pub attribute of
          // jwk as a base64url encoded public key.
          return new MlKemCryptoKey(
            { name: ALGORITHM_NAME } as MlKemAlgorithm,
            "public",
            usages,
            extractable,
            publicKeyData
          );
        } catch {
          throw new MlKemDataError("Invalid public key format");
        }
      }
    }
    throw new MlKemNotSupportedError("Unsupported key format");
  }

  // Internal: implements encapsulateBits without checking key usages.
  async #encapsulate(
    algorithm: MlKemAlgorithm,
    encapsulationKey: MlKemCryptoKey,
    usage: MlKemKeyUsage
  ) {
    const module = await this.#getModule();
    this.#checkAlgorithm(algorithm);

    // 1. If the [[type]] internal slot of key is not "public", then throw an
    // InvalidAccessError.
    if (
      !(encapsulationKey instanceof MlKemCryptoKey) ||
      encapsulationKey.type !== "public"
    ) {
      throw new MlKemInvalidAccessError(
        "Expected publicKey to be an instance of MlKemCryptoKey with type 'public'"
      );
    }
    if (!encapsulationKey.usages.includes(usage)) {
      throw new MlKemInvalidAccessError(`Key usages don't include '${usage}'`);
    }
    // 2. Perform the encapsulation key check described in Section 7.2 of
    // [FIPS-203] with the parameter set indicated by the name member of
    // algorithm, using the key represented by the [[handle]] internal slot of
    // key as the ek input parameter.
    // 3. If the encapsulation key check failed, return an OperationError.
    // (Note: this is done by _mlkem768_enc_derand)

    const publicKeyData = encapsulationKey[_publicKeyData];
    if (publicKeyData.length !== PUBLICKEY_BYTES) {
      throw new MlKemOperationError("Invalid public key length");
    }

    // 4. Let sharedKey and ciphertext be the outputs that result from
    // performing the ML-KEM.Encaps function described in Section 7.2 of
    // [FIPS-203] with the parameter set indicated by the name member of
    // algorithm, using the key represented by the [[handle]] internal slot of
    // key as the ek input parameter.
    const coins = crypto.getRandomValues(new Uint8Array(ENC_RANDOM_BYTES));
    const stackSave = module.stackSave();
    try {
      const pkPtr = module.stackAlloc(PUBLICKEY_BYTES);
      const ctPtr = module.stackAlloc(CIPHERTEXT_BYTES);
      const ssPtr = module.stackAlloc(SHARED_SECRET_BYTES);
      const coinsPtr = module.stackAlloc(ENC_RANDOM_BYTES);

      module.HEAPU8.set(publicKeyData, pkPtr);
      module.HEAPU8.set(coins, coinsPtr);

      const result = module._mlkem768_enc_derand(ctPtr, ssPtr, pkPtr, coinsPtr);

      // If the ML-KEM.Encaps function returned an error, return an OperationError.
      if (result !== 0) {
        throw new MlKemOperationError("Encapsulation failed");
      }

      const ciphertext = new Uint8Array(CIPHERTEXT_BYTES);
      const sharedKey = new Uint8Array(SHARED_SECRET_BYTES);

      ciphertext.set(module.HEAPU8.subarray(ctPtr, ctPtr + CIPHERTEXT_BYTES));
      sharedKey.set(module.HEAPU8.subarray(ssPtr, ssPtr + SHARED_SECRET_BYTES));

      module.HEAPU8.fill(0, ctPtr, ctPtr + CIPHERTEXT_BYTES);
      module.HEAPU8.fill(0, ssPtr, ssPtr + SHARED_SECRET_BYTES);
      module.HEAPU8.fill(0, pkPtr, pkPtr + PUBLICKEY_BYTES);
      module.HEAPU8.fill(0, coinsPtr, coinsPtr + ENC_RANDOM_BYTES);

      // 6. Let result be a new EncapsulatedBits dictionary.
      // 7. Set the sharedKey attribute of result to the result of creating an
      // ArrayBuffer containing sharedKey.
      // 8. Set the ciphertext attribute of result to the result of creating an
      // ArrayBuffer containing ciphertext.
      // 9. Return result.
      return {
        ciphertext: ciphertext.buffer,
        sharedKey: sharedKey.buffer,
      };
    } finally {
      module.stackRestore(stackSave);
    }
  }

  async encapsulateBits(
    algorithm: MlKemAlgorithm,
    encapsulationKey: MlKemCryptoKey
  ) {
    return this.#encapsulate(algorithm, encapsulationKey, "encapsulateBits");
  }

  async encapsulateKey(
    encapsulationAlgorithm: MlKemAlgorithm,
    encapsulationKey: MlKemCryptoKey,
    sharedKeyAlgorithm: KeyAlgorithm,
    extractable: boolean,
    usages: KeyUsage[]
  ) {
    const { sharedKey: sharedKeyBits, ciphertext } = await this.#encapsulate(
      encapsulationAlgorithm,
      encapsulationKey,
      "encapsulateKey"
    );
    const sharedKey = await crypto.subtle.importKey(
      "raw",
      sharedKeyBits,
      sharedKeyAlgorithm,
      extractable,
      usages
    );
    return {
      sharedKey,
      ciphertext,
    };
  }

  // Internal: implements decapsulateBits without checking key usages.
  async #decapsulate(
    algorithm: MlKemAlgorithm,
    decapsulationKey: MlKemCryptoKey,
    ciphertext: BufferSource,
    usage: MlKemKeyUsage
  ) {
    const module = await this.#getModule();
    this.#checkAlgorithm(algorithm);

    // 1. If the [[type]] internal slot of key is not "private", then throw an InvalidAccessError.
    if (
      !(decapsulationKey instanceof MlKemCryptoKey) ||
      decapsulationKey.type !== "private"
    ) {
      throw new MlKemInvalidAccessError(
        "Expected key to be an instance of MlKemCryptoKey with type 'private'"
      );
    }
    if (!decapsulationKey.usages.includes(usage)) {
      throw new MlKemInvalidAccessError(`Key usages don't include '${usage}'`);
    }

    // 2. Perform the decapsulation input check described in Section 7.3 of
    // [FIPS-203] with the parameter set indicated by the name member of
    // algorithm, using the key represented by the [[handle]] internal slot of
    // key as the dk input parameter, and ciphertext as the c input parameter.
    // 3. If the decapsulation key check failed, return an OperationError.
    // (Note: this is done by _mlkem768_dec)
    const secretKeyData = decapsulationKey[_privateSecretKey];
    if (!secretKeyData || secretKeyData.length !== SECRETKEY_BYTES) {
      throw new Error("Invalid secret key length");
    }
    const ct = ArrayBuffer.isView(ciphertext)
      ? new Uint8Array(
          ciphertext.buffer,
          ciphertext.byteOffset,
          ciphertext.byteLength
        )
      : new Uint8Array(ciphertext);
    if (ct.length !== CIPHERTEXT_BYTES) {
      throw new MlKemOperationError("Invalid ciphertext length");
    }

    // 4. Let sharedKey be the output that results from performing the
    // ML-KEM.Decaps function described in Section 7.3 of [FIPS-203] with the
    // parameter set indicated by the name member of algorithm, using the key
    // represented by the [[handle]] internal slot of key as the dk input
    // parameter, and ciphertext as the c input parameter.
    const stackSave = module.stackSave();
    try {
      const ctPtr = module.stackAlloc(CIPHERTEXT_BYTES);
      const skPtr = module.stackAlloc(SECRETKEY_BYTES);
      const ssPtr = module.stackAlloc(SHARED_SECRET_BYTES);

      module.HEAPU8.set(ct, ctPtr);
      module.HEAPU8.set(secretKeyData, skPtr);

      const result = module._mlkem768_dec(ssPtr, ctPtr, skPtr);
      if (result !== 0) {
        throw new MlKemOperationError("Decapsulation failed");
      }

      const sharedKey = new Uint8Array(SHARED_SECRET_BYTES);
      sharedKey.set(module.HEAPU8.subarray(ssPtr, ssPtr + SHARED_SECRET_BYTES));

      module.HEAPU8.fill(0, ctPtr, ctPtr + CIPHERTEXT_BYTES);
      module.HEAPU8.fill(0, skPtr, skPtr + SECRETKEY_BYTES);
      module.HEAPU8.fill(0, ssPtr, ssPtr + SHARED_SECRET_BYTES);

      // 5. Return sharedKey.
      return sharedKey.buffer;
    } finally {
      module.stackRestore(stackSave);
    }
  }

  async decapsulateBits(
    decapsulationAlgorithm: MlKemAlgorithm,
    decapsulationKey: MlKemCryptoKey,
    ciphertext: BufferSource
  ) {
    return this.#decapsulate(
      decapsulationAlgorithm,
      decapsulationKey,
      ciphertext,
      "decapsulateBits"
    );
  }

  async decapsulateKey(
    decapsulationAlgorithm: MlKemAlgorithm,
    decapsulationKey: MlKemCryptoKey,
    ciphertext: BufferSource,
    sharedKeyAlgorithm: KeyAlgorithm,
    extractable: boolean,
    usages: KeyUsage[]
  ) {
    const sharedKeyBits = await this.#decapsulate(
      decapsulationAlgorithm,
      decapsulationKey,
      ciphertext,
      "decapsulateKey"
    );
    const sharedKey = await crypto.subtle.importKey(
      "raw",
      sharedKeyBits,
      sharedKeyAlgorithm,
      extractable,
      usages
    );
    return sharedKey;
  }
}

export default new MlKem768();
