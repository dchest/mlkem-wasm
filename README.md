# mlkem-wasm

**ML-KEM-768 post-quantum key encapsulation mechanism in WebAssembly.**

This package provides a WebAssembly-based implementation of ML-KEM-768, based on [mlkem-native](https://github.com/pq-code-package/mlkem-native). It exposes a modern, WebCrypto-compatible API for key generation, encapsulation, and decapsulation, all bundled in a single JavaScript file with the WASM module inlined.

Use it as a stopgap solution until the [WebCrypto API supports ML-KEM natively](https://wicg.github.io/webcrypto-modern-algos/).

Demo: <https://dchest.github.io/mlkem-wasm/>

> [!CAUTION]
> Beta version. CONTAINS CRYPTOGRAPHY! Use at your own risk.

## Features

- API compatible with the [WebCrypto API draft for modern algorithms](https://wicg.github.io/webcrypto-modern-algos/) (when it ships, replace `mlkem` with `crypto.subtle` and burn this package).
- All code and WASM are bundled into a single `dist/mlkem.js` ES module (no external `.wasm` files needed).
- Works in browsers and Node.js, and should work everywhere WebAssembly is supported.
- Small: 53 KB unminified .js (17 KB gzipped / 14 KB brotlied).
- Based on memory-safe, type-safe, high-performance C code ([mlkem-native](src/mlkem-native/README.md)).
- A single, most common ML-KEM-768 algorithm, so there’s no need to choose between 512, 768, and 1024!

## Limitations

- The `CryptoKey` returned by this module's `generateKey` and `importKey` has the same prototype as WebCrypto's `CryptoKey`, but cannot be cloned with `structuredClone`, so you cannot, for example, save them to IndexedDB, pass them to a worker, or use `wrapKey` on them, without exporting. You can only use them with this library's methods. (You can, however, encapsulate and decapsulate exportable WebCrypto `CryptoKey` objects.) Cloning is deliberately disabled to prevent compatibility issues with the future WebCrypto API (e.g., you saved an `mlkem-wasm` key to IndexedDB, and then switched to the native WebCrypto API, which has its own internal key format and cannot deserialize it).
- Key material is not accessible from outside of the module (that is, you should not be able to get raw key data without exporting), but is somewhere in JavaScript memory until garbage collected. The module takes care to wipe key data from memory during garbage collection, but JavaScript runtimes may optimize this cleanup away.
- Operations, while asynchronous on the surface (all functions are `async` to be compatible and to be able to load the WASM module without a separate initialization call), are done synchronously, instead of being fully asynchronous like in the WebCrypto API. You may consider it an improvement.
- Base64 encoding and decoding for JWK is not constant-time (not sure if it is in other implementations except BoringSSL, though).
- `pkcs8` import only supports the seed format of private keys (as nature intended).

## Installation

```sh
npm install mlkem-wasm
```

## Usage Example

### Encapsulating bits

```js
import mlkem from "mlkem-wasm";

// Alice generates her key pair
const alice = await mlkem.generateKey({ name: "ML-KEM-768" }, true, [
  "encapsulateBits",
  "decapsulateBits",
]);
const { publicKey: alicePublicKey, privateKey: alicePrivateKey } = alice;

// Bob generates his key pair
const bob = await mlkem.generateKey({ name: "ML-KEM-768" }, true, [
  "encapsulateBits",
  "decapsulateBits",
]);
const { publicKey: bobPublicKey, privateKey: bobPrivateKey } = bob;

// Bob learns Alice's public key

// Bob encapsulates a shared secret to Alice's public key
const { ciphertext, sharedKey } = await mlkem.encapsulateBits(
  { name: "ML-KEM-768" },
  alicePublicKey
);

// Bob sends ciphertext to Alice

// Alice decapsulates the shared secret using her private key
const recoveredKey = await mlkem.decapsulateBits(
  { name: "ML-KEM-768" },
  alicePrivateKey,
  ciphertext
);

// sharedKey and recoveredKey are equal
```

### Encapsulating a key

```js
import mlkem from "mlkem-wasm";

// Alice generates her key pair
const alice = await mlkem.generateKey({ name: "ML-KEM-768" }, true, [
  "encapsulateKey",
  "decapsulateKey",
]);
const { publicKey: alicePublicKey, privateKey: alicePrivateKey } = alice;

// Bob wants to send Alice an AES-GCM key.
// Bob encapsulates an AES-GCM key to Alice's public key
const { sharedKey: aesKey, ciphertext } = await mlkem.encapsulateKey(
  { name: "ML-KEM-768" },
  alicePublicKey,
  { name: "AES-GCM", length: 256 },
  true, // extractable
  ["encrypt", "decrypt"]
);

// Bob sends ciphertext to Alice

// Alice decapsulates the AES-GCM key using her private key
const recoveredAesKey = await mlkem.decapsulateKey(
  { name: "ML-KEM-768" },
  alicePrivateKey,
  ciphertext,
  { name: "AES-GCM", length: 256 },
  true, // extractable
  ["encrypt", "decrypt"]
);

// aesKey and recoveredAesKey are both WebCrypto CryptoKey objects, use the standard crypto.subtle.encrypt/decrypt methods.
```

### Exporting and importing keys

You can export and import ML-KEM keys in several formats. Here are some examples:

#### Exporting a public key (raw format)

```js
// Export Alice's public key as raw bytes
const rawPublicKey = await mlkem.exportKey("raw-public", alicePublicKey);
// rawPublicKey is an ArrayBuffer
```

#### Exporting a private key (seed format)

```js
// Export Alice's private key as a seed
const rawSeed = await mlkem.exportKey("raw-seed", alicePrivateKey);
// rawSeed is an ArrayBuffer
```

#### Exporting a key as JWK

```js
// Export Alice's public key as JWK
const jwkPublic = await mlkem.exportKey("jwk", alicePublicKey);
// jwkPublic is a JsonWebKey object
```

#### Importing a public key (raw format)

```js
// Import a public key from raw bytes
const importedPublicKey = await mlkem.importKey(
  "raw-public",
  rawPublicKey,
  { name: "ML-KEM-768" },
  true, // extractable
  ["encapsulateBits", "encapsulateKey"]
);
```

#### Importing a private key (seed format)

```js
// Import a private key from seed
const importedPrivateKey = await mlkem.importKey(
  "raw-seed",
  rawSeed,
  { name: "ML-KEM-768" },
  false, // not extractable
  ["decapsulateBits", "decapsulateKey"]
);
```

#### Importing a key from JWK

```js
// Import a public key from JWK
const importedJwkPublicKey = await mlkem.importKey(
  "jwk",
  jwkPublic,
  { name: "ML-KEM-768" },
  false,
  ["encapsulateBits", "encapsulateKey"]
);
```

## API Reference

All API methods are asynchronous and return Promises. See [Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/) for details.

### `mlkem.generateKey(algorithm, extractable, usages)`

- **algorithm**: `{ name: "ML-KEM-768" }` or `"ML-KEM-768"`
- **extractable**: `boolean` (for private key)
- **usages**: array of usages: `"encapsulateKey"`, `"encapsulateBits"`, `"decapsulateKey"`, `"decapsulateBits"`
- **Returns**: `{ publicKey, privateKey }` (both are `CryptoKey`)

### `mlkem.exportKey(format, key)`

- **format**: `"raw-public"`, `"raw-seed"`, `"jwk"`, `"pkcs8"` or `"spki"`
- **key**: `CryptoKey`
- **Returns**: `ArrayBuffer` or `JsonWebKey`

### `mlkem.importKey(format, keyData, algorithm, extractable, usages)`

- **format**: `"raw-public"`, `"raw-seed"`, `"jwk"`, `"pkcs8"` or `"spki"`
- **keyData**: `ArrayBuffer`, typed array, or `JsonWebKey`
- **algorithm**: `{ name: "ML-KEM-768" }` or `"ML-KEM-768"`
- **extractable**: `boolean`
- **usages**: array of usages
- **Returns**: `CryptoKey`

### `mlkem.encapsulateBits(algorithm, encapsulationKey)`

- **algorithm**: `{ name: "ML-KEM-768" }` or `"ML-KEM-768"`
- **encapsulationKey**: public `CryptoKey`
- **Returns**: `{ ciphertext, sharedKey }` (both `ArrayBuffer`)

### `mlkem.encapsulateKey(encapsulationAlgorithm, encapsulationKey, sharedKeyAlgorithm, extractable, usages)`

- **encapsulationAlgorithm**: `{ name: "ML-KEM-768" }` or `"ML-KEM-768"`
- **encapsulationKey**: public `CryptoKey`
- **sharedKeyAlgorithm**: WebCrypto KeyAlgorithm (e.g., `{ name: "AES-GCM" }`)
- **extractable**: `boolean`
- **usages**: usages for the shared key
- **Returns**: `{ sharedKey, ciphertext }` (`sharedKey` is a WebCrypto `CryptoKey`)

### `mlkem.decapsulateBits(decapsulationAlgorithm, decapsulationKey, ciphertext)`

- **decapsulationAlgorithm**: `{ name: "ML-KEM-768" }` or `"ML-KEM-768"`
- **decapsulationKey**: private `CryptoKey`
- **ciphertext**: `ArrayBuffer` or typed array
- **Returns**: `ArrayBuffer` (shared key)

### `mlkem.decapsulateKey(decapsulationAlgorithm, decapsulationKey, ciphertext, sharedKeyAlgorithm, extractable, usages)`

- **decapsulationAlgorithm**: `{ name: "ML-KEM-768" }` or `"ML-KEM-768"`
- **decapsulationKey**: private `CryptoKey`
- **ciphertext**: `ArrayBuffer` or typed array
- **sharedKeyAlgorithm**: WebCrypto KeyAlgorithm
- **extractable**: `boolean`
- **usages**: usages for the shared key
- **Returns**: `CryptoKey`

### `mlkem.getPublicKey(key, usages)`

- **key**: private `CryptoKey`
- **usages**: array of usages for the returned public key (`"encapsulateKey"`, `"encapsulateBits"`)
- **Returns**: public `CryptoKey`

### `mlkem._isSupportedCryptoKey(key)`

Non-spec method to check if a `CryptoKey` was created by this library.
You can use it to distinguish WebCrypto's native keys from `mlkem-wasm` keys.

- **key**: `CryptoKey`
- **Returns**: `boolean`

### Types

- `CryptoKey`: Internal key object, not compatible with WebCrypto's `CryptoKey`.
- Usages: `"encapsulateKey"`, `"encapsulateBits"`, `"decapsulateKey"`, `"decapsulateBits"`
- Formats: `"raw-public"`, `"raw-seed"`, `"jwk"`, `"pkcs8"`, `"spki"`

## When WebCrypto API ships

Once the WebCrypto API supports ML-KEM natively (assuming the draft ships as-is), just switch `mlkem` to `crypto.subtle` and use the native API directly.

## Spec changes

Since the WebCrypto API draft is still evolving, this library may need updates to keep up with changes in the spec. The updates are not guaranteed (but I will try to keep up), and they may break compatibility with previous versions.

## Build Instructions

### Prerequisites

- [Emscripten](https://emscripten.org/) (for building WASM)
- `git` (to fetch mlkem-native sources)
- `npm install` to install dev dependencies (`esbuild`, `typescript`, and `vitest`).

### Steps

1. **Fetch mlkem-native sources**
   - The sources are included as a git submodule in `src/mlkem-native/`.
   - To initialize and update the submodule, run:
     ```sh
     git submodule update --init --recursive
     ```
2. **Build**
   - Run:
     ```sh
     npm run build
     ```
   - This uses Emscripten to compile C sources, which puts the result into `src/build/wasm-module.js` (WASM inlined as base64).
   - Creates a single distributable file by combining `src/build/wasm-module.js` and `src/mlkem.ts` using `esbuild`, resulting in `dist/mlkem.js`.
   - Creates TypeScript types in `types/mlkem.d.ts` by running `tsc`.

## Distribution

- The entire library is distributed as a single-file ES module: `dist/mlkem.js`.
- The WASM module is inlined as base64, so no external files are needed.
- TypeScript types are in `types/mlkem.d.ts`.

## Supply chain security

_Fupply fain fufurity_. The whole WASM module is a scary-looking opaque base64-encoded blob,
compiled by me from the code I got from GitHub (apparently used by AWS' Cryptography library
and other popular projects), npm-installed by you from the internets. I made this library
for my project and happily share it with you.

Nobody checks every line of code they `npm install`, instead they like to check checkboxes.

Here are some checkboxes:

- [x] `mlkem-native` is included as a git submodule instead of importing it directly into the source.
- [x] there are no modifications to the original `mlkem-native` code.
- [x] there are 0 (zero) non-dev dependencies in `package.json`.
- [x] the JavaScript code is not minified.
- [x] build artifacts (except for .o) are committed to the repository.
- [x] hardware security key is used for npm authentication when publishing.

If your company wants to pay to get some other checkboxes from me, please contact me directly.

## License

- WASM wrapper: MIT License
- mlkem-native: See [mlkem-native/LICENSE](src/mlkem-native/LICENSE) (choice of MIT/Apache 2.0/etc.)
