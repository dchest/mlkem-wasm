declare const ALGORITHM_NAME = "ML-KEM-768";
export type MlKemAlgorithm = {
    name: typeof ALGORITHM_NAME;
} | typeof ALGORITHM_NAME;
declare const KEY_USAGES: readonly ["encapsulateKey", "encapsulateBits", "decapsulateKey", "decapsulateBits"];
export type MlKemKeyUsage = (typeof KEY_USAGES)[number];
export type MlKemKeyFormat = "raw-public" | "raw-seed" | "jwk";
declare const _publicKeyData: unique symbol;
declare const _privateSeed: unique symbol;
declare const _privateSecretKey: unique symbol;
declare class MlKemCryptoKey {
    #private;
    constructor(algorithm: MlKemAlgorithm, type: Omit<KeyType, "secret">, usages: MlKemKeyUsage[], extractable: boolean, publicKeyData: Uint8Array<ArrayBuffer>, privateSeed?: Uint8Array<ArrayBuffer> | null, privateSecretKey?: Uint8Array<ArrayBuffer> | null);
    get algorithm(): MlKemAlgorithm;
    get type(): Omit<KeyType, "secret">;
    get usages(): ("encapsulateKey" | "encapsulateBits" | "decapsulateKey" | "decapsulateBits")[];
    get extractable(): boolean;
    get [_publicKeyData](): Uint8Array<ArrayBuffer>;
    get [_privateSeed](): Uint8Array<ArrayBuffer> | null;
    get [_privateSecretKey](): Uint8Array<ArrayBuffer> | null;
}
export type { MlKemCryptoKey };
export type MlKemCryptoKeyPair = {
    publicKey: MlKemCryptoKey;
    privateKey: MlKemCryptoKey;
};
declare class MlKem768 {
    #private;
    generateKey(keyAlgorithm: MlKemAlgorithm, extractable: boolean, usages: MlKemKeyUsage[]): Promise<MlKemCryptoKeyPair>;
    exportKey(format: "jwk", // JWK format returns a JsonWebKey
    key: MlKemCryptoKey): Promise<JsonWebKey>;
    exportKey(format: Exclude<MlKemKeyFormat, "jwk">, // other formats return an ArrayBuffer
    key: MlKemCryptoKey): Promise<ArrayBuffer>;
    importKey(format: "jwk", keyData: JsonWebKey, algorithm: MlKemAlgorithm, extractable: boolean, usages: MlKemKeyUsage[]): Promise<MlKemCryptoKey>;
    importKey(format: Exclude<MlKemKeyFormat, "jwk">, keyData: BufferSource, algorithm: MlKemAlgorithm, extractable: boolean, usages: MlKemKeyUsage[]): Promise<MlKemCryptoKey>;
    encapsulateBits(algorithm: MlKemAlgorithm, encapsulationKey: MlKemCryptoKey): Promise<{
        ciphertext: ArrayBuffer;
        sharedKey: ArrayBuffer;
    }>;
    encapsulateKey(encapsulationAlgorithm: MlKemAlgorithm, encapsulationKey: MlKemCryptoKey, sharedKeyAlgorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[]): Promise<{
        sharedKey: CryptoKey;
        ciphertext: ArrayBuffer;
    }>;
    decapsulateBits(decapsulationAlgorithm: MlKemAlgorithm, decapsulationKey: MlKemCryptoKey, ciphertext: BufferSource): Promise<ArrayBuffer>;
    decapsulateKey(decapsulationAlgorithm: MlKemAlgorithm, decapsulationKey: MlKemCryptoKey, ciphertext: BufferSource, sharedKeyAlgorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[]): Promise<CryptoKey>;
}
declare const _default: MlKem768;
export default _default;
