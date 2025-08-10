export type MlKemAlgorithm = {
    name: "ML-KEM-768";
} | "ML-KEM-768";
export type MlKemKeyUsage = "encapsulateKey" | "encapsulateBits" | "decapsulateKey" | "decapsulateBits";
export type MlKemKeyFormat = "raw-public" | "raw-seed" | "jwk";
export type EncapsulatedKey = {
    sharedKey: CryptoKey;
    ciphertext: ArrayBuffer;
};
export type EncapsulatedBits = {
    sharedKey: ArrayBuffer;
    ciphertext: ArrayBuffer;
};
declare function _isSupportedCryptoKey(key: CryptoKey): boolean;
declare function generateKey(keyAlgorithm: MlKemAlgorithm, extractable: boolean, usages: MlKemKeyUsage[]): Promise<CryptoKeyPair>;
declare function exportKey(format: "jwk", // JWK format returns a JsonWebKey
key: CryptoKey): Promise<JsonWebKey>;
declare function exportKey(format: Exclude<MlKemKeyFormat, "jwk">, // other formats return an ArrayBuffer
key: CryptoKey): Promise<ArrayBuffer>;
declare function importKey(format: "jwk", keyData: JsonWebKey, algorithm: MlKemAlgorithm, extractable: boolean, usages: MlKemKeyUsage[]): Promise<CryptoKey>;
declare function importKey(format: Exclude<MlKemKeyFormat, "jwk">, keyData: BufferSource, algorithm: MlKemAlgorithm, extractable: boolean, usages: MlKemKeyUsage[]): Promise<CryptoKey>;
declare function encapsulateBits(algorithm: MlKemAlgorithm, encapsulationKey: CryptoKey): Promise<EncapsulatedBits>;
declare function encapsulateKey(encapsulationAlgorithm: MlKemAlgorithm, encapsulationKey: CryptoKey, sharedKeyAlgorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[]): Promise<EncapsulatedKey>;
declare function decapsulateBits(decapsulationAlgorithm: MlKemAlgorithm, decapsulationKey: CryptoKey, ciphertext: BufferSource): Promise<ArrayBuffer>;
declare function decapsulateKey(decapsulationAlgorithm: MlKemAlgorithm, decapsulationKey: CryptoKey, ciphertext: BufferSource, sharedKeyAlgorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[]): Promise<CryptoKey>;
declare const mlkem: {
    generateKey: typeof generateKey;
    exportKey: typeof exportKey;
    importKey: typeof importKey;
    encapsulateBits: typeof encapsulateBits;
    encapsulateKey: typeof encapsulateKey;
    decapsulateBits: typeof decapsulateBits;
    decapsulateKey: typeof decapsulateKey;
    _isSupportedCryptoKey: typeof _isSupportedCryptoKey;
};
export default mlkem;
