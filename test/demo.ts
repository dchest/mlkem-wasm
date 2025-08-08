import mlkem from "../dist/mlkem.js";

async function main() {
  // Example usage
  const { publicKey, privateKey } = await mlkem.generateKey(
    "ML-KEM-768",
    true,
    ["encapsulateBits", "decapsulateBits"]
  );
  // console.log("Public Key:", Buffer.from(publicKey).toString('base64url'));
  // console.log("Secret Key:", Buffer.from(privateKey).toString('base64url'));
  const exportedPublicKey = await mlkem.exportKey("jwk", publicKey);
  console.log(
    "Exported Public Key (JWK):",
    JSON.stringify(exportedPublicKey, null, 2)
  );
  const exportedPrivateKey = await mlkem.exportKey("jwk", privateKey);
  console.log(
    "Exported Private Key (JWK):",
    JSON.stringify(exportedPrivateKey, null, 2)
  );

  const { ciphertext, sharedKey } = await mlkem.encapsulateBits(
    "ML-KEM-768",
    publicKey
  );
  console.log("Ciphertext:", ciphertext);
  console.log("Shared Secret:", sharedKey);

  const decSharedSecret = await mlkem.decapsulateBits(
    "ML-KEM-768",
    privateKey,
    ciphertext
  );
  console.log("Decapsulated Shared Secret:", decSharedSecret);

  if (sharedKey.toString() === decSharedSecret.toString()) {
    console.log("Decapsulation successful, shared secrets match!");
  } else {
    console.error("Decapsulation failed, shared secrets do not match.");
  }
}

await main().catch((err) => {
  console.error("Error:", err);
});
