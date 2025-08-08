import { describe, it, expect } from "vitest";
import mlkem from "../dist/mlkem.js";

// Generated using Go implementation.
const TEST_VECTOR = {
  publicKey: new Uint8Array([
    255, 241, 100, 118, 147, 158, 185, 58, 7, 108, 74, 3, 83, 220, 138, 251,
    211, 135, 202, 2, 114, 202, 154, 196, 200, 195, 1, 93, 64, 25, 118, 176, 96,
    158, 101, 152, 222, 178, 100, 76, 250, 60, 147, 44, 174, 242, 12, 49, 210,
    132, 19, 226, 9, 201, 131, 53, 100, 4, 240, 63, 106, 23, 167, 240, 48, 33,
    64, 89, 54, 247, 216, 62, 242, 57, 21, 164, 240, 12, 202, 124, 29, 88, 36,
    2, 222, 72, 150, 209, 178, 82, 93, 240, 137, 93, 66, 159, 122, 224, 5, 210,
    85, 70, 180, 51, 49, 234, 182, 51, 212, 171, 12, 214, 59, 56, 107, 75, 179,
    149, 88, 10, 231, 154, 2, 21, 59, 107, 5, 196, 75, 113, 10, 113, 147, 34, 6,
    221, 210, 146, 0, 221, 126, 125, 71, 146, 85, 50, 187, 76, 0, 194, 28, 250,
    102, 35, 5, 72, 251, 242, 1, 26, 165, 166, 237, 16, 207, 127, 55, 33, 212,
    244, 119, 8, 251, 199, 95, 107, 88, 10, 202, 52, 8, 83, 163, 198, 160, 93,
    237, 83, 177, 184, 124, 119, 230, 148, 142, 198, 144, 77, 190, 40, 136, 244,
    214, 105, 158, 27, 63, 5, 220, 146, 79, 36, 38, 63, 37, 57, 29, 122, 110,
    59, 234, 10, 154, 17, 75, 108, 66, 68, 204, 226, 99, 244, 156, 129, 17, 106,
    142, 131, 231, 94, 43, 98, 187, 136, 88, 79, 21, 39, 105, 101, 68, 156, 249,
    234, 135, 115, 231, 8, 131, 131, 197, 106, 199, 81, 105, 160, 64, 67, 35,
    21, 119, 64, 140, 133, 17, 185, 53, 211, 52, 147, 133, 199, 47, 250, 94,
    112, 51, 6, 232, 112, 201, 122, 33, 205, 121, 104, 130, 79, 113, 78, 147,
    102, 184, 158, 135, 76, 76, 98, 84, 91, 200, 180, 113, 234, 100, 196, 135,
    184, 127, 97, 172, 100, 87, 137, 157, 60, 163, 66, 104, 50, 221, 54, 75, 33,
    183, 42, 73, 244, 37, 3, 18, 11, 22, 230, 20, 37, 107, 168, 57, 86, 48, 224,
    83, 138, 139, 51, 101, 126, 208, 71, 81, 114, 137, 120, 20, 6, 102, 58, 165,
    97, 166, 161, 99, 117, 152, 151, 172, 20, 46, 27, 19, 166, 187, 117, 85,
    135, 79, 204, 10, 195, 78, 232, 90, 164, 48, 206, 164, 54, 40, 132, 17, 41,
    220, 229, 72, 135, 82, 93, 243, 209, 197, 20, 209, 126, 138, 166, 88, 223,
    225, 36, 240, 226, 26, 95, 144, 183, 169, 214, 0, 76, 163, 182, 51, 194, 99,
    52, 204, 8, 93, 251, 45, 23, 199, 187, 16, 178, 96, 134, 219, 150, 211, 144,
    11, 255, 170, 74, 21, 28, 114, 149, 124, 77, 205, 65, 175, 237, 250, 80, 55,
    68, 205, 254, 187, 12, 175, 150, 75, 75, 90, 53, 143, 236, 22, 88, 70, 198,
    0, 198, 167, 141, 240, 36, 66, 163, 201, 81, 42, 97, 87, 120, 132, 178, 118,
    178, 1, 51, 176, 79, 88, 63, 211, 236, 93, 6, 246, 204, 138, 166, 69, 228,
    115, 171, 217, 5, 199, 214, 165, 78, 31, 72, 65, 100, 251, 96, 144, 243, 77,
    185, 40, 71, 192, 247, 132, 147, 26, 150, 104, 36, 35, 137, 1, 182, 95, 16,
    54, 138, 186, 175, 156, 162, 77, 231, 38, 187, 47, 115, 101, 206, 53, 159,
    48, 50, 205, 153, 60, 191, 254, 101, 44, 101, 148, 23, 96, 208, 161, 77, 23,
    202, 100, 246, 130, 158, 144, 192, 102, 146, 71, 77, 180, 83, 156, 150, 63,
    10, 208, 30, 37, 55, 190, 212, 81, 0, 75, 227, 150, 233, 145, 137, 165, 196,
    121, 217, 165, 41, 132, 178, 94, 105, 178, 119, 113, 2, 145, 24, 76, 140,
    52, 54, 147, 205, 121, 51, 167, 10, 111, 127, 220, 21, 35, 180, 182, 166,
    17, 89, 162, 199, 1, 217, 19, 163, 72, 234, 182, 160, 203, 185, 208, 117,
    73, 54, 227, 25, 255, 76, 21, 234, 151, 142, 8, 151, 85, 103, 19, 88, 33,
    26, 127, 210, 165, 162, 248, 64, 203, 187, 5, 195, 248, 213, 193, 240, 67,
    7, 54, 176, 169, 194, 243, 133, 32, 214, 204, 139, 102, 32, 34, 124, 71,
    205, 22, 94, 216, 27, 52, 98, 197, 196, 141, 149, 0, 157, 178, 63, 247, 229,
    184, 162, 42, 5, 127, 115, 67, 133, 103, 115, 216, 176, 120, 170, 22, 187,
    48, 219, 125, 176, 227, 166, 244, 201, 64, 3, 89, 121, 88, 7, 163, 254, 20,
    100, 74, 8, 51, 157, 96, 170, 25, 18, 137, 109, 91, 164, 145, 50, 57, 59,
    226, 125, 121, 248, 56, 94, 213, 98, 82, 204, 182, 184, 116, 18, 62, 145,
    134, 1, 198, 37, 145, 69, 74, 53, 249, 94, 56, 97, 57, 202, 75, 73, 51, 108,
    189, 223, 231, 186, 24, 86, 105, 176, 147, 131, 124, 114, 115, 134, 106, 49,
    44, 82, 115, 154, 23, 69, 21, 230, 60, 84, 201, 203, 255, 92, 10, 211, 70,
    3, 31, 113, 133, 231, 35, 80, 10, 249, 120, 95, 199, 44, 22, 241, 176, 153,
    171, 0, 102, 72, 155, 106, 212, 62, 210, 133, 10, 35, 236, 81, 118, 8, 81,
    226, 183, 29, 17, 227, 154, 70, 186, 86, 85, 58, 189, 223, 250, 124, 148,
    236, 185, 202, 137, 5, 72, 230, 43, 134, 98, 69, 46, 105, 96, 45, 229, 186,
    5, 115, 125, 12, 196, 86, 210, 51, 203, 47, 98, 62, 152, 202, 88, 96, 96,
    24, 172, 228, 154, 231, 251, 163, 175, 160, 29, 32, 213, 146, 149, 225, 103,
    107, 37, 42, 49, 28, 136, 51, 250, 163, 128, 244, 149, 43, 198, 197, 36,
    248, 108, 112, 134, 179, 46, 133, 140, 13, 65, 132, 82, 100, 137, 64, 43, 8,
    214, 21, 171, 68, 25, 106, 29, 68, 30, 196, 168, 94, 142, 100, 182, 114,
    167, 113, 16, 22, 16, 171, 147, 58, 28, 1, 162, 2, 212, 119, 198, 177, 41,
    238, 87, 167, 77, 133, 71, 166, 251, 105, 205, 8, 157, 100, 66, 79, 129,
    102, 7, 121, 85, 150, 129, 194, 33, 16, 84, 19, 206, 244, 102, 98, 10, 112,
    52, 149, 44, 251, 70, 33, 2, 120, 153, 172, 52, 174, 20, 105, 201, 146, 58,
    55, 115, 6, 43, 235, 2, 161, 138, 118, 162, 94, 64, 12, 16, 183, 38, 114,
    248, 193, 86, 117, 0, 34, 200, 191, 4, 156, 37, 101, 19, 93, 213, 188, 110,
    134, 132, 56, 191, 51, 197, 253, 210, 53, 120, 139, 66, 234, 250, 43, 69,
    59, 152, 78, 117, 160, 103, 129, 55, 187, 177, 42, 170, 69, 158, 146, 250,
    21, 172, 196, 38, 60, 193, 45, 202, 181, 146, 104, 218, 16, 56, 179, 5, 183,
    154, 205, 223, 51, 198, 130, 200, 171, 239, 55, 1, 230, 25, 106, 3, 81, 194,
    209, 164, 251, 54, 254, 49, 128, 164, 152, 210, 252, 10, 126, 198, 77, 208,
    159,
  ]),
  privateKey: new Uint8Array([
    173, 141, 180, 147, 231, 218, 204, 221, 255, 81, 102, 4, 229, 22, 118, 108,
    174, 56, 211, 92, 43, 19, 167, 161, 92, 178, 144, 115, 98, 238, 45, 229,
    195, 203, 150, 146, 24, 164, 109, 112, 174, 146, 106, 251, 6, 216, 198, 125,
    240, 45, 61, 60, 238, 178, 177, 106, 54, 108, 0, 149, 189, 103, 143, 157,
  ]),
  ciphertext: new Uint8Array([
    106, 242, 247, 197, 92, 201, 120, 122, 51, 74, 166, 31, 109, 129, 226, 219,
    9, 188, 137, 144, 253, 56, 160, 184, 21, 255, 253, 157, 17, 28, 120, 102,
    133, 254, 42, 163, 210, 155, 98, 120, 29, 99, 0, 26, 215, 138, 96, 218, 107,
    93, 228, 207, 96, 238, 6, 10, 93, 255, 40, 198, 138, 101, 144, 172, 30, 110,
    232, 139, 109, 135, 203, 240, 173, 23, 33, 16, 43, 142, 214, 220, 198, 242,
    15, 144, 26, 200, 54, 50, 81, 162, 239, 221, 196, 168, 178, 253, 61, 19,
    210, 89, 32, 178, 24, 199, 37, 45, 97, 228, 104, 92, 113, 151, 4, 93, 145,
    105, 93, 125, 154, 89, 118, 184, 38, 94, 101, 107, 212, 233, 168, 225, 184,
    238, 150, 18, 45, 129, 190, 198, 36, 2, 229, 200, 188, 145, 17, 40, 172,
    247, 250, 189, 137, 121, 81, 145, 160, 31, 166, 221, 26, 81, 161, 208, 89,
    80, 63, 99, 127, 14, 161, 75, 190, 223, 233, 67, 137, 138, 105, 96, 90, 123,
    37, 196, 134, 111, 102, 65, 1, 47, 100, 32, 114, 45, 142, 64, 160, 252, 194,
    10, 42, 57, 237, 222, 130, 107, 206, 252, 217, 193, 169, 83, 229, 39, 71,
    113, 197, 173, 154, 188, 107, 173, 104, 250, 107, 247, 217, 139, 178, 23,
    204, 157, 117, 197, 132, 146, 238, 126, 200, 97, 113, 80, 62, 242, 231, 100,
    61, 67, 85, 182, 138, 10, 159, 146, 24, 219, 205, 57, 154, 166, 89, 171,
    153, 200, 207, 236, 234, 71, 239, 3, 14, 179, 251, 126, 159, 171, 250, 204,
    40, 192, 15, 158, 168, 118, 47, 55, 62, 188, 133, 228, 9, 28, 248, 204, 67,
    83, 23, 220, 165, 6, 234, 188, 30, 153, 206, 150, 109, 130, 121, 9, 170,
    170, 99, 192, 210, 137, 11, 44, 204, 38, 211, 105, 96, 252, 15, 208, 229,
    173, 164, 87, 219, 222, 181, 152, 38, 153, 84, 26, 85, 124, 105, 184, 18,
    155, 168, 35, 229, 178, 5, 32, 78, 66, 207, 60, 96, 33, 244, 118, 68, 100,
    121, 33, 30, 160, 142, 36, 154, 214, 61, 96, 117, 76, 64, 107, 232, 179, 61,
    249, 182, 239, 42, 94, 131, 1, 209, 1, 72, 122, 189, 252, 133, 37, 205, 179,
    222, 63, 90, 47, 216, 61, 246, 86, 138, 157, 117, 231, 73, 92, 176, 7, 40,
    165, 90, 138, 170, 218, 79, 22, 230, 230, 132, 111, 25, 48, 100, 143, 159,
    247, 24, 152, 200, 42, 233, 11, 127, 243, 151, 183, 168, 46, 248, 139, 89,
    243, 11, 55, 26, 89, 167, 28, 78, 151, 150, 95, 103, 205, 87, 210, 164, 201,
    211, 101, 185, 253, 100, 249, 24, 101, 229, 40, 45, 220, 240, 91, 25, 205,
    133, 0, 40, 105, 56, 115, 133, 16, 48, 170, 175, 116, 194, 91, 119, 101,
    198, 115, 21, 115, 151, 218, 179, 133, 70, 87, 56, 219, 93, 203, 189, 194,
    9, 66, 213, 102, 49, 23, 218, 132, 33, 69, 24, 228, 100, 55, 219, 24, 109,
    60, 153, 19, 37, 128, 114, 142, 146, 240, 36, 46, 133, 172, 122, 208, 17, 9,
    189, 160, 32, 202, 46, 29, 65, 177, 11, 160, 219, 7, 179, 94, 194, 80, 226,
    8, 150, 23, 83, 140, 172, 158, 249, 154, 194, 209, 152, 221, 207, 90, 207,
    133, 92, 169, 19, 229, 59, 93, 143, 44, 59, 105, 27, 169, 230, 247, 233, 40,
    109, 143, 180, 68, 126, 219, 177, 115, 76, 86, 125, 182, 108, 212, 47, 112,
    145, 100, 37, 236, 231, 143, 26, 94, 2, 154, 167, 205, 26, 172, 155, 13,
    231, 61, 249, 154, 145, 226, 74, 127, 244, 196, 36, 229, 38, 250, 22, 212,
    76, 199, 209, 152, 128, 144, 91, 72, 242, 80, 12, 90, 238, 55, 34, 130, 186,
    44, 229, 133, 205, 155, 235, 142, 20, 162, 15, 50, 174, 142, 56, 202, 234,
    196, 185, 114, 102, 114, 35, 224, 226, 136, 223, 91, 100, 137, 111, 136, 10,
    205, 56, 14, 92, 3, 222, 7, 75, 190, 39, 52, 49, 7, 68, 148, 228, 45, 38,
    48, 98, 158, 219, 115, 26, 54, 246, 207, 164, 19, 98, 215, 75, 121, 9, 173,
    13, 244, 234, 211, 127, 30, 27, 77, 143, 91, 192, 29, 12, 40, 38, 31, 210,
    0, 193, 92, 57, 214, 19, 151, 106, 172, 50, 150, 72, 249, 140, 195, 152,
    125, 55, 97, 148, 87, 131, 122, 153, 131, 111, 176, 115, 93, 201, 199, 8,
    144, 49, 2, 193, 20, 61, 204, 188, 123, 184, 125, 41, 23, 140, 70, 231, 63,
    58, 59, 33, 12, 96, 211, 222, 5, 216, 48, 46, 113, 159, 223, 122, 171, 79,
    205, 143, 138, 205, 22, 126, 116, 251, 237, 146, 227, 163, 162, 5, 190, 224,
    196, 24, 160, 43, 83, 41, 241, 118, 236, 222, 33, 39, 180, 93, 114, 174, 74,
    150, 98, 250, 59, 185, 80, 49, 135, 82, 177, 35, 138, 4, 202, 169, 10, 121,
    138, 2, 176, 105, 200, 50, 52, 248, 122, 180, 130, 57, 20, 136, 252, 70,
    104, 75, 132, 61, 117, 204, 114, 191, 111, 224, 52, 83, 104, 144, 237, 86,
    28, 46, 132, 125, 41, 61, 77, 150, 2, 192, 88, 246, 77, 102, 131, 216, 56,
    119, 234, 130, 169, 144, 119, 213, 167, 3, 164, 60, 90, 16, 134, 23, 97,
    144, 41, 20, 6, 213, 210, 115, 206, 172, 151, 36, 67, 92, 167, 176, 19, 2,
    4, 170, 90, 9, 202, 204, 8, 222, 221, 219, 216, 61, 135, 26, 107, 68, 167,
    228, 68, 132, 249, 83, 153, 194, 42, 84, 106, 67, 244, 99, 24, 124, 231,
    152, 63, 144, 204, 140, 94, 114, 0, 54, 131, 235, 168, 163, 145, 105, 56,
    65, 228, 1, 246, 199, 144, 32, 173, 35, 89, 148, 89, 26, 113, 122, 54, 223,
    127, 147, 120, 188, 4, 66, 202, 250, 42, 36, 64, 36, 84, 224, 130, 184, 180,
    118, 41, 16, 74, 227, 253, 79, 114, 213, 240, 107, 245, 233, 131, 27, 199,
    95, 125, 195, 190, 196, 244, 255, 116, 131, 212, 134, 74, 152, 16, 250, 187,
    180, 167, 98, 33, 27, 33, 234, 241, 70, 185, 156, 93, 41, 64, 106, 151, 184,
    222, 97, 36, 232, 101, 107, 85, 221, 54, 4, 255, 94, 47, 217, 72, 104, 17,
    242, 228,
  ]),
  sharedKey: new Uint8Array([
    244, 219, 57, 108, 160, 137, 130, 131, 207, 61, 54, 176, 5, 60, 130, 122,
    118, 190, 218, 211, 34, 10, 196, 38, 141, 247, 96, 178, 185, 6, 184, 54,
  ]),
};

describe("MlKem768 API", () => {
  describe("Error cases", () => {
    it("should throw TypeError for unsupported algorithm", async () => {
      await expect(
        mlkem.generateKey("BAD-ALG", true, ["encapsulateKey"])
      ).rejects.toThrow(expect.objectContaining({ name: "TypeError" }));
    });

    it("should throw SyntaxError for invalid key usages in generateKey", async () => {
      await expect(
        mlkem.generateKey({ name: "ML-KEM-768" }, true, ["badUsage"])
      ).rejects.toThrow(expect.objectContaining({ name: "SyntaxError" }));
    });

    it("should throw OperationError if key is not extractable in exportKey", async () => {
      const { privateKey } = await mlkem.generateKey(
        { name: "ML-KEM-768" },
        false,
        ["decapsulateKey"]
      );
      await expect(mlkem.exportKey("raw-seed", privateKey)).rejects.toThrow(
        expect.objectContaining({ name: "OperationError" })
      );
    });

    it("should throw TypeError if exporting raw-public from private key", async () => {
      const { privateKey } = await mlkem.generateKey(
        { name: "ML-KEM-768" },
        true,
        ["decapsulateKey"]
      );
      await expect(mlkem.exportKey("raw-public", privateKey)).rejects.toThrow(
        expect.objectContaining({ name: "TypeError" })
      );
    });

    it("should throw InvalidAccessError if exporting raw-seed from public key", async () => {
      const { publicKey } = await mlkem.generateKey(
        { name: "ML-KEM-768" },
        true,
        ["encapsulateKey"]
      );
      await expect(mlkem.exportKey("raw-seed", publicKey)).rejects.toThrow(
        expect.objectContaining({ name: "InvalidAccessError" })
      );
    });

    it("should throw NotSupportedError for unknown export format", async () => {
      const { publicKey } = await mlkem.generateKey(
        { name: "ML-KEM-768" },
        true,
        ["encapsulateKey"]
      );
      await expect(mlkem.exportKey("bad-format", publicKey)).rejects.toThrow(
        expect.objectContaining({ name: "NotSupportedError" })
      );
    });

    it("should throw SyntaxError for invalid usages in importKey raw-public", async () => {
      await expect(
        mlkem.importKey(
          "raw-public",
          new Uint8Array(32),
          { name: "ML-KEM-768" },
          true,
          ["badUsage"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "SyntaxError" }));
    });

    it("should throw SyntaxError for invalid usages in importKey raw-seed", async () => {
      await expect(
        mlkem.importKey(
          "raw-seed",
          new Uint8Array(32),
          { name: "ML-KEM-768" },
          true,
          ["badUsage"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "SyntaxError" }));
    });

    it("should throw DataError for invalid key length in importKey raw-seed", async () => {
      await expect(
        mlkem.importKey(
          "raw-seed",
          new Uint8Array(10),
          { name: "ML-KEM-768" },
          true,
          ["decapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for non-object keyData in importKey jwk", async () => {
      await expect(
        mlkem.importKey("jwk", null, { name: "ML-KEM-768" }, true, [
          "encapsulateKey",
        ])
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for wrong kty in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "WRONG", alg: "MLKEM768", pub: "AA" },
          { name: "ML-KEM-768" },
          true,
          ["encapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for wrong alg in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "WRONG", pub: "AA" },
          { name: "ML-KEM-768" },
          true,
          ["encapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for wrong use in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "AA", use: "bad" },
          { name: "ML-KEM-768" },
          true,
          ["encapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for wrong key_ops in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "AA", key_ops: "bad" },
          { name: "ML-KEM-768" },
          true,
          ["encapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for wrong ext in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "AA", ext: false },
          { name: "ML-KEM-768" },
          true,
          ["encapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for invalid private key length in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "AA", priv: "AA" },
          { name: "ML-KEM-768" },
          true,
          ["decapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for invalid public key data in importKey jwk", async () => {
      // priv is valid length, but pub does not match
      const priv = btoa(String.fromCharCode(...new Uint8Array(32)));
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "WRONG", priv },
          { name: "ML-KEM-768" },
          true,
          ["decapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for invalid private key format in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "AA", priv: "!!notbase64!!" },
          { name: "ML-KEM-768" },
          true,
          ["decapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw DataError for invalid public key format in importKey jwk", async () => {
      await expect(
        mlkem.importKey(
          "jwk",
          { kty: "AKP", alg: "MLKEM768", pub: "!!notbase64!!" },
          { name: "ML-KEM-768" },
          true,
          ["encapsulateKey"]
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw NotSupportedError for unsupported key format in importKey", async () => {
      await expect(
        mlkem.importKey("bad-format", {}, { name: "ML-KEM-768" }, true, [
          "encapsulateKey",
        ])
      ).rejects.toThrow(expect.objectContaining({ name: "NotSupportedError" }));
    });

    it("should throw InvalidAccessError for wrong type in encapsulateBits", async () => {
      await expect(
        mlkem.encapsulateBits({ name: "ML-KEM-768" }, {})
      ).rejects.toThrow(
        expect.objectContaining({ name: "InvalidAccessError" })
      );
    });

    it("should throw OperationError for invalid public key length in encapsulateBits", async () => {
      const key = mlkem.importKey(
        "raw-public",
        new Uint8Array(10),
        { name: "ML-KEM-768" },
        true,
        ["encapsulateBits"]
      );
      await expect(
        key.then((k) => mlkem.encapsulateBits({ name: "ML-KEM-768" }, k))
      ).rejects.toThrow(expect.objectContaining({ name: "OperationError" }));
    });

    // Encapsulation failure is hard to simulate unless the WASM module is patched to fail

    it("should throw InvalidAccessError for wrong type in decapsulateBits", async () => {
      await expect(
        mlkem.decapsulateBits({ name: "ML-KEM-768" }, {}, new Uint8Array(32))
      ).rejects.toThrow(
        expect.objectContaining({ name: "InvalidAccessError" })
      );
    });

    it("should throw DataError for invalid secret key length in decapsulateBits", async () => {
      const key = mlkem.importKey(
        "raw-seed",
        new Uint8Array(10),
        { name: "ML-KEM-768" },
        true,
        ["decapsulateKey"]
      );
      await expect(
        key.then((k) =>
          mlkem.decapsulateBits({ name: "ML-KEM-768" }, k, new Uint8Array(32))
        )
      ).rejects.toThrow(expect.objectContaining({ name: "DataError" }));
    });

    it("should throw OperationError for invalid ciphertext length in decapsulateBits", async () => {
      const { privateKey } = await mlkem.generateKey(
        { name: "ML-KEM-768" },
        true,
        ["decapsulateBits"]
      );
      await expect(
        mlkem.decapsulateBits(
          { name: "ML-KEM-768" },
          privateKey,
          new Uint8Array(10)
        )
      ).rejects.toThrow(expect.objectContaining({ name: "OperationError" }));
    });

    // Decapsulation failure is hard to simulate unless the WASM module is patched to fail
  });
  it("should generate a key pair", async () => {
    const { publicKey, privateKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["encapsulateKey", "decapsulateKey"]
    );
    expect(publicKey).toBeDefined();
    expect(privateKey).toBeDefined();
    expect(publicKey.type).toBe("public");
    expect(privateKey.type).toBe("private");
  });

  it("should export and import public key (raw-public)", async () => {
    const { publicKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["encapsulateKey"]
    );
    const raw = await mlkem.exportKey("raw-public", publicKey);
    expect(raw).toBeInstanceOf(ArrayBuffer);

    const imported = await mlkem.importKey(
      "raw-public",
      raw,
      { name: "ML-KEM-768" },
      true,
      ["encapsulateKey"]
    );
    expect(imported.type).toBe("public");
  });

  it("should export and import public key (jwk)", async () => {
    const { publicKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["encapsulateKey"]
    );
    const jwk = await mlkem.exportKey("jwk", publicKey);
    expect(jwk).toHaveProperty("kty", "AKP");
    expect(jwk).toHaveProperty("alg", "MLKEM768");
    expect(jwk).toHaveProperty("pub");
    const imported = await mlkem.importKey(
      "jwk",
      jwk,
      { name: "ML-KEM-768" },
      true,
      ["encapsulateKey"]
    );
    expect(imported.type).toBe("public");
  });

  it("should export and import private key (jwk)", async () => {
    const { privateKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["decapsulateKey"]
    );
    const jwk = await mlkem.exportKey("jwk", privateKey);
    expect(jwk).toHaveProperty("kty", "AKP");
    expect(jwk).toHaveProperty("alg", "MLKEM768");
    expect(jwk).toHaveProperty("priv");
    expect(jwk).toHaveProperty("pub");
    const imported = await mlkem.importKey(
      "jwk",
      jwk,
      { name: "ML-KEM-768" },
      true,
      ["decapsulateKey"]
    );
    expect(imported.type).toBe("private");
  });

  it("should export and import private key (raw-seed)", async () => {
    const { privateKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["decapsulateKey"]
    );
    const rawSeed = await mlkem.exportKey("raw-seed", privateKey);
    expect(rawSeed).toBeInstanceOf(ArrayBuffer);
    // Import back
    const imported = await mlkem.importKey(
      "raw-seed",
      rawSeed,
      { name: "ML-KEM-768" },
      true,
      ["decapsulateKey"]
    );
    expect(imported.type).toBe("private");
    // Export again and compare
    const rawSeed2 = await mlkem.exportKey("raw-seed", imported);
    expect(new Uint8Array(rawSeed2)).toEqual(new Uint8Array(rawSeed));
  });

  it("should encapsulate and decapsulate bits", async () => {
    const { publicKey, privateKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["encapsulateKey", "decapsulateKey", "encapsulateBits", "decapsulateBits"]
    );
    const { ciphertext, sharedKey } = await mlkem.encapsulateBits(
      { name: "ML-KEM-768" },
      publicKey
    );
    expect(ciphertext).toBeInstanceOf(ArrayBuffer);
    expect(sharedKey).toBeInstanceOf(ArrayBuffer);

    const decapsulated = await mlkem.decapsulateBits(
      { name: "ML-KEM-768" },
      privateKey,
      ciphertext
    );
    expect(decapsulated).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(decapsulated)).toEqual(new Uint8Array(sharedKey));
  });

  it("should decapsulate known test vector", async () => {
    const privateKey = await mlkem.importKey(
      "raw-seed",
      TEST_VECTOR.privateKey,
      { name: "ML-KEM-768" },
      true,
      ["decapsulateBits"]
    );
    const decapsulated = await mlkem.decapsulateBits(
      { name: "ML-KEM-768" },
      privateKey,
      TEST_VECTOR.ciphertext
    );
    expect(new Uint8Array(decapsulated)).toEqual(TEST_VECTOR.sharedKey);
  });

  it("should encapsulate known test vector", async () => {
    const publicKey = await mlkem.importKey(
      "raw-public",
      TEST_VECTOR.publicKey,
      { name: "ML-KEM-768" },
      true,
      ["encapsulateBits"]
    );
    const { ciphertext, sharedKey } = await mlkem.encapsulateBits(
      { name: "ML-KEM-768" },
      publicKey
    );
    const privateKey = await mlkem.importKey(
      "raw-seed",
      TEST_VECTOR.privateKey,
      { name: "ML-KEM-768" },
      true,
      ["decapsulateBits"]
    );
    // Check if can decapsulate the ciphertext
    const decapsulated = await mlkem.decapsulateBits(
      { name: "ML-KEM-768" },
      privateKey,
      ciphertext
    );
    expect(new Uint8Array(decapsulated)).toEqual(new Uint8Array(sharedKey));
  });
});
