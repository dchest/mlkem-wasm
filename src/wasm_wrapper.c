#include <emscripten.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_API_NAMESPACE_PREFIX mlkem
#include "mlkem-native/mlkem/mlkem_native.h"


// ML-KEM-768 wrapper functions using deterministic variants
EMSCRIPTEN_KEEPALIVE
int mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    return crypto_kem_keypair_derand(pk, sk, coins);
}

EMSCRIPTEN_KEEPALIVE
int mlkem768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    return crypto_kem_enc_derand(ct, ss, pk, coins);
}

EMSCRIPTEN_KEEPALIVE
int mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return crypto_kem_dec(ss, ct, sk);
}
