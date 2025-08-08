#include "randombytes.h"

/**
 * WASM implementation doesn't use functions that call `randombytes()`.
 *
 * Instead, it generates entropy via crypto.getRandomValues() in the JavaScript wrapper,
 * and passes it to C code that expects entropy.
 *
 * This is normal. This file is just a placeholder to satisfy the build system.
 */

void randombytes_reset(void) {
    // No-op for WASM implementation
}

void randombytes(uint8_t *buf, size_t n) {
    // Mark as used to avoid unused parameter warnings.
    (void)buf;
    (void)n;
    // This function is not called in the WASM implementation.
    abort();
}
