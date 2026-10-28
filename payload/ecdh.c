#include <stddef.h>
#include <stdint.h>

#include "uECC.h"

void *memcpy(void *destination, const void *source, size_t length) {
    uint8_t *out = (uint8_t *)destination;
    const uint8_t *in = (const uint8_t *)source;
    while (length-- != 0) {
        *out++ = *in++;
    }
    return destination;
}

void *memset(void *destination, int value, size_t length) {
    uint8_t *out = (uint8_t *)destination;
    while (length-- != 0) {
        *out++ = (uint8_t)value;
    }
    return destination;
}

int payload_ecdh(
    const uint8_t private_key[32],
    const uint8_t server_public_key[64],
    uint8_t client_public_key[64],
    uint8_t shared_secret[32]
) {
    uECC_Curve curve = uECC_secp256r1();
    if (!uECC_compute_public_key(private_key, client_public_key, curve)) {
        return 0;
    }
    return uECC_shared_secret(
        server_public_key,
        private_key,
        shared_secret,
        curve
    );
}
