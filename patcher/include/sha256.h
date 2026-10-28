#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    size_t used;
} Sha256;

void sha256_init(Sha256 *ctx);
void sha256_update(Sha256 *ctx, const void *data, size_t size);
void sha256_final(Sha256 *ctx, uint8_t output[32]);
void sha256_buffer(const void *data, size_t size, uint8_t output[32]);
