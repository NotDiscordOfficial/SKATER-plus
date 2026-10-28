#pragma once

#include <stddef.h>
#include <stdint.h>

#define ROOT_PEM_LIMIT 8192u
#define ROOT_EXTRA_LIMIT 16384u
#define ROOT_EXTRA_COUNT 4u

/* One self-signed CA certificate per PEM file. Returns a diagnostic on error. */
int root_pem_check(const uint8_t *pem, size_t size, uint8_t fingerprint[32],
                   char *subject, size_t subject_size, const char **error);
int root_bundle_contains(const uint8_t *bundle, size_t size,
                         const uint8_t fingerprint[32]);
int root_extra_at(const uint8_t *bundle, size_t size, size_t base_size,
                  unsigned index, size_t *offset, size_t *length);
int root_remove_extra(uint8_t *bundle, size_t *size, size_t base_size, unsigned index);
