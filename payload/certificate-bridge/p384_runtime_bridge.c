#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Resolved to the browser's existing OpenSSL allocation functions at link time. */
extern void *browser_crypto_malloc(int size, const char *file, int line);
extern void browser_crypto_free(void *ptr);

void *malloc(size_t size)
{
    if (size == 0 || size > INT_MAX) return NULL;
    return browser_crypto_malloc((int)size, "p384-fallback", 0);
}

void free(void *ptr)
{
    if (ptr) browser_crypto_free(ptr);
}

void *calloc(size_t count, size_t size)
{
    if (size != 0 && count > SIZE_MAX / size) return NULL;
    size_t total = count * size;
    void *ptr = malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}
