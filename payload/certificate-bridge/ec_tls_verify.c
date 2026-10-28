#include <stddef.h>
#include <stdint.h>

/* Signatures observed at the stock EVP_VerifyFinal wrapper (CRO 0x5780c).
 * These calls are resolved only after their ARM/Thumb ABI is tested offline. */
typedef struct {
    const void *digest, *engine;
    unsigned long flags;
    void *md_data, *pctx;
    void *update;
} OSSLMDContext;
typedef struct {
    int type, save_type, references;
    const void *ameth, *engine, *key;
    int save_parameters;
    void *attributes;
} OSSLKey;
typedef struct {
    uint32_t curve_bits;
    unsigned char point[97];
} ECPointKey;

_Static_assert(sizeof(void *) == 4, "3DS ARM32 ABI required");
_Static_assert(sizeof(OSSLMDContext) == 0x18, "EVP_MD_CTX layout");
_Static_assert(offsetof(OSSLKey, key) == 0x14, "EVP_PKEY layout");

extern void browser_md_ctx_init(OSSLMDContext *ctx);
extern int browser_md_ctx_copy(OSSLMDContext *to, const OSSLMDContext *from);
extern int browser_md_final(OSSLMDContext *ctx, unsigned char *digest, unsigned *len);
extern int browser_md_ctx_cleanup(OSSLMDContext *ctx);
extern int browser_verify_final(OSSLMDContext *ctx, const unsigned char *sig,
                                unsigned sig_len, OSSLKey *key);
extern int ec_verify_digest_point(unsigned bits, const unsigned char *point,
                                  size_t point_len, const unsigned char *digest,
                                  size_t digest_len, const unsigned char *sig,
                                  size_t sig_len);

/* The stock RSA/DSA/GOST paths are unchanged. Only EC keys created by our
 * strict SPKI decoder use the mbedTLS ECDSA verifier. */
int ec_tls_verify_final(OSSLMDContext *ctx, const unsigned char *sig,
                        unsigned sig_len, OSSLKey *key)
{
    if (!key || key->type != 408)
        return browser_verify_final(ctx, sig, sig_len, key);
    if (!ctx || !sig || !key->key || sig_len == 0 || sig_len > 144)
        return 0;
    const ECPointKey *pub = key->key;
    if (pub->curve_bits != 256 && pub->curve_bits != 384)
        return 0;
    OSSLMDContext copy;
    unsigned char digest[64];
    unsigned digest_len = 0;
    browser_md_ctx_init(&copy);
    int valid = browser_md_ctx_copy(&copy, ctx) == 1 &&
                browser_md_final(&copy, digest, &digest_len) == 1 &&
                digest_len <= sizeof(digest) &&
                ec_verify_digest_point(pub->curve_bits, pub->point,
                                       pub->curve_bits == 256 ? 65 : 97,
                                       digest, digest_len, sig, sig_len);
    browser_md_ctx_cleanup(&copy);
    volatile unsigned char *wipe = digest;
    for (size_t i = 0; i < sizeof(digest); ++i) wipe[i] = 0;
    return valid;
}
