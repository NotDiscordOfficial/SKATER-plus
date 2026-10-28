#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL 1.0.2 ABI used by SKATER's oss.cro. This is an offline candidate:
 * it is not linked into the live CRO until all call sites are accounted for. */
typedef struct { int length, type; unsigned char *data; long flags; } OSSLString;
typedef struct { const char *sn, *ln; int nid, length;
                 const unsigned char *data; int flags; } OSSLObject;
typedef struct { int type; union { void *ptr; OSSLObject *object; } value; } OSSLType;
typedef struct { OSSLObject *algorithm; OSSLType *parameter; } OSSLAlgor;
typedef struct { OSSLAlgor *algor; OSSLString *public_key; void *pkey; } OSSLPubkey;

typedef struct OSSLKeyMethod OSSLKeyMethod;
typedef struct {
    int type, save_type, references;
    const OSSLKeyMethod *ameth;
    void *engine;
    void *key;
    int save_parameters;
    void *attributes;
} OSSLKey;

typedef struct {
    uint32_t curve_bits;
    unsigned char point[97];
} ECPointKey;

struct OSSLKeyMethod {
    int pkey_id, pkey_base_id;
    unsigned long flags;
    char *pem_str, *info;
    int (*pub_decode)(OSSLKey *, OSSLPubkey *);
    void *pub_encode;
    int (*pub_cmp)(const OSSLKey *, const OSSLKey *);
    void *pub_print, *priv_decode, *priv_encode, *priv_print;
    int (*pkey_size)(const OSSLKey *);
    int (*pkey_bits)(const OSSLKey *);
    void *param_decode, *param_encode;
    int (*param_missing)(const OSSLKey *);
    void *param_copy, *param_cmp, *param_print, *sig_print;
    void (*pkey_free)(OSSLKey *);
    void *pkey_ctrl, *old_priv_decode, *old_priv_encode;
    void *item_verify, *item_sign;
};

_Static_assert(sizeof(void *) == 4, "3DS ARM32 ABI required");
_Static_assert(offsetof(OSSLKey, key) == 0x14, "EVP_PKEY key offset");
_Static_assert(offsetof(OSSLKeyMethod, pub_decode) == 0x14, "ASN1 method callback offset");
_Static_assert(offsetof(OSSLKeyMethod, param_missing) == 0x40, "ASN1 parameter callback offset");
_Static_assert(offsetof(OSSLKeyMethod, pkey_free) == 0x54, "ASN1 free callback offset");

extern int ec_validate_public_point(unsigned bits, const unsigned char *point, size_t len);

static int oid_equal(const OSSLObject *obj, const unsigned char *bytes, size_t len)
{
    return obj && obj->data && obj->length == (int)len &&
           memcmp(obj->data, bytes, len) == 0;
}

static int ec_pub_decode(OSSLKey *key, OSSLPubkey *pub)
{
    static const unsigned char ec_oid[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
    static const unsigned char p256_oid[] = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    static const unsigned char p384_oid[] = {0x2b,0x81,0x04,0x00,0x22};
    if (!key || !pub || !pub->algor || !pub->public_key ||
        !oid_equal(pub->algor->algorithm, ec_oid, sizeof(ec_oid)) ||
        !pub->algor->parameter || pub->algor->parameter->type != 6)
        return 0;
    OSSLString *src = pub->public_key;
    unsigned bits = 0;
    if (oid_equal(pub->algor->parameter->value.object, p256_oid, sizeof(p256_oid)))
        bits = 256;
    else if (oid_equal(pub->algor->parameter->value.object, p384_oid, sizeof(p384_oid)))
        bits = 384;
    else
        return 0;
    const size_t len = bits == 256 ? 65 : 97;
    if (!src->data || src->length != (int)len || src->data[0] != 4 ||
        ((unsigned long)src->flags & 7u) != 0 ||
        !ec_validate_public_point(bits, src->data, len))
        return 0;
    ECPointKey *owned = malloc(sizeof(*owned));
    if (!owned) return 0;
    owned->curve_bits = bits;
    memcpy(owned->point, src->data, len);
    key->key = owned;
    return 1;
}

static int ec_pub_cmp(const OSSLKey *a, const OSSLKey *b)
{
    const ECPointKey *x = a ? a->key : NULL, *y = b ? b->key : NULL;
    if (!x || !y || x->curve_bits != y->curve_bits) return -2;
    const size_t len = x->curve_bits == 256 ? 65 : 97;
    return memcmp(x->point, y->point, len) == 0 ? 1 : 0;
}

static int ec_pkey_size(const OSSLKey *key)
{
    const ECPointKey *point = key ? key->key : NULL;
    if (!point) return 0;
    return point->curve_bits == 256 ? 72 :
           point->curve_bits == 384 ? 104 : 0;
}

static int ec_pkey_bits(const OSSLKey *key)
{
    const ECPointKey *point = key ? key->key : NULL;
    return point ? (int)point->curve_bits : 0;
}

static int ec_param_missing(const OSSLKey *key)
{
    const ECPointKey *point = key ? key->key : NULL;
    return !point || (point->curve_bits != 256 && point->curve_bits != 384);
}

static void ec_pkey_free(OSSLKey *key)
{
    if (key && key->key) {
        memset(key->key, 0, sizeof(ECPointKey));
        free(key->key);
        key->key = NULL;
    }
}

/* NID_X9_62_id_ecPublicKey == 408. The loader must relocate this method's
 * callbacks and the sorted six-entry method table before it can be used. */
const OSSLKeyMethod ec_asn1_method = {
    .pkey_id = 408,
    .pkey_base_id = 408,
    .pem_str = "EC",
    .info = "EC Public Key",
    .pub_decode = ec_pub_decode,
    .pub_cmp = ec_pub_cmp,
    .pkey_size = ec_pkey_size,
    .pkey_bits = ec_pkey_bits,
    .param_missing = ec_param_missing,
    .pkey_free = ec_pkey_free,
};
