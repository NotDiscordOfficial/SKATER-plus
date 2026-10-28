#include "roots.h"
#include "sha256.h"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <stdlib.h>
#include <string.h>

static const char begin_marker[]="-----BEGIN CERTIFICATE-----";
static const char end_marker[]="-----END CERTIFICATE-----";

static int is_space(uint8_t c) {
    return c==' ' || c=='\t' || c=='\r' || c=='\n';
}

int root_extra_at(const uint8_t *bundle,size_t size,size_t base_size,
                  unsigned index,size_t *offset,size_t *length) {
    if (!bundle || base_size>size || size-base_size>ROOT_EXTRA_LIMIT || index>=ROOT_EXTRA_COUNT) return -1;
    size_t pos=base_size,begin=sizeof(begin_marker)-1,end=sizeof(end_marker)-1;
    for (unsigned found=0;found<=index;found++) {
        while (pos<size && is_space(bundle[pos])) pos++;
        if (pos==size) return 0;
        if (size-pos<begin || memcmp(bundle+pos,begin_marker,begin)) return -1;
        size_t stop=pos+begin;
        while (stop+end<=size && memcmp(bundle+stop,end_marker,end)) stop++;
        if (stop+end>size || stop+end-pos>ROOT_PEM_LIMIT) return -1;
        if (found==index) { *offset=pos; *length=stop+end-pos; return 1; }
        pos=stop+end;
    }
    return 0;
}

int root_remove_extra(uint8_t *bundle,size_t *size,size_t base_size,unsigned index) {
    size_t offset=0,length=0;
    if (!size || root_extra_at(bundle,*size,base_size,index,&offset,&length)!=1) return -1;
    memmove(bundle+offset,bundle+offset+length,*size-offset-length);
    *size-=length;
    size_t pos=base_size;
    while (pos<*size && is_space(bundle[pos])) pos++;
    if (pos==*size) *size=base_size;
    return 0;
}

int root_pem_check(const uint8_t *pem,size_t size,uint8_t fingerprint[32],
                   char *subject,size_t subject_size,const char **error) {
    if (error) *error="Invalid PEM";
    if (!pem || !size || size>ROOT_PEM_LIMIT || memchr(pem,0,size)) return -1;
    while (size && is_space(*pem)) { pem++; size--; }
    while (size && is_space(pem[size-1])) size--;
    size_t begin=sizeof(begin_marker)-1,end=sizeof(end_marker)-1;
    if (size<begin+end || memcmp(pem,begin_marker,begin) ||
        memcmp(pem+size-end,end_marker,end)) return -1;
    /* Reject chains, keys, comments and other trailing material. */
    for (size_t i=begin;i<size-end;i++) {
        uint8_t c=pem[i];
        if (!is_space(c) && !(c>='A' && c<='Z') && !(c>='a' && c<='z') &&
            !(c>='0' && c<='9') && c!='+' && c!='/' && c!='=') return -1;
    }
    uint8_t *copy=malloc(size+1);
    if (!copy) { if (error) *error="Out of memory"; return -1; }
    memcpy(copy,pem,size); copy[size]=0;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int rc=mbedtls_x509_crt_parse(&crt,copy,size+1);
    free(copy);
    if (rc || crt.next || !crt.raw.p) { rc=-1; goto done; }
    if (error) *error="Expected a self-signed CA root";
    rc=-1;
    if (!crt.ca_istrue || crt.issuer_raw.len!=crt.subject_raw.len ||
        memcmp(crt.issuer_raw.p,crt.subject_raw.p,crt.issuer_raw.len) ||
        mbedtls_x509_crt_check_key_usage(&crt,MBEDTLS_X509_KU_KEY_CERT_SIGN)) goto done;
    const mbedtls_md_info_t *md=mbedtls_md_info_from_type(crt.sig_md);
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];
    if (!md || mbedtls_md(md,crt.tbs.p,crt.tbs.len,digest) ||
        mbedtls_pk_verify_ext(crt.sig_pk,crt.sig_opts,&crt.pk,crt.sig_md,
                             digest,mbedtls_md_get_size(md),crt.sig.p,crt.sig.len)) goto done;
    sha256_buffer(crt.raw.p,crt.raw.len,fingerprint);
    if (subject && subject_size) {
        if (mbedtls_x509_dn_gets(subject,subject_size,&crt.subject)<0) subject[0]=0;
        for (size_t i=0;i<subject_size && subject[i];i++)
            if ((unsigned char)subject[i]<32 || (unsigned char)subject[i]>=127) subject[i]='?';
    }
    if (error) *error=NULL;
    rc=0;
done:
    mbedtls_x509_crt_free(&crt);
    return rc;
}

int root_bundle_contains(const uint8_t *bundle,size_t size,const uint8_t fingerprint[32]) {
    /* Parse each certificate separately: some bundled stock roots are expired. */
    size_t pos=0,begin=sizeof(begin_marker)-1,end=sizeof(end_marker)-1;
    while (pos+begin<=size) {
        if (memcmp(bundle+pos,begin_marker,begin)) { pos++; continue; }
        size_t stop=pos+begin;
        while (stop+end<=size && memcmp(bundle+stop,end_marker,end)) stop++;
        if (stop+end>size || stop+end-pos>ROOT_PEM_LIMIT) return -1;
        size_t length=stop+end-pos;
        uint8_t *copy=malloc(length+1);
        if (!copy) return -1;
        memcpy(copy,bundle+pos,length); copy[length]=0;
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        int rc=mbedtls_x509_crt_parse(&crt,copy,length+1);
        free(copy);
        if (rc || !crt.raw.p) { mbedtls_x509_crt_free(&crt); return -1; }
        uint8_t got[32];
        sha256_buffer(crt.raw.p,crt.raw.len,got);
        int same=!memcmp(got,fingerprint,32);
        mbedtls_x509_crt_free(&crt);
        if (same) return 1;
        pos=stop+end;
    }
    return 0;
}
