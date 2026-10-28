#include "patch.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_all(const char *path, unsigned char **data, size_t *size) {
    FILE *f=fopen(path,"rb"); if (!f) return -1;
    fseek(f,0,SEEK_END); long n=ftell(f); rewind(f);
    *data=malloc((size_t)n); *size=(size_t)n;
    int ok=*data && fread(*data,1,*size,f)==*size; fclose(f); return ok?0:-1;
}

int main(int argc,char **argv) {
    if (argc!=8) return 2;
    unsigned char *packed=NULL,*source=NULL,*delta=NULL,*expected=NULL,*actual=NULL,*roundtrip=NULL;
    size_t packed_n=0,source_n=0,delta_n=0,expected_n=0,actual_n=0,roundtrip_n=0;
    if (read_all(argv[1],&packed,&packed_n) || read_all(argv[2],&source,&source_n) ||
        read_all(argv[3],&delta,&delta_n) || read_all(argv[4],&expected,&expected_n)) return 3;
    if (lz11_decompress(packed,packed_n,&roundtrip,&roundtrip_n) || roundtrip_n!=source_n || memcmp(roundtrip,source,source_n)) return 4;
    if (delta_apply(delta,delta_n,source,source_n,&actual,&actual_n) || actual_n!=expected_n || memcmp(actual,expected,expected_n)) return 5;
    free(source); free(delta); free(expected); free(actual);
    source=delta=expected=actual=NULL; source_n=delta_n=expected_n=actual_n=0;
    if (read_all(argv[5],&source,&source_n) || read_all(argv[6],&delta,&delta_n) || read_all(argv[7],&expected,&expected_n)) return 7;
    if (delta_apply(delta,delta_n,source,source_n,&actual,&actual_n) || actual_n!=expected_n || memcmp(actual,expected,expected_n)) return 8;
    unsigned char got[32],known[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    sha256_buffer("abc",3,got); if (memcmp(got,known,32)) return 6;
    free(packed); free(source); free(delta); free(expected); free(actual); free(roundtrip);
    puts("PASS patch, LZ11, and SHA-256 tests"); return 0;
}
