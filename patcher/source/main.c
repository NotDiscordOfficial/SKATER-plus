#include <3ds.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "patch.h"
#include "pxi_romfs.h"
#include "roots.h"
#include "sha256.h"

#define PATCHER_TITLE_ID UINT64_C(0x000400000F5A5400)
#define PATCHER_BUILD "0.1.0"
#define STATE_DIR "sdmc:/3ds/skater-plus-patcher"
#define STATE_PATH STATE_DIR "/state.bin"
#define BACKUP_DIR STATE_DIR "/backup"
#define CERTS_DIR STATE_DIR "/certs"

typedef struct { const char *name; u64 base_title, update_title; } Region;
static const Region regions[] = {
    {"JPN", UINT64_C(0x0004003000008802), UINT64_C(0x0004003020008802)},
    {"USA", UINT64_C(0x0004003000009402), UINT64_C(0x0004003020009402)},
    {"EUR/AUS", UINT64_C(0x0004003000009D02), UINT64_C(0x0004003020009D02)},
    {"KOR", UINT64_C(0x000400300000AE02), UINT64_C(0x000400302000AE02)},
};

typedef struct {
    char magic[4];
    u32 version;
    u64 title;
    u32 region;
    u32 backup_mask;
} State;

static bool detected_active_patch;
static bool patcher_uninstalled;
static const char *detect_stage="title list";
static char verify_detail[96];

static const u8 source_raw_sha[32]={0xbd,0xd4,0x28,0xc3,0x71,0x71,0x7b,0x07,0x41,0xcc,0xfc,0x11,0x8b,0xab,0xb3,0x55,0xbf,0xb6,0xd2,0xf3,0x58,0x5b,0xac,0xe2,0xe4,0xdd,0xee,0xe2,0x72,0x3c,0x87,0xde};
static const u8 target_raw_sha[32]={0xeb,0xec,0xae,0x61,0x02,0xc5,0x21,0xd8,0x61,0x24,0xe9,0x15,0x46,0x95,0xf4,0xe7,0x87,0xb8,0xed,0x33,0x6d,0x11,0x84,0xc3,0x63,0x27,0x93,0x23,0x2d,0xe0,0x52,0x14};
static const u8 stock_root_sha[32]={0x3d,0x7e,0x05,0x3f,0xb7,0xb8,0xad,0x42,0x5a,0xb7,0xc0,0xae,0x45,0x23,0xb8,0x37,0x16,0x3c,0xa9,0xd4,0x36,0xf8,0xbf,0xe4,0x3c,0x8f,0xe7,0x30,0x63,0x6d,0x04,0xe2};
static const u8 target_root_sha[32]={0x77,0xd8,0xb6,0x98,0x54,0x42,0xf7,0x4b,0xda,0xd3,0x65,0x5f,0xd1,0x6d,0x87,0x1b,0xaf,0xc0,0x24,0x0a,0xb4,0xcf,0x0b,0x29,0x02,0xf1,0xe0,0x89,0xfc,0xeb,0x68,0x65};
static const u8 target_crr_sha[32]={0x86,0x71,0x2c,0x50,0xa3,0xe4,0xc6,0x25,0x6d,0x8c,0xc8,0x1a,0x4b,0x61,0x33,0x1d,0x6e,0x9a,0x1c,0x46,0x67,0x69,0x41,0xe0,0x06,0x42,0x89,0xff,0x81,0x1f,0x54,0x22};
static const u8 stock_crr_identity[32]={0xaf,0x7d,0x27,0x13,0x33,0x7f,0x09,0xd5,0xf2,0x29,0xae,0x2a,0xfc,0x1d,0xbe,0xe9,0x06,0x4b,0x7a,0x00,0xd3,0x84,0x30,0x69,0xba,0xcf,0xbc,0xb2,0x89,0x82,0xd3,0x3e};
static const u8 target_crr_identity[32]={0x61,0xf2,0x85,0x80,0x86,0xe6,0xda,0xf2,0x1b,0x80,0x25,0xf5,0x66,0x25,0x6e,0xc3,0x8e,0x60,0x3e,0x7d,0x29,0x42,0x6e,0xe2,0xf5,0x4b,0xef,0x8f,0x31,0x08,0xf6,0x95};
static const u8 fixed_crr_identities[96]={
    0x6c,0x0d,0x71,0x5c,0x21,0x7c,0xc4,0xcb,0x37,0x3d,0xc6,0x92,0x1b,0x6f,0x0d,0xb9,0x24,0x75,0xa3,0x40,0xf6,0xcb,0xe0,0x4f,0x78,0x03,0x0c,0x36,0x8f,0x12,0x14,0xab,
    0xef,0x7d,0x94,0xed,0x9b,0x64,0xb1,0x6a,0x30,0x47,0xd4,0x61,0x64,0x5c,0xce,0x45,0x0c,0x5f,0x62,0x41,0x87,0xb9,0x58,0x52,0x63,0x6e,0x0b,0x02,0x78,0x68,0x2c,0x8e,
    0xf5,0x02,0x94,0x9c,0x4a,0x9a,0xa6,0x08,0xec,0x23,0x40,0xed,0x2e,0xa5,0x5a,0x08,0x9e,0xac,0x08,0xca,0xef,0x7d,0x2e,0xfe,0x17,0x00,0x64,0x36,0xa4,0x09,0x0f,0x78,
};
static const u8 legacy_code_sha[4][32]={
    {0x7f,0x61,0xc7,0x54,0x75,0x71,0x92,0xd2,0x42,0x22,0x8e,0x71,0xd9,0x32,0xfd,0x60,0xc5,0xc3,0x33,0x25,0x34,0x1f,0x6c,0x0e,0x1f,0xa5,0xf1,0xb2,0xe8,0x51,0xac,0x7a},
    {0x1d,0x9a,0xd1,0x10,0x6d,0xf8,0xfd,0xb5,0xa0,0xdc,0xb7,0xf8,0x21,0xf3,0x82,0x2c,0x1b,0x2b,0x4a,0x74,0xee,0x08,0x3b,0xa9,0xb4,0x72,0xb1,0x49,0xaf,0x1c,0xb6,0xe3},
    {0x1b,0xbf,0xf5,0x2d,0x75,0x0f,0x58,0x13,0x63,0xfa,0xa6,0xd0,0x40,0xa2,0x98,0xe8,0x75,0x88,0xbb,0x44,0x56,0x40,0x8e,0x0d,0xc0,0x6b,0x80,0x0f,0xfa,0x1a,0x87,0x05},
    {0xd2,0x70,0x0a,0x6f,0xe9,0xd5,0xe9,0xe8,0xb9,0x74,0x22,0x23,0x26,0x8e,0xc2,0x4f,0xfe,0x2b,0x26,0x3b,0x1b,0xe9,0xe9,0xf2,0xe3,0x5c,0xf0,0xaa,0xba,0xe4,0x9a,0xed},
};

enum { FILE_CODE, FILE_CRO, FILE_CRR, FILE_ROOTS, FILE_COUNT };

static int read_file(const char *path, u8 **data, size_t *size) {
    FILE *f=fopen(path,"rb"); if (!f) return -1;
    if (fseek(f,0,SEEK_END) || ftell(f)<0) { fclose(f); return -1; }
    long length=ftell(f); rewind(f); u8 *buffer=malloc(length ? (size_t)length : 1);
    if (!buffer) { fclose(f); return -2; }
    if (fread(buffer,1,length,f)!=(size_t)length) { free(buffer); fclose(f); return -1; }
    fclose(f); *data=buffer; *size=(size_t)length; return 0;
}

static int read_browser_file(const char *path,u8 **data,size_t *size) {
    const char *prefix="stock:/";
    if (!strncmp(path,prefix,strlen(prefix))) path+=strlen(prefix);
    return pxi_romfs_read_file(path,data,size);
}

static bool file_exists(const char *path) { struct stat st; return stat(path,&st)==0 && S_ISREG(st.st_mode); }
static int mkdir_one(const char *path) { return mkdir(path,0777)==0 || errno==EEXIST ? 0 : -1; }

static int game_patching_status(Result *result) {
    s64 is_emulator=0;
    if (R_SUCCEEDED(svcGetSystemInfo(&is_emulator,0x20000,0)) && is_emulator) {
        if (result) *result=0;
        return 1;
    }

    s64 options=0;
    Result rc=svcGetSystemInfo(&options,0x10000,3);
    if (result) *result=rc;
    if (R_FAILED(rc)) return -1;
    return (int)((options>>2)&1);
}

static int make_title_dirs(u64 title) {
    char p[160];
    if (mkdir_one("sdmc:/luma") || mkdir_one("sdmc:/luma/titles")) return -1;
    snprintf(p,sizeof(p),"sdmc:/luma/titles/%016llX",(unsigned long long)title); if (mkdir_one(p)) return -1;
    strncat(p,"/romfs",sizeof(p)-strlen(p)-1); if (mkdir_one(p)) return -1;
    char romfs[160]; snprintf(romfs,sizeof(romfs),"%s",p);
    strncat(p,"/.crr",sizeof(p)-strlen(p)-1); if (mkdir_one(p)) return -1;
    strncat(romfs,"/browser",sizeof(romfs)-strlen(romfs)-1); return mkdir_one(romfs);
}

static int write_atomic(const char *path, const void *data, size_t size) {
    char temp[256]; snprintf(temp,sizeof(temp),"%s.tmp",path); remove(temp);
    FILE *f=fopen(temp,"wb"); if (!f) return -1;
    bool ok=fwrite(data,1,size,f)==size && fflush(f)==0;
    if (fclose(f)!=0) ok=false;
    if (!ok) { remove(temp); return -1; }
    remove(path); if (rename(temp,path)!=0) { remove(temp); return -1; } return 0;
}

static int copy_file(const char *from, const char *to) {
    u8 *data=NULL; size_t size=0; int rc=read_file(from,&data,&size);
    if (!rc) rc=write_atomic(to,data,size);
    free(data); return rc;
}

static bool hash_is(const void *data,size_t size,const u8 wanted[32]) { u8 got[32]; sha256_buffer(data,size,got); return memcmp(got,wanted,32)==0; }

static void title_paths(u64 title, char out[FILE_COUNT][192]) {
    char base[128]; snprintf(base,sizeof(base),"sdmc:/luma/titles/%016llX",(unsigned long long)title);
    snprintf(out[FILE_CODE],192,"%s/code.ips",base);
    snprintf(out[FILE_CRO],192,"%s/romfs/os2.cro.lex",base);
    snprintf(out[FILE_CRR],192,"%s/romfs/.crr/tlsfix.crr",base);
    snprintf(out[FILE_ROOTS],192,"%s/romfs/browser/rootca.pem",base);
}

static bool file_matches(const char *path,const u8 wanted[32]) {
    u8 *data=NULL; size_t size=0; bool ok=read_file(path,&data,&size)==0 && hash_is(data,size,wanted); free(data); return ok;
}

static void roots_hash_path(unsigned region,char path[160]) {
    snprintf(path,160,STATE_DIR "/roots-%s.sha256",region==2?"EUR":regions[region].name);
}

static bool roots_file_matches(unsigned region,const char *path) {
    if (file_matches(path,target_root_sha)) return true;
    char registry[160]; roots_hash_path(region,registry);
    u8 *hashes=NULL; size_t count=0;
    if (read_file(registry,&hashes,&count)) return false;
    bool match=(count==32 || count==64) &&
               (file_matches(path,hashes) || (count==64 && file_matches(path,hashes+32)));
    free(hashes);
    return match;
}

static u32 read_le32(const u8 *p) { return (u32)p[0]|(u32)p[1]<<8|(u32)p[2]<<16|(u32)p[3]<<24; }

static bool crr_structure_matches(const u8 *data,size_t size,const u8 first_identity[32]) {
    return size==0x1000 && read_le32(data+0x350)==0x360 && read_le32(data+0x354)==4 &&
           !memcmp(data+0x360,first_identity,32) &&
           !memcmp(data+0x380,fixed_crr_identities,sizeof(fixed_crr_identities));
}

static bool crr_matches(const char *path) {
    u8 *data=NULL; size_t size=0;
    bool ok=read_file(path,&data,&size)==0 &&
            (hash_is(data,size,target_crr_sha) || crr_structure_matches(data,size,target_crr_identity));
    free(data); return ok;
}

static int build_target_crr(const u8 *source,size_t size,u8 **targetp,size_t *target_size) {
    if (!crr_structure_matches(source,size,stock_crr_identity) &&
        !crr_structure_matches(source,size,target_crr_identity)) return -1;
    u8 *target=malloc(size);
    if (!target) return -2;
    memcpy(target,source,size);
    memcpy(target+0x360,target_crr_identity,sizeof(target_crr_identity));
    *targetp=target; *target_size=size; return 0;
}

static bool cro_matches(const char *path) {
    u8 *packed=NULL,*raw=NULL; size_t packed_size=0,raw_size=0;
    bool ok=read_file(path,&packed,&packed_size)==0 && lz11_decompress(packed,packed_size,&raw,&raw_size)==0 && hash_is(raw,raw_size,target_raw_sha);
    free(packed); free(raw); return ok;
}

static int load_asset(const char *name,u8 **data,size_t *size) { char p[160]; snprintf(p,sizeof(p),"romfs:/assets/%s",name); return read_file(p,data,size); }

static bool installed_file_is_ours(unsigned item,unsigned region,const char *path) {
    if (!file_exists(path)) return true;
    if (item==FILE_CRO) return cro_matches(path);
    if (item==FILE_CRR) return crr_matches(path);
    if (item==FILE_ROOTS) return roots_file_matches(region,path);
    char asset[64]; snprintf(asset,sizeof(asset),"%s/code.ips",region==2?"EUR":regions[region].name);
    u8 *expected=NULL,*actual=NULL; size_t expected_n=0,actual_n=0;
    bool ok=load_asset(asset,&expected,&expected_n)==0 && read_file(path,&actual,&actual_n)==0 && expected_n==actual_n && !memcmp(expected,actual,actual_n);
    free(expected); free(actual); return ok;
}

enum { ART_CODE_IPS, ART_CODE_BIN, ART_CRO, ART_CRR, ART_ROOTS };
typedef struct { const char *relative; unsigned kind; } PatchArtifact;
static const PatchArtifact patch_artifacts[]={
    {"code.ips",ART_CODE_IPS}, {"code.bin",ART_CODE_BIN},
    {"romfs/os2.cro.lex",ART_CRO}, {"romfs/oss.cro.lex",ART_CRO},
    {"romfs/.crr/tlsfix.crr",ART_CRR}, {"romfs/.crr/static.crr",ART_CRR},
    {"romfs/rootca.pem",ART_ROOTS}, {"romfs/browser/rootca.pem",ART_ROOTS},
};

static bool patch_artifact_is_ours(unsigned region,unsigned kind,const char *path) {
    if (kind==ART_CODE_BIN) return file_matches(path,legacy_code_sha[region]);
    if (kind==ART_CRO) return cro_matches(path);
    if (kind==ART_CRR) return crr_matches(path);
    if (kind==ART_ROOTS) return roots_file_matches(region,path);
    char asset[64]; snprintf(asset,sizeof(asset),"%s/code.ips",region==2?"EUR":regions[region].name);
    u8 *expected=NULL,*actual=NULL; size_t expected_n=0,actual_n=0;
    bool ok=load_asset(asset,&expected,&expected_n)==0 && read_file(path,&actual,&actual_n)==0 && expected_n==actual_n && !memcmp(expected,actual,actual_n);
    free(expected); free(actual); return ok;
}

static void artifact_path(u64 title,const PatchArtifact *artifact,char out[192]) {
    snprintf(out,192,"sdmc:/luma/titles/%016llX/%s",(unsigned long long)title,artifact->relative);
}

static bool mounted_browser_is_supported(void) {
    u8 *packed=NULL,*raw=NULL; size_t packed_n=0,raw_n=0;
    bool ok=false;
    int rc=read_browser_file("oss.cro.lex",&packed,&packed_n);
    if (rc) snprintf(verify_detail,sizeof(verify_detail),"oss.cro.lex read failed (%d/%d)",rc,errno);
    else if ((rc=lz11_decompress(packed,packed_n,&raw,&raw_n))!=0)
        snprintf(verify_detail,sizeof(verify_detail),"LZ11 failed (%d), packed=%lu",rc,(unsigned long)packed_n);
    else {
        if (hash_is(raw,raw_n,target_raw_sha)) { detected_active_patch=true; ok=true; }
        else ok=hash_is(raw,raw_n,source_raw_sha);
        if (!ok) {
            u8 digest[32]; sha256_buffer(raw,raw_n,digest);
            snprintf(verify_detail,sizeof(verify_detail),"raw=%lu sha=%02X%02X%02X%02X%02X%02X%02X%02X",
                     (unsigned long)raw_n,digest[0],digest[1],digest[2],digest[3],
                     digest[4],digest[5],digest[6],digest[7]);
        }
    }
    free(packed); free(raw); return ok;
}

static int detect_region(Result *last_result) {
    *last_result=0;
    detect_stage="AM title list";
    Result ar=amInit();
    if (R_FAILED(ar)) { *last_result=ar; return -1; }
    u32 count=0,read=0;
    Result r=AM_GetTitleCount(MEDIATYPE_NAND,&count);
    if (R_FAILED(r)) { *last_result=r; amExit(); return -1; }
    u64 *titles=calloc(count ? count : 1,sizeof(*titles));
    if (!titles) { amExit(); return -1; }
    r=AM_GetTitleList(&read,MEDIATYPE_NAND,count,titles);
    if (R_FAILED(r)) { *last_result=r; free(titles); amExit(); return -1; }
    for (unsigned i=0;i<sizeof(regions)/sizeof(regions[0]);i++) {
        const u64 candidates[]={regions[i].update_title,regions[i].base_title};
        bool region_installed=false;
        for (unsigned j=0;j<sizeof(candidates)/sizeof(candidates[0]);j++)
            for (u32 k=0;k<read;k++) if (titles[k]==candidates[j]) region_installed=true;
        if (!region_installed) continue;

        for (unsigned j=0;j<sizeof(candidates)/sizeof(candidates[0]);j++) {
            bool installed=false;
            for (u32 k=0;k<read;k++) if (titles[k]==candidates[j]) { installed=true; break; }
            if (!installed) continue;
            detect_stage="PxiFS0 browser RomFS open";
            r=pxi_romfs_open(candidates[j]);
            if (R_FAILED(r)) { detect_stage=pxi_romfs_stage(); *last_result=r; pxi_romfs_close(); continue; }
            detect_stage="browser data verification";
            if (mounted_browser_is_supported()) { free(titles); amExit(); return (int)i; }
            pxi_romfs_close();
        }
    }
    free(titles);
    amExit();
    return -1;
}

static int prepare_state(unsigned region,const char paths[FILE_COUNT][192],State *state) {
    if (mkdir_one("sdmc:/3ds") || mkdir_one(STATE_DIR) || mkdir_one(BACKUP_DIR)) return -1;
    if (file_exists(STATE_PATH)) {
        u8 *raw=NULL; size_t size=0;
        if (read_file(STATE_PATH,&raw,&size) || size!=sizeof(*state)) { free(raw); return -1; }
        memcpy(state,raw,sizeof(*state)); free(raw);
        if (memcmp(state->magic,"SKS1",4) || state->version!=2 || state->title!=regions[region].base_title) return -1;
        for (unsigned i=0;i<FILE_COUNT;i++) if (!installed_file_is_ours(i,region,paths[i])) return -1;
        return 0;
    }
    memcpy(state->magic,"SKS1",4); state->version=2; state->title=regions[region].base_title; state->region=region; state->backup_mask=0;
    for (unsigned i=0;i<FILE_COUNT;i++) if (file_exists(paths[i])) {
        if (installed_file_is_ours(i,region,paths[i])) continue;
        char backup[160]; snprintf(backup,sizeof(backup),BACKUP_DIR "/%u.bin",i);
        if (copy_file(paths[i],backup)) return -1;
        state->backup_mask|=1u<<i;
    }
    return write_atomic(STATE_PATH,state,sizeof(*state));
}

static int install_patch(unsigned region) {
    printf("\nRegion: %s\nReading official browser files...\n",regions[region].name);
    u8 *packed=NULL,*source=NULL,*delta=NULL,*target=NULL,*stock_roots=NULL,*suffix=NULL,*stock_crr=NULL,*target_crr=NULL,*code=NULL;
    size_t packed_n=0,source_n=0,delta_n=0,target_n=0,roots_n=0,suffix_n=0,stock_crr_n=0,target_crr_n=0,code_n=0;
    int rc=-1; char asset[64];
    if (read_browser_file("oss.cro.lex",&packed,&packed_n) || lz11_decompress(packed,packed_n,&source,&source_n)) { printf("Unsupported oss.cro.lex.\n"); goto done; }
    free(packed); packed=NULL;
    if (hash_is(source,source_n,target_raw_sha)) {
        target=malloc(source_n ? source_n : 1); if (!target) goto done;
        memcpy(target,source,source_n); target_n=source_n;
    } else if (hash_is(source,source_n,source_raw_sha)) {
        if (load_asset("oss.delta",&delta,&delta_n) || delta_apply(delta,delta_n,source,source_n,&target,&target_n) || !hash_is(target,target_n,target_raw_sha)) { printf("CRO delta validation failed.\n"); goto done; }
    } else { printf("Unsupported oss.cro.lex.\n"); goto done; }
    if (read_browser_file("browser/rootca.pem",&stock_roots,&roots_n)) { printf("Unsupported rootca.pem.\n"); goto done; }
    if (hash_is(stock_roots,roots_n,stock_root_sha)) {
        if (load_asset("rootca.append",&suffix,&suffix_n)) goto done;
        while (roots_n && (stock_roots[roots_n-1]==' ' || stock_roots[roots_n-1]=='\t' || stock_roots[roots_n-1]=='\r' || stock_roots[roots_n-1]=='\n')) roots_n--;
        u8 *roots=realloc(stock_roots,roots_n+suffix_n); if (!roots) goto done;
        stock_roots=roots; memcpy(stock_roots+roots_n,suffix,suffix_n); roots_n+=suffix_n;
    }
    if (!hash_is(stock_roots,roots_n,target_root_sha)) { printf("Root bundle validation failed.\n"); goto done; }
    int crr_rc=read_browser_file(".crr/static.crr",&stock_crr,&stock_crr_n);
    if (crr_rc) { printf("CRR read failed: %d\n",crr_rc); goto done; }
    crr_rc=build_target_crr(stock_crr,stock_crr_n,&target_crr,&target_crr_n);
    if (crr_rc) {
        u8 digest[32]; sha256_buffer(stock_crr,stock_crr_n,digest);
        printf("Unsupported CRR structure: %d\nsource=%lu sha=%02X%02X%02X%02X%02X%02X%02X%02X\n",crr_rc,
               (unsigned long)stock_crr_n,digest[0],digest[1],digest[2],digest[3],
               digest[4],digest[5],digest[6],digest[7]);
        goto done;
    }
    snprintf(asset,sizeof(asset),"%s/code.ips",region==2?"EUR":regions[region].name);
    if (load_asset(asset,&code,&code_n)) goto done;

    char paths[FILE_COUNT][192]; title_paths(regions[region].base_title,paths); State state;
    if (make_title_dirs(regions[region].base_title) || prepare_state(region,paths,&state)) { printf("Could not create a safe backup state.\n"); goto done; }
    printf("Writing verified Luma patch...\n");
    if (write_atomic(paths[FILE_CODE],code,code_n) || write_atomic(paths[FILE_CRR],target_crr,target_crr_n) || write_atomic(paths[FILE_ROOTS],stock_roots,roots_n)) goto write_fail;
    char temp[224]; snprintf(temp,sizeof(temp),"%s.tmp",paths[FILE_CRO]); remove(temp);
    if (lz11_write_literals(temp,target,target_n)) goto write_fail;
    remove(paths[FILE_CRO]); if (rename(temp,paths[FILE_CRO])) goto write_fail;
    printf("\x1b[32mInstall complete.\x1b[0m\nEnable Luma game patching, then launch the browser.\n"); rc=0; goto done;
write_fail: printf("Write failed. Any displaced files remain in the backup directory.\n");
done:
    free(packed); free(source); free(delta); free(target); free(stock_roots); free(suffix); free(stock_crr); free(target_crr); free(code); return rc;
}

static bool known_patch_at_title(unsigned region,u64 title) {
    for (unsigned i=0;i<sizeof(patch_artifacts)/sizeof(patch_artifacts[0]);i++) {
        char path[192]; artifact_path(title,&patch_artifacts[i],path);
        if (file_exists(path) && !patch_artifact_is_ours(region,patch_artifacts[i].kind,path)) return false;
    }
    return true;
}

static void remove_known_patch_at_title(unsigned region,u64 title) {
    for (unsigned i=0;i<sizeof(patch_artifacts)/sizeof(patch_artifacts[0]);i++) {
        char path[192]; artifact_path(title,&patch_artifacts[i],path);
        if (file_exists(path) && patch_artifact_is_ours(region,patch_artifacts[i].kind,path)) remove(path);
    }
}

static int remove_active_patch(unsigned region) {
    const u64 titles[]={regions[region].base_title,regions[region].update_title};
    for (unsigned i=0;i<sizeof(titles)/sizeof(titles[0]);i++)
        if (!known_patch_at_title(region,titles[i])) {
            printf("Patch files differ; removal stopped.\n");
            return -1;
        }
    for (unsigned i=0;i<sizeof(titles)/sizeof(titles[0]);i++) remove_known_patch_at_title(region,titles[i]);
    char registry[160]; roots_hash_path(region,registry); remove(registry);
    bool backups=false;
    for (unsigned i=0;i<FILE_COUNT;i++) {
        char backup[160]; snprintf(backup,sizeof(backup),BACKUP_DIR "/%u.bin",i);
        if (file_exists(backup)) backups=true;
    }
    if (!backups) {
        remove(STATE_PATH); rmdir(BACKUP_DIR); rmdir(STATE_DIR);
    }
    printf("\x1b[32mPatch removed.\x1b[0m\nYou can open the browser now.\n");
    if (backups) printf("Pre-existing files were kept in\n" BACKUP_DIR ".\n");
    return 0;
}

static bool confirm_root(const char *filename,const char *subject,const u8 fingerprint[32]) {
    printf("\x1b[2J\x1b[1;1HAdd trusted root certificate?\n\n%.80s\n%.180s\n\nSHA-256 (DER):\n",filename,subject);
    for (unsigned i=0;i<32;i++) printf("%02X%s",fingerprint[i],i%16==15?"\n":":");
    printf("\nOnly accept a CA you trust.\nA  Add\nB or START  Cancel\n");
    while (aptMainLoop()) {
        hidScanInput(); u32 down=hidKeysDown();
        if (down&(KEY_B|KEY_START)) return false;
        if (down&KEY_A) return true;
        gspWaitForVBlank();
    }
    return false;
}

static void import_roots(unsigned region) {
    char paths[FILE_COUNT][192]; title_paths(regions[region].base_title,paths);
    if (mkdir_one("sdmc:/3ds") || mkdir_one(STATE_DIR) || mkdir_one(CERTS_DIR)) {
        printf("Could not create certificate folder.\n"); return;
    }
    u8 *bundle=NULL,*stock=NULL,*suffix=NULL;
    size_t size=0,stock_size=0,suffix_size=0;
    if (!roots_file_matches(region,paths[FILE_ROOTS]) ||
        read_file(paths[FILE_ROOTS],&bundle,&size) ||
        read_browser_file("browser/rootca.pem",&stock,&stock_size) ||
        load_asset("rootca.append",&suffix,&suffix_size)) {
        printf("Install the patch before importing certificates.\n"); goto done;
    }
    /* Recognize the fixed base before accepting any existing extra roots. */
    while (stock_size && (stock[stock_size-1]==' ' || stock[stock_size-1]=='\t' ||
           stock[stock_size-1]=='\r' || stock[stock_size-1]=='\n')) stock_size--;
    size_t base_size=stock_size+suffix_size;
    if (size<base_size || !hash_is(bundle,base_size,target_root_sha) || size-base_size>ROOT_EXTRA_LIMIT) {
        printf("Unexpected root bundle. Import stopped.\n"); goto done;
    }
    unsigned extra_count=0;
    const char *marker="-----BEGIN CERTIFICATE-----";
    for (size_t i=base_size;i+strlen(marker)<=size;i++)
        if (!memcmp(bundle+i,marker,strlen(marker))) extra_count++;
    DIR *dir=opendir(CERTS_DIR);
    if (!dir) { printf("Could not open certificate folder.\n"); goto done; }
    unsigned added=0,skipped=0,invalid=0;
    struct dirent *entry;
    while ((entry=readdir(dir))!=NULL) {
        const char *ext=strrchr(entry->d_name,'.');
        if (!ext || (strcmp(ext,".pem") && strcmp(ext,".crt"))) continue;
        char source[512];
        if (snprintf(source,sizeof(source),CERTS_DIR "/%s",entry->d_name)>=(int)sizeof(source)) { invalid++; continue; }
        struct stat st;
        if (stat(source,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>ROOT_PEM_LIMIT) { invalid++; continue; }
        u8 *pem=NULL; size_t pem_size=0; u8 fingerprint[32]; char subject[192]; const char *error=NULL;
        if (read_file(source,&pem,&pem_size) ||
            root_pem_check(pem,pem_size,fingerprint,subject,sizeof(subject),&error)) {
            printf("Rejected %.64s: %s\n",entry->d_name,error?error:"Read failed");
            free(pem); invalid++; continue;
        }
        int duplicate=root_bundle_contains(bundle,size,fingerprint);
        if (duplicate<0) { free(pem); printf("Root bundle parse failed.\n"); break; }
        if (duplicate) { free(pem); skipped++; continue; }
        if (extra_count>=ROOT_EXTRA_COUNT || pem_size+2>ROOT_EXTRA_LIMIT-(size-base_size)) {
            free(pem); printf("Custom root limit reached (4 roots / 16 KiB).\n"); break;
        }
        if (!confirm_root(entry->d_name,subject,fingerprint)) { free(pem); skipped++; continue; }
        u8 *next=realloc(bundle,size+pem_size+2);
        if (!next) { free(pem); printf("Out of memory.\n"); break; }
        bundle=next;
        u8 hashes[64]; sha256_buffer(bundle,size,hashes);
        bundle[size]='\n'; memcpy(bundle+size+1,pem,pem_size); bundle[size+pem_size+1]='\n';
        size_t next_size=size+pem_size+2;
        sha256_buffer(bundle,next_size,hashes+32);
        free(pem);
        char registry[160]; roots_hash_path(region,registry);
        /* Keep both hashes until the bundle replacement succeeds. */
        if (write_atomic(registry,hashes,sizeof(hashes)) ||
            write_atomic(paths[FILE_ROOTS],bundle,next_size)) {
            printf("Certificate write failed. Import stopped.\n"); break;
        }
        size=next_size; extra_count++; added++;
    }
    closedir(dir);
    printf("\nAdded: %u  Skipped: %u  Rejected: %u\n",added,skipped,invalid);
    printf("PEM roots folder:\n" CERTS_DIR "\nClose and reopen the browser to use new roots.\n");
done:
    free(bundle); free(stock); free(suffix);
}

static void remove_extra_roots(unsigned region) {
    char paths[FILE_COUNT][192]; title_paths(regions[region].base_title,paths);
    u8 *bundle=NULL,*stock=NULL,*suffix=NULL;
    size_t size=0,stock_size=0,suffix_size=0;
    if (!roots_file_matches(region,paths[FILE_ROOTS]) ||
        read_file(paths[FILE_ROOTS],&bundle,&size) ||
        read_browser_file("browser/rootca.pem",&stock,&stock_size) ||
        load_asset("rootca.append",&suffix,&suffix_size)) {
        printf("Could not read the installed root bundle.\n"); goto done;
    }
    while (stock_size && (stock[stock_size-1]==' ' || stock[stock_size-1]=='\t' ||
           stock[stock_size-1]=='\r' || stock[stock_size-1]=='\n')) stock_size--;
    size_t base_size=stock_size+suffix_size;
    if (size<base_size || !hash_is(bundle,base_size,target_root_sha)) {
        printf("Unexpected root bundle.\n"); goto done;
    }
    unsigned count=0;
    size_t offset=0,length=0;
    while (count<ROOT_EXTRA_COUNT && root_extra_at(bundle,size,base_size,count,&offset,&length)==1) count++;
    if (!count) { printf("No imported certificates to remove.\n"); goto done; }
    unsigned selected=0;
    bool redraw=true;
    while (aptMainLoop()) {
        if (redraw) {
            u8 fingerprint[32]; char subject[192]; const char *error=NULL;
            if (root_extra_at(bundle,size,base_size,selected,&offset,&length)!=1 ||
                root_pem_check(bundle+offset,length,fingerprint,subject,sizeof(subject),&error)) {
                printf("Invalid imported certificate.\n"); break;
            }
            printf("\x1b[2J\x1b[1;1HImported certificate %u / %u\n\n%.180s\n\nSHA-256 (DER):\n",selected+1,count,subject);
            for (unsigned i=0;i<32;i++) printf("%02X%s",fingerprint[i],i%16==15?"\n":":");
            printf("\nUP/DOWN  Select certificate\nA  Remove this certificate\nB or START  Cancel\n");
            redraw=false;
        }
        hidScanInput(); u32 down=hidKeysDown();
        if (down&(KEY_B|KEY_START)) break;
        if (down&KEY_UP) { selected=(selected+count-1)%count; redraw=true; }
        if (down&KEY_DOWN) { selected=(selected+1)%count; redraw=true; }
        if (down&KEY_A) {
            u8 hashes[64]; sha256_buffer(bundle,size,hashes);
            if (root_remove_extra(bundle,&size,base_size,selected)) { printf("Removal failed.\n"); break; }
            sha256_buffer(bundle,size,hashes+32);
            char registry[160]; roots_hash_path(region,registry);
            if (write_atomic(registry,hashes,sizeof(hashes)) || write_atomic(paths[FILE_ROOTS],bundle,size)) {
                printf("Certificate write failed.\n"); break;
            }
            if (size==base_size) remove(registry);
            printf("\x1b[2J\x1b[1;1HCertificate removed.\nClose and reopen the browser.\nSource PEM file remains in certs/.\n");
            break;
        }
        gspWaitForVBlank();
    }
done:
    free(bundle); free(stock); free(suffix);
}

static bool patch_files_active(unsigned region) {
    const u64 titles[]={regions[region].base_title,regions[region].update_title};
    for (unsigned t=0;t<sizeof(titles)/sizeof(titles[0]);t++) {
        for (unsigned i=0;i<sizeof(patch_artifacts)/sizeof(patch_artifacts[0]);i++) {
            char path[192]; artifact_path(titles[t],&patch_artifacts[i],path);
            if (file_exists(path) && patch_artifact_is_ours(region,patch_artifacts[i].kind,path)) return true;
        }
    }
    return false;
}

static void maybe_self_delete(void) {
    if (envIsHomebrew()) { printf("\n3DSX launch: self-delete is unavailable.\n"); return; }
    printf("\nPress X to uninstall this patcher CIA,\nor B to keep it.\n");
    while (aptMainLoop()) { hidScanInput(); u32 down=hidKeysDown(); if (down&KEY_B) return; if (down&KEY_X) {
        Result r=amInit(); if (R_SUCCEEDED(r)) { r=AM_DeleteUserTitle(MEDIATYPE_SD,PATCHER_TITLE_ID); amExit(); }
        if (R_SUCCEEDED(r)) { patcher_uninstalled=true; printf("Patcher uninstalled. Press START to exit.\n"); return; }
        printf("Self-delete failed: %08lX\n",(unsigned long)r); return;
    }}
}

int main(void) {
    gfxInitDefault(); consoleInit(GFX_BOTTOM,NULL); printf("\x1b[2J\x1b[1;1HSKATER+ Patcher\nBuild: %s\n\n",PATCHER_BUILD);
    Result luma_result=0;
    int game_patching=game_patching_status(&luma_result);
    if (game_patching<=0) {
        if (game_patching<0) printf("Luma3DS settings could not be read.\nResult: %08lX\n\n",(unsigned long)luma_result);
        else printf("Enable game patching is disabled.\n\n");
        printf("Hold SELECT while booting, enable\nEnable game patching, press START to save,\nthen launch this patcher again.\n");
        goto exit_wait;
    }
    if (R_FAILED(romfsInit())) { printf("Could not mount patcher assets.\n"); goto exit_wait; }
    Result detect_result=0;
    int region=detect_region(&detect_result);
    if (region<0) {
        printf("Supported New 3DS browser data could not be read.\n");
        printf("Step: %s\n",detect_stage);
        if (!strcmp(detect_stage,"browser data verification") && verify_detail[0]) printf("Detail: %s\n",verify_detail);
        if (R_FAILED(detect_result)) printf("FS result: %08lX\n",(unsigned long)detect_result);
        if (envIsHomebrew()) printf("If NAND title access is denied, use the CIA build.\n");
        goto exit_assets;
    }
    detected_active_patch=detected_active_patch || patch_files_active((unsigned)region);
    printf("Detected region: %s\nTitle: %016llX\n\n",regions[region].name,(unsigned long long)regions[region].base_title);
    if (detected_active_patch) {
        printf("The patch is already active.\nA  Remove patch\nY  Add SD certificates\nL  Remove imported certificates\nX  Uninstall patcher CIA\nB or START  Keep patch and exit\n");
        while (aptMainLoop()) {
            hidScanInput(); u32 down=hidKeysDown();
            if (down&(KEY_B|KEY_START)) break;
            if (down&KEY_A) { remove_active_patch((unsigned)region); break; }
            if (down&KEY_Y) { import_roots((unsigned)region); break; }
            if (down&KEY_L) { remove_extra_roots((unsigned)region); break; }
            if (down&KEY_X) { maybe_self_delete(); break; }
            gspWaitForVBlank(); gfxFlushBuffers(); gfxSwapBuffers();
        }
        goto detected_done;
    }
    printf("A  Install/update patch\nX  Uninstall patcher CIA\nSTART  Exit\n");
    while (aptMainLoop()) {
        hidScanInput(); u32 down=hidKeysDown();
        if (down&KEY_START) break;
        if (down&KEY_A) { if (!install_patch((unsigned)region)) maybe_self_delete(); break; }
        if (down&KEY_X) { maybe_self_delete(); break; }
        gspWaitForVBlank(); gfxFlushBuffers(); gfxSwapBuffers();
    }
detected_done:
    pxi_romfs_close();
exit_assets: romfsExit();
exit_wait: printf("\nPress START to exit.\n");
    if (!envIsHomebrew() && !patcher_uninstalled) printf("X  Uninstall patcher CIA\n");
    while (aptMainLoop()) {
        hidScanInput(); u32 down=hidKeysDown();
        if (down&KEY_START) break;
        if ((down&KEY_X) && !envIsHomebrew() && !patcher_uninstalled) maybe_self_delete();
        gspWaitForVBlank();
    }
    gfxExit(); return 0;
}
