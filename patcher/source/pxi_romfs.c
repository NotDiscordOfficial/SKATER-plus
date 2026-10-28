#include <3ds.h>
#include <3ds/services/fspxi.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "pxi_romfs.h"

#define ROMFS_NONE UINT32_MAX
#define MAX_TABLE_SIZE (16u * 1024u * 1024u)

typedef struct {
    Handle service;
    FSPXI_Archive archive;
    FSPXI_File file;
    u64 program_handle;
    u64 base_offset;
    romfs_header header;
    u8 *dirs;
    u8 *files;
    bool archive_open;
    bool file_open;
    bool loader_active;
} PxiRomfs;

typedef struct __attribute__((packed)) {
    u64 offset;
    u64 size;
    u32 block_size_log2;
    u32 reserved;
} IvfcLevel;

typedef struct __attribute__((packed)) {
    u32 magic;
    u32 type;
    u32 master_hash_size;
    IvfcLevel level[3];
    u32 header_size;
    u32 reserved;
} IvfcHeader;

_Static_assert(sizeof(IvfcHeader)==0x5C,"Unexpected IVFC header layout");

static PxiRomfs ctx;
static Result last_result;
static const char *stage="not started";

__attribute__((naked)) static Result control_service(u32 op __attribute__((unused)), ...) {
    __asm__ volatile("svc 0xB0\n"
                     "bx lr\n");
}

static bool read_exact(u64 offset, void *buffer, u32 size) {
    u32 got=0;
    last_result=FSPXI_ReadFile(ctx.service,ctx.file,&got,offset,buffer,size);
    return R_SUCCEEDED(last_result) && got==size;
}

static bool read_romfs_exact(u64 offset,void *buffer,u32 size) {
    if (offset>UINT64_MAX-ctx.base_offset) return false;
    return read_exact(ctx.base_offset+offset,buffer,size);
}

static bool range_ok(u32 offset,u32 need,u32 size) {
    return offset<=size && need<=size-offset;
}

static romfs_dir *dir_at(u32 offset) {
    if (!range_ok(offset,sizeof(romfs_dir),ctx.header.dirTableSize)) return NULL;
    romfs_dir *dir=(romfs_dir *)(ctx.dirs+offset);
    if (!range_ok(offset,sizeof(romfs_dir)+dir->nameLen,ctx.header.dirTableSize) || (dir->nameLen&1)) return NULL;
    return dir;
}

static romfs_file *file_at(u32 offset) {
    if (!range_ok(offset,sizeof(romfs_file),ctx.header.fileTableSize)) return NULL;
    romfs_file *file=(romfs_file *)(ctx.files+offset);
    if (!range_ok(offset,sizeof(romfs_file)+file->nameLen,ctx.header.fileTableSize) || (file->nameLen&1)) return NULL;
    return file;
}

static bool ascii_name_is(const u16 *actual,u32 bytes,const char *wanted,size_t length) {
    if (bytes!=length*2) return false;
    for (size_t i=0;i<length;i++) if (wanted[i]=='\0' || actual[i]!=(u8)wanted[i]) return false;
    return true;
}

static u32 child_dir(u32 parent,const char *name,size_t length) {
    romfs_dir *p=dir_at(parent);
    if (!p) return ROMFS_NONE;
    u32 current=p->childDir;
    for (u32 guard=0;current!=ROMFS_NONE && guard<ctx.header.dirTableSize/sizeof(romfs_dir)+1;guard++) {
        romfs_dir *entry=dir_at(current);
        if (!entry) return ROMFS_NONE;
        if (ascii_name_is(entry->name,entry->nameLen,name,length)) return current;
        current=entry->sibling;
    }
    return ROMFS_NONE;
}

static romfs_file *child_file(u32 parent,const char *name,size_t length) {
    romfs_dir *p=dir_at(parent);
    if (!p) return NULL;
    u32 current=p->childFile;
    for (u32 guard=0;current!=ROMFS_NONE && guard<ctx.header.fileTableSize/sizeof(romfs_file)+1;guard++) {
        romfs_file *entry=file_at(current);
        if (!entry) return NULL;
        if (ascii_name_is(entry->name,entry->nameLen,name,length)) return entry;
        current=entry->sibling;
    }
    return NULL;
}

Result pxi_romfs_open(u64 title_id) {
    pxi_romfs_close();
    stage="Loader service";
    last_result=loaderInit();
    if (R_FAILED(last_result)) return last_result;
    ctx.loader_active=true;

    FS_ProgramInfo program={0};
    program.programId=title_id;
    program.mediaType=MEDIATYPE_NAND;
    stage="Loader browser registration";
    last_result=LOADER_RegisterProgram(&ctx.program_handle,&program,&program);
    if (R_FAILED(last_result)) { pxi_romfs_close(); return last_result; }

    stage="PxiFS0 session";
    last_result=control_service(0,&ctx.service,"PxiFS0");
    if (R_FAILED(last_result)) return last_result;

    const u64 archive_path=ctx.program_handle;
    stage="PXI program-content archive";
    last_result=FSPXI_OpenArchive(ctx.service,&ctx.archive,ARCHIVE_SAVEDATA_AND_CONTENT2,
                                  (FS_Path){PATH_BINARY,sizeof(archive_path),&archive_path});
    if (R_FAILED(last_result)) { pxi_romfs_close(); return last_result; }
    ctx.archive_open=true;

    const u32 file_path[3]={0};
    stage="PXI browser RomFS file";
    last_result=FSPXI_OpenFile(ctx.service,&ctx.file,ctx.archive,
                              (FS_Path){PATH_BINARY,sizeof(file_path),file_path},FS_OPEN_READ,0);
    if (R_FAILED(last_result)) { pxi_romfs_close(); return last_result; }
    ctx.file_open=true;

    stage="PXI IVFC header";
    IvfcHeader ivfc={0};
    if (!read_exact(0,&ivfc,sizeof(ivfc))) { pxi_romfs_close(); return last_result; }
    if (ivfc.magic==0x43465649) {
        if (ivfc.type!=0x00010000 || ivfc.header_size!=0x5C ||
            ivfc.level[2].block_size_log2>=32) {
            last_result=MAKERESULT(RL_FATAL,RS_INVALIDSTATE,RM_ROMFS,RD_INVALID_SIZE);
            pxi_romfs_close(); return last_result;
        }
        u64 block=UINT64_C(1)<<ivfc.level[2].block_size_log2;
        u64 after_master=UINT64_C(0x60)+ivfc.master_hash_size;
        if (after_master>UINT64_MAX-(block-1)) {
            last_result=MAKERESULT(RL_FATAL,RS_INVALIDSTATE,RM_ROMFS,RD_INVALID_SIZE);
            pxi_romfs_close(); return last_result;
        }
        ctx.base_offset=(after_master+(block-1))&~(block-1);
    }

    stage="PXI RomFS header";
    if (!read_romfs_exact(0,&ctx.header,sizeof(ctx.header)) ||
        ctx.header.headerSize!=sizeof(ctx.header) ||
        !ctx.header.dirTableSize || !ctx.header.fileTableSize ||
        ctx.header.dirTableSize>MAX_TABLE_SIZE || ctx.header.fileTableSize>MAX_TABLE_SIZE) {
        if (R_SUCCEEDED(last_result)) last_result=MAKERESULT(RL_FATAL,RS_INVALIDSTATE,RM_ROMFS,RD_INVALID_SIZE);
        pxi_romfs_close(); return last_result;
    }
    ctx.dirs=malloc(ctx.header.dirTableSize);
    ctx.files=malloc(ctx.header.fileTableSize);
    if (!ctx.dirs || !ctx.files) {
        last_result=MAKERESULT(RL_FATAL,RS_OUTOFRESOURCE,RM_ROMFS,RD_OUT_OF_MEMORY);
        pxi_romfs_close(); return last_result;
    }
    stage="PXI RomFS tables";
    if (!read_romfs_exact(ctx.header.dirTableOff,ctx.dirs,ctx.header.dirTableSize) ||
        !read_romfs_exact(ctx.header.fileTableOff,ctx.files,ctx.header.fileTableSize) || !dir_at(0)) {
        if (R_SUCCEEDED(last_result)) last_result=MAKERESULT(RL_FATAL,RS_INVALIDSTATE,RM_ROMFS,RD_NOT_FOUND);
        pxi_romfs_close(); return last_result;
    }
    stage="ready";
    return 0;
}

int pxi_romfs_read_file(const char *path,u8 **data,size_t *size) {
    if (!ctx.file_open || !path || !data || !size) return -1;
    while (*path=='/') path++;
    u32 parent=0;
    const char *part=path;
    for (;;) {
        const char *slash=strchr(part,'/');
        if (!slash) break;
        if (slash==part) { part++; continue; }
        parent=child_dir(parent,part,(size_t)(slash-part));
        if (parent==ROMFS_NONE) return -1;
        part=slash+1;
    }
    if (!*part) return -1;
    romfs_file *entry=child_file(parent,part,strlen(part));
    if (!entry || entry->dataSize>SIZE_MAX) return -1;
    size_t length=(size_t)entry->dataSize;
    u8 *buffer=malloc(length ? length : 1);
    if (!buffer) return -2;
    if (length && (length>UINT32_MAX || !read_romfs_exact((u64)ctx.header.fileDataOff+entry->dataOff,buffer,(u32)length))) {
        free(buffer); return -1;
    }
    *data=buffer; *size=length;
    return 0;
}

Result pxi_romfs_last_result(void) { return last_result; }
const char *pxi_romfs_stage(void) { return stage; }

void pxi_romfs_close(void) {
    free(ctx.files); free(ctx.dirs);
    if (ctx.file_open) FSPXI_CloseFile(ctx.service,ctx.file);
    if (ctx.archive_open) FSPXI_CloseArchive(ctx.service,ctx.archive);
    if (ctx.service) svcCloseHandle(ctx.service);
    if (ctx.program_handle) LOADER_UnregisterProgram(ctx.program_handle);
    if (ctx.loader_active) loaderExit();
    memset(&ctx,0,sizeof(ctx));
}

