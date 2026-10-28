#pragma once

#include <3ds/types.h>

Result pxi_romfs_open(u64 title_id);
void pxi_romfs_close(void);
int pxi_romfs_read_file(const char *path, u8 **data, size_t *size);
Result pxi_romfs_last_result(void);
const char *pxi_romfs_stage(void);

