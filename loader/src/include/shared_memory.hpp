#pragma once

#include <stdint.h>

// Constants
#define MAX_MODULES 32
#define MAX_DENYLIST 1024
#define MAX_PATH_LEN 256
#define MAX_PROCESS_LEN 128

// Magic number ("NEO")
#define ZYGISK_SHARED_MAGIC 0x4E454F00

// status flags
#define PROCESS_IS_FIRST_STARTED  (1 << 0)
#define PROCESS_IS_MANAGER        (1 << 1)
#define PROCESS_ON_DENYLIST       (1 << 2)
#define PROCESS_DO_INJECT         (1 << 3)

namespace zygisk {

#pragma pack(push, 1)

struct SharedModule {
    char path[MAX_PATH_LEN];
};

struct SharedDenyEntry {
    char process[MAX_PROCESS_LEN];
};

struct ZygiskSharedData {
    uint32_t magic;
    
    // modules list
    uint32_t module_count;
    SharedModule modules[MAX_MODULES];
    
    // denied processes list
    uint32_t deny_count;
    SharedDenyEntry deny_list[MAX_DENYLIST];
    
    // manager name (ej. com.topjohnwu.magisk o me.weishu.kernelsu)
    char manager_app[MAX_PROCESS_LEN];
};

#pragma pack(pop)

} // namespace zygisk
