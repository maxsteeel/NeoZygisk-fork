#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "root_impl.hpp"
#include "constants.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "daemon.hpp"

namespace apatch {

struct ConfigData {
    struct timespec mtim = {0, -1};
    IntList packages; // bit-packed: 0-29 uid, 30 allow, 31 exclude
};

static const char* CONFIG_FILE = "/data/adb/ap/package_config";

static ConfigData g_config;
static RWLock g_config_mutex;
static _Atomic(int64_t) last_stat_time_ms = 0;

// Macro to extract only the UID from the packed integer
#define GET_UID(packed) ((packed) & 0x3FFFFFFF)

static void parse_and_sort_config(int fd, size_t size, ConfigData& config) {
    if (size == 0) return;

    void* map = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) return;

    const char* start = static_cast<const char*>(map);
    const char* end = start + size;

    // Skip header: find first newline
    const char* p = static_cast<const char*>(memchr(start, '\n', end - start));
    if (p) {
        p++; // move past header newline

        while (p < end) {
            const char* line_end = static_cast<const char*>(memchr(p, '\n', end - p));
            if (!line_end) line_end = end;

            if (line_end > p) {
                const char* cursor = line_end - 1;
                
                // Safe Reverse Parsing
                int commas_found = 0;
                const char* exclude_start = nullptr;
                const char* allow_start = nullptr;
                const char* uid_start = nullptr;

                while (cursor >= p) {
                    if (*cursor == ',') {
                        commas_found++;
                        if (commas_found == 1) uid_start = cursor + 1;
                        else if (commas_found == 2) allow_start = cursor + 1;
                        else if (commas_found == 3) {
                            exclude_start = cursor + 1;
                            break; // Stop looking, we have our 3 values
                        }
                    }
                    cursor--;
                }

                // Only process if we found all exactly 3 fields (pkg, uid, allow, exclude)
                if (commas_found >= 3 && uid_start && allow_start && exclude_start) {
                    int uid_val = fast_atoi(uid_start);
                    int allow_val = fast_atoi(allow_start);
                    int exclude_val = fast_atoi(exclude_start);

                    uint32_t packed = (static_cast<uint32_t>(uid_val) & 0x3FFFFFFF);
                    if (allow_val == 1) packed |= (1U << 30);
                    if (exclude_val == 1) packed |= (1U << 31);
                    
                    config.packages.push_back(packed);
                }
            }
            p = line_end + 1;
        }
    }
    munmap(map, size);

    if (config.packages.size > 0) {
        // Sort purely by UID, ignoring the higher flag bits
        ::sort(config.packages.data, 
             config.packages.data + config.packages.size, 
             [](const uint32_t a, const uint32_t b) {
                 return GET_UID(a) < GET_UID(b);
             });
        
        // Remove duplicates (keep highest priority if needed, or simply unique)
        size_t unique_count = 1;
        for (size_t i = 1; i < config.packages.size; ++i) {
            if (GET_UID(config.packages.data[i]) != GET_UID(config.packages.data[unique_count - 1])) {
                config.packages.data[unique_count++] = config.packages.data[i];
            }
        }
        config.packages.size = unique_count;
    }
}

Version detect_version() {
    static Version cached_version = Version::Null; 
    static ::once_flag flag = 0;

    ::call_once(flag, []() {
        char buf[256];
        const char* args[] = {"apd", "-V", nullptr};
        auto output = utils::exec_command(args, buf, sizeof(buf));
        if (!output) return;

        const char* p = buf;
        while (*p && (*p < '0' || *p > '9')) p++;

        if (*p) {
            int version = fast_atoi(p);
            if (version >= MIN_APATCH_VERSION) {
                cached_version = Version::Supported;
            } else {
                cached_version = Version::TooOld;
            }
        }
    });

    return cached_version;
}

void refresh_cache() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;

    // Prevent excessive disk stats
    if (now_ms - atomic_load_explicit(&last_stat_time_ms, memory_order_relaxed) < 2000) return;

    struct stat st;
    if (stat(CONFIG_FILE, &st) != 0) return;

    atomic_store_explicit(&last_stat_time_ms, now_ms, memory_order_relaxed);

    // Fast Check (Read Lock)
    {
        SharedMutexGuard read_lock(g_config_mutex);
        if (g_config.mtim.tv_sec == st.st_mtim.tv_sec &&
            g_config.mtim.tv_nsec == st.st_mtim.tv_nsec) {
            return;
        }
    }

    // Slow Update (Write Lock)
    UniqueMutexGuard write_lock(g_config_mutex);

    // Double-check to prevent concurrent rebuilds
    if (g_config.mtim.tv_sec == st.st_mtim.tv_sec &&
        g_config.mtim.tv_nsec == st.st_mtim.tv_nsec) {
        return;
    }

    UniqueFd fd(open(CONFIG_FILE, O_RDONLY | O_CLOEXEC));
    if (fd < 0) return;

    // Safe in-place rebuild. Reusing the old vector buffer is memory efficient
    g_config.packages.clear(); 
    g_config.mtim = st.st_mtim;

    parse_and_sort_config(fd, st.st_size, g_config);
}

static uint32_t find_package(const ConfigData& config, int32_t uid) {
    if (config.packages.size == 0) return 0;

    uint32_t target = static_cast<uint32_t>(uid) & 0x3FFFFFFF;
    
    auto cmp_apatch_search = [](const void* key, const void* element) -> int {
        uint32_t k = *(static_cast<const uint32_t*>(key));
        uint32_t e = GET_UID(*(static_cast<const uint32_t*>(element)));
        if (k < e) return -1;
        if (k > e) return 1;
        return 0;
    };

    void* result = bsearch(&target, config.packages.data, config.packages.size, sizeof(uint32_t), cmp_apatch_search);

    if (result) {
        return *(static_cast<uint32_t*>(result));
    }
    return 0;
}

bool uid_granted_root(int32_t uid) {
    SharedMutexGuard read_lock(g_config_mutex);
    uint32_t pkg = find_package(g_config, uid);
    return (pkg & (1U << 30)) != 0;
}

bool uid_should_umount(int32_t uid) {
    SharedMutexGuard read_lock(g_config_mutex);
    uint32_t pkg = find_package(g_config, uid);
    return (pkg & (1U << 31)) != 0;
}

bool uid_is_manager(int32_t uid, int64_t now_ms) {
    static _Atomic(int32_t) g_manager_uid = -1;
    static _Atomic(int64_t) last_manager_stat_time_ms = 0;
    int32_t manager_uid = atomic_load_explicit(&g_manager_uid, memory_order_relaxed);

    if (manager_uid <= -1 || now_ms - atomic_load_explicit(&last_manager_stat_time_ms, memory_order_relaxed) > 1000) {
        struct stat st;
        if (stat("/data/user_de/0/me.bmax.apatch", &st) == 0) {
            manager_uid = static_cast<int32_t>(st.st_uid);
        } else {
            manager_uid = -2; 
        }
        atomic_store_explicit(&g_manager_uid, manager_uid, memory_order_relaxed);
        atomic_store_explicit(&last_manager_stat_time_ms, now_ms, memory_order_relaxed);
    }
    return manager_uid == uid;
}

bool uid_is_manager(int32_t uid) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
    return uid_is_manager(uid, now_ms);
}

} // namespace apatch
