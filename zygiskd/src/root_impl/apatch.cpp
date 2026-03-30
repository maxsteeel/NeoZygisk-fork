#include "apatch.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <mutex>
#include <memory>
#include <atomic>
#include <algorithm>

#include "constants.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "daemon.hpp" // For UniqueFd

namespace apatch {

struct ConfigData {
    struct timespec mtim;
    IntList packages; // bit-packed: 0-29 uid, 30 allow, 31 exclude
};

static const char* CONFIG_FILE = "/data/adb/ap/package_config";

static std::mutex writer_mutex;
static std::atomic<const ConfigData*> config_cache_rcu{nullptr};
static std::atomic<int64_t> last_stat_time_ms{0};

std::optional<Version> detect_version() {
    static std::optional<Version> cached_version = std::nullopt;
    static std::once_flag flag;

    std::call_once(flag, []() {
        auto output = utils::exec_command({"apd", "-V"});
        if (!output) return;

        const char* p = output.value().c_str();
        while (*p && !isdigit(static_cast<unsigned char>(*p))) p++;

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

static const ConfigData* get_config() {
    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    int64_t now_ms = now_ts.tv_sec * 1000LL + now_ts.tv_nsec / 1000000LL;

    auto cached_data = config_cache_rcu.load(std::memory_order_acquire);

    // VDSO Rate-Limiting: Check max once every 500ms
    if (cached_data && now_ms - last_stat_time_ms.load(std::memory_order_relaxed) < 500) {
        return cached_data;
    }

    struct stat st;
    if (stat(CONFIG_FILE, &st) != 0) {
        return nullptr;
    }

    last_stat_time_ms.store(now_ms, std::memory_order_relaxed);

    if (cached_data) {
        if (cached_data->mtim.tv_sec == st.st_mtim.tv_sec &&
            cached_data->mtim.tv_nsec == st.st_mtim.tv_nsec) {
            return cached_data;
        }
    }

    std::lock_guard<std::mutex> lock(writer_mutex);

    // Double check after acquiring the lock
    cached_data = config_cache_rcu.load(std::memory_order_acquire);
    if (cached_data && cached_data->mtim.tv_sec == st.st_mtim.tv_sec &&
        cached_data->mtim.tv_nsec == st.st_mtim.tv_nsec) {
        return cached_data;
    }

    UniqueFd fd(open(CONFIG_FILE, O_RDONLY | O_CLOEXEC));
    if (fd < 0) return nullptr;

    // Allocate raw pointer to avoid NDK shared_ptr atomic limitation
    ConfigData* new_config = new ConfigData();
    new_config->mtim = st.st_mtim;

    if (st.st_size > 0) {
        void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map != MAP_FAILED) {
            const char* start = static_cast<const char*>(map);
            const char* end = start + st.st_size;

            // Count newlines to preallocate vector and avoid reallocations
            [[maybe_unused]] size_t lines = 0;
            const char* p_count = start;
            while ((p_count = static_cast<const char*>(memchr(p_count, '\n', end - p_count)))) {
                lines++;
                p_count++;
            }

            // Skip header: find first newline
            const char* p = static_cast<const char*>(memchr(start, '\n', end - start));
            if (p) {
                p++; // move past header newline

                // Parse backwards from each newline for zero-allocation performance
                while (p < end) {
                    const char* line_end = static_cast<const char*>(memchr(p, '\n', end - p));
                    if (!line_end) line_end = end;

                    if (line_end > p) {
                        const char* cursor = line_end - 1;

                        // Extract uid (last component)
                        while (cursor >= p && *cursor != ',') cursor--;
                        if (cursor >= p) {
                            int uid_val = fast_atoi(cursor + 1);

                            // Extract allow
                            cursor--;
                            while (cursor >= p && *cursor != ',') cursor--;
                            if (cursor >= p) {
                                int allow_val = fast_atoi(cursor + 1);

                                // Extract exclude
                                cursor--;
                                while (cursor >= p && *cursor != ',') cursor--;
                                if (cursor >= p) {
                                    int exclude_val = fast_atoi(cursor + 1);

                                    uint32_t packed = (static_cast<uint32_t>(uid_val) & 0x3FFFFFFF);
                                    if (allow_val == 1) packed |= (1U << 30);
                                    if (exclude_val == 1) packed |= (1U << 31);
                                    new_config->packages.push_back(packed);
                                }
                            }
                        }
                    }
                    p = line_end + 1;
                }
            }
            munmap(map, st.st_size);
        }
    }

    auto cmp_apatch_pkg = [](const void* a, const void* b) -> int {
        uint32_t v1 = *(const uint32_t*)a & 0x3FFFFFFF;
        uint32_t v2 = *(const uint32_t*)b & 0x3FFFFFFF;
        if (v1 < v2) return -1;
        if (v1 > v2) return 1;
        return 0;
    };

    if (new_config->packages.size > 0) {
        qsort(new_config->packages.data, new_config->packages.size, sizeof(uint32_t), cmp_apatch_pkg);
    }

    // Store new configuration
    (void)config_cache_rcu.exchange(new_config, std::memory_order_release);

    // Defer deletion of old_config. In a strict daemon environment with extremely
    // rare updates, leaking a few KB is safer than risking a Use-After-Free.
    // However, if we know threads finish quickly, we could theoretically delete old_config here.
    // For maximum safety without a hazard pointer framework, we leave it orphaned.

    return new_config;
}

static uint32_t find_package(const ConfigData* config, int32_t uid) {
    if (!config || config->packages.size == 0) return 0;

    uint32_t target = static_cast<uint32_t>(uid) & 0x3FFFFFFF;
    auto cmp_apatch_search = [](const void* key, const void* element) -> int {
        uint32_t k = *(const uint32_t*)key;
        uint32_t e = *(const uint32_t*)element & 0x3FFFFFFF;
        if (k < e) return -1;
        if (k > e) return 1;
        return 0;
    };

    void* result = bsearch(&target, config->packages.data, config->packages.size, sizeof(uint32_t), cmp_apatch_search);

    if (result) {
        return *(static_cast<uint32_t*>(result));
    }
    return 0;
}

bool uid_granted_root(int32_t uid) {
    auto config = get_config();
    if (!config) return false;
    uint32_t pkg = find_package(config, uid);
    return (pkg & (1U << 30)) != 0;
}

bool uid_should_umount(int32_t uid) {
    auto config = get_config();
    if (!config) return false;
    uint32_t pkg = find_package(config, uid);
    return (pkg & (1U << 31)) != 0;
}

bool uid_is_manager(int32_t uid, int64_t now_ms) {
    static std::atomic<int32_t> g_manager_uid{-1};
    static std::atomic<int64_t> last_manager_stat_time_ms{0};
    int32_t manager_uid = g_manager_uid.load(std::memory_order_relaxed);

    if (manager_uid <= -1 || now_ms - last_manager_stat_time_ms.load(std::memory_order_relaxed) > 1000) {
        struct stat st;
        if (stat("/data/user_de/0/me.bmax.apatch", &st) == 0) {
            manager_uid = static_cast<int32_t>(st.st_uid);
        } else {
            manager_uid = -2; 
        }
        g_manager_uid.store(manager_uid, std::memory_order_relaxed);
        last_manager_stat_time_ms.store(now_ms, std::memory_order_relaxed);
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
