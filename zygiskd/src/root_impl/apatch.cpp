#include "apatch.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <mutex>
#include <memory>

#include "constants.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace apatch {

struct PackageInfo {
    int32_t uid;
    bool exclude;
    bool allow;
};

static const char* CONFIG_FILE = "/data/adb/ap/package_config";

static std::mutex cache_mutex;
static std::optional<std::pair<time_t, std::shared_ptr<const std::vector<PackageInfo>>>> config_cache;

std::optional<Version> detect_version() {
    UniquePipe pipe(popen("apd -V", "re"));
    if (!pipe) return std::nullopt;

    char buf[128] = {0};
    if (fgets(buf, sizeof(buf), pipe)) {
        char* token = strtok(buf, " \t\r\n");
        if (token) {
            token = strtok(nullptr, " \t\r\n");
            if (token) {
                int version = atoi(token);
                if (version >= MIN_APATCH_VERSION) {
                    return Version::Supported;
                } else {
                    return Version::TooOld;
                }
            }
        }
    }
    return std::nullopt;
}

static std::shared_ptr<const std::vector<PackageInfo>> get_config() {
    struct stat st;
    if (stat(CONFIG_FILE, &st) != 0) {
        return nullptr;
    }

    time_t mtime = st.st_mtime;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (config_cache.has_value()) {
            if (config_cache.value().first == mtime) {
                return config_cache.value().second;
            }
        }
    }

    UniqueFile file(fopen(CONFIG_FILE, "re"));
    if (!file) return nullptr;

    auto result = std::make_shared<std::vector<PackageInfo>>();
    char line[512];

    // Skip header
    if (!fgets(line, sizeof(line), file)) {
        return nullptr;
    }

    while (fgets(line, sizeof(line), file)) {
        int exclude_val, allow_val;
        int32_t uid_val;

        // format: pkg_name,exclude,allow,uid,...
        char pkg_name[256];
        if (sscanf(line, "%255[^,],%d,%d,%d", pkg_name, &exclude_val, &allow_val, &uid_val) >= 4) {
            result->push_back({uid_val, exclude_val == 1, allow_val == 1});
        }
    }

    std::shared_ptr<const std::vector<PackageInfo>> const_result = result;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        config_cache = std::make_pair(mtime, const_result);
    }

    return const_result;
}

bool uid_granted_root(int32_t uid) {
    auto config = get_config();
    if (!config) return false;
    for (const auto& pkg : *config) {
        if (pkg.uid == uid && pkg.allow) return true;
    }
    return false;
}

bool uid_should_umount(int32_t uid) {
    auto config = get_config();
    if (!config) return false;
    for (const auto& pkg : *config) {
        if (pkg.uid == uid && pkg.exclude) return true;
    }
    return false;
}

bool uid_is_manager(int32_t uid) {
    struct stat st;
    if (stat("/data/user_de/0/me.bmax.apatch", &st) == 0) {
        return st.st_uid == static_cast<uid_t>(uid);
    }
    return false;
}

} // namespace apatch
