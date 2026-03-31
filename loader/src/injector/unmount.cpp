#include <fcntl.h>
#include <algorithm>
#include <string_view>
#include <cstring>

#include "daemon.hpp"
#include "logging.hpp"
#include "module.hpp"

std::vector<mount_info> check_zygote_traces(uint32_t info_flags) {
    std::vector<mount_info> traces;

    const char* mount_source_name = nullptr;
    bool is_kernelsu = false;

    if (info_flags & PROCESS_ROOT_IS_APATCH) {
        mount_source_name = "APatch";
    } else if (info_flags & PROCESS_ROOT_IS_KSU) {
        mount_source_name = "KSU";
        is_kernelsu = true;
    } else if (info_flags & PROCESS_ROOT_IS_MAGISK) {
        mount_source_name = "magisk";
    } else {
        LOGE("could not determine root implementation, aborting unmount.");
        return traces;
    }

    UniqueFd fd(open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return traces;

    char buf[65536]; 
    ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);

    if (bytes_read <= 0) return traces;
    buf[bytes_read] = '\0'; 

    if (!strstr(buf, "/adb/") && !strstr(buf, mount_source_name)) {
        LOGV("Fast-Path: No relevant mounts found. Kernel level unmount is active.");
        return traces;
    }

    char kernel_su_module_source[256] = {0};
    char* saveptr = nullptr;
    char* line = strtok_r(buf, "\n", &saveptr);

    while (line != nullptr) {
        char* separator = strstr(line, " - ");
        if (!separator) {
            line = strtok_r(nullptr, "\n", &saveptr);
            continue;
        }

        mount_info info = {};

        if (sscanf(line, "%u %u %*s %127s %255s", &info.id, &info.parent, info.root, info.target) >= 4) {
            if (sscanf(separator + 3, "%63s %255s", info.type, info.source) >= 2) {
                if (is_kernelsu && strcmp(info.target, "/data/adb/modules") == 0 && 
                    strncmp(info.source, "/dev/block/loop", 15) == 0) {
                    strlcpy(kernel_su_module_source, info.source, sizeof(kernel_su_module_source));
                }
                bool should_unmount = (strstr(line, "/adb/") != nullptr) || 
                                     (strcmp(info.source, mount_source_name) == 0) ||
                                     (kernel_su_module_source[0] != '\0' && 
                                      strcmp(info.source, kernel_su_module_source) == 0);

                if (should_unmount) {
                    traces.push_back(info);
                }
            }
        }

        line = strtok_r(nullptr, "\n", &saveptr);
    }

    if (traces.empty()) return traces;

    qsort(traces.data(), traces.size(), sizeof(mount_info), +[](const void* a, const void* b) -> int {
        const auto* m1 = static_cast<const mount_info*>(a);
        const auto* m2 = static_cast<const mount_info*>(b);
        if (m2->id > m1->id) return 1;
        if (m2->id < m1->id) return -1;
        return 0;
    });

    LOGV("found %zu mounting traces to revert.", traces.size());
    return traces;
}
