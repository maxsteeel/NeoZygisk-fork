#include <sys/sysmacros.h>  // For makedev
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>          // For qsort
#include <cstring>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "module.hpp"
#include "zygisk.hpp"

std::vector<mount_info> check_zygote_traces(uint32_t info_flags) {
    std::vector<mount_info> traces;

    const char* mount_source_name = nullptr;
    bool is_kernelsu = false;

    // Check flags early to avoid reading the file if we don't need to
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
    if (fd < 0) {
        PLOGE("open /proc/self/mountinfo");
        return traces;
    }

    std::vector<char> buf;
    buf.resize(1024 * 128); // 128KB is usually enough, avoids vector reallocations
    size_t total_read = 0;

    while (true) {
        if (total_read == buf.size()) buf.resize(buf.size() * 2);
        ssize_t bytes_read = read(fd, buf.data() + total_read, buf.size() - total_read);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }

    if (total_read == 0) return traces;
    buf[total_read] = '\0'; // Null terminate

    std::vector<mount_info> all_mounts;
    all_mounts.reserve(256); // Pre-allocate to avoid reallocations
    char ksu_module_source[256] = {0};

    char* p = buf.data();
    char* end = buf.data() + total_read;

    while (p < end) {
        // Fast line splitting using memchr
        char* line_end = static_cast<char*>(memchr(p, '\n', end - p));
        if (!line_end) line_end = end;
        *line_end = '\0'; // Null terminate

        char* separator = strstr(p, " - ");
        if (separator) {
            mount_info info = {};
            unsigned int maj = 0, min = 0;

            if (sscanf(p, "%u %u %u:%u %127s %255s", &info.id, &info.parent, &maj, &min, info.root, info.target) >= 6) {
                info.device = makedev(maj, min);

                if (sscanf(separator + 3, "%63s %255s", info.type, info.source) >= 2) {

                    if (is_kernelsu && strcmp(info.target, "/data/adb/modules") == 0 &&
                        strncmp(info.source, "/dev/block/loop", 15) == 0) {
                        strlcpy(ksu_module_source, info.source, sizeof(ksu_module_source));
                        LOGV("detected KernelSU loop device module source: %s", ksu_module_source);
                    }

                    all_mounts.push_back(info);
                }
            }
        }
        p = line_end + 1;
    }

    traces.reserve(all_mounts.size());

    for (const auto& info : all_mounts) {
        bool should_unmount = false;

        if (strncmp(info.root, "/adb/modules", 12) == 0) {
            should_unmount = true;
        } else if (strncmp(info.target, "/data/adb/modules", 17) == 0) {
            should_unmount = true;
        } else if (strcmp(info.source, mount_source_name) == 0) {
            should_unmount = true;
        } else if (ksu_module_source[0] != '\0' && strcmp(info.source, ksu_module_source) == 0) {
            should_unmount = true;
        }

        if (should_unmount) {
            traces.push_back(info);
        }
    }

    if (traces.empty()) {
        LOGV("no relevant mount points found to unmount.");
        return traces;
    }

    qsort(traces.data(), traces.size(), sizeof(mount_info), +[](const void* a, const void* b) -> int {
        const auto* m1 = static_cast<const mount_info*>(a);
        const auto* m2 = static_cast<const mount_info*>(b);
        if (m1->id > m2->id) return -1;
        if (m1->id < m2->id) return 1;
        return 0;
    });

    LOGV("found %zu mounting traces in zygote.", traces.size());
    return traces;
}
