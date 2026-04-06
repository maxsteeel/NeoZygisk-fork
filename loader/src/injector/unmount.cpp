#include <fcntl.h>
#include <algorithm>
#include <string_view>
#include <cstring>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "module.hpp"

// We need an extended struct to hold fs_opt during parsing
struct parsed_mount {
    mount_info info;
    char fs_opt[1024];
};

std::vector<mount_info> check_zygote_traces(uint32_t info_flags) {
    std::vector<mount_info> traces;

    if (!(info_flags & (PROCESS_ROOT_IS_APATCH | PROCESS_ROOT_IS_KSU | PROCESS_ROOT_IS_MAGISK))) {
        LOGE("Could not determine root implementation, aborting unmount.");
        return traces;
    }

    UniqueFd fd(open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return traces;

    std::vector<char> buf;
    buf.resize(1024 * 128);
    size_t total_read = 0;

    while (true) {
        if (total_read == buf.size()) buf.resize(buf.size() * 2);
        ssize_t bytes_read = read(fd, buf.data() + total_read, buf.size() - total_read);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }

    if (total_read == 0) return traces;
    buf[total_read] = '\0';

    std::vector<parsed_mount> all_mounts;
    char root_loop_device[256] = {0};

    // Parse all mounts
    char* p = buf.data();
    char* end = buf.data() + total_read;

    while (p < end) {
        char* line_end = static_cast<char*>(memchr(p, '\n', end - p));
        if (!line_end) line_end = end;
        *line_end = '\0';

        char* separator = strstr(p, " - ");
        if (separator) {
            parsed_mount pm = {};
            if (sscanf(p, "%u %u %*s %127s %255s", &pm.info.id, &pm.info.parent, pm.info.root, pm.info.target) >= 4) {
                if (sscanf(separator + 3, "%63s %255s %1023[^\n]", pm.info.type, pm.info.source, pm.fs_opt) >= 2) {

                    // Track the exact loop device used by KSU/APatch for its modules
                    if (strncmp(pm.info.source, "/dev/block/loop", 15) == 0 &&
                        (strstr(pm.info.target, "/data/adb/") || strstr(pm.info.target, "/ksu/") || strstr(pm.info.target, "/apatch/"))) {
                        strlcpy(root_loop_device, pm.info.source, sizeof(root_loop_device));
                    }

                    all_mounts.push_back(pm);
                }
            }
        }
        p = line_end + 1;
    }

    // Execute unmount rules
    for (const auto& pm : all_mounts) {
        bool should_unmount = false;

        // Catch Known Root Sources
        if (strcmp(pm.info.source, "magisk") == 0   ||
            strcmp(pm.info.source, "KSU") == 0      ||
            strcmp(pm.info.source, "APatch") == 0   ||
            strcmp(pm.info.source, "worker") == 0   ||
            strncmp(pm.info.source, "ksu_", 4) == 0 ||
            strcmp(pm.info.source, "none") == 0) {  // some mounts are hidden using mount source "none"
            should_unmount = true;
        }

        // Catch Suspicious Paths
        if (!should_unmount) {
            if (strstr(pm.info.root, "/adb/") || strstr(pm.info.root, "/ksu/")        ||
                strstr(pm.info.root, "/magisk/") || strstr(pm.info.root, "/apatch/")  ||
                strstr(pm.info.target, "/data/adb/") || strstr(pm.info.target, "/ksu/")) {
                should_unmount = true;
            }
        }

        // Search module image bind-mounts
        if (!should_unmount && root_loop_device[0] != '\0') {
            if (strcmp(pm.info.source, root_loop_device) == 0) {
                should_unmount = true;
            }
        }

        if (!should_unmount) {
            bool is_system_target = (strncmp(pm.info.target, "/system", 7) == 0      ||
                                     strncmp(pm.info.target, "/system_ext", 11) == 0 ||
                                     strncmp(pm.info.target, "/vendor", 7) == 0      ||
                                     strncmp(pm.info.target, "/product", 8) == 0     ||
                                     strncmp(pm.info.target, "/etc", 4) == 0         ||
                                     strncmp(pm.info.target, "/odm", 4) == 0);

            if (is_system_target) {
                // If a module mounted an overlay or a tmpfs over a system file, nuke it.
                if (strcmp(pm.info.type, "overlay") == 0 || strcmp(pm.info.type, "tmpfs") == 0) {
                    should_unmount = true;
                }
            }
        }

        if (should_unmount) {
            traces.push_back(pm.info);
        }
    }

    if (traces.empty()) return traces;

    // Sort by ID descending to unmount children before parents
    qsort(traces.data(), traces.size(), sizeof(mount_info), +[](const void* a, const void* b) -> int {
        const auto* m1 = static_cast<const mount_info*>(a);
        const auto* m2 = static_cast<const mount_info*>(b);

        if (m1->id > m2->id) return -1;
        if (m1->id < m2->id) return 1;
        return 0;
    });

    LOGV("found %zu mounting traces to revert.", traces.size());
    return traces;
}
