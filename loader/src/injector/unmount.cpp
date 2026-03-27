#include <fcntl.h>
#include <algorithm>
#include <string_view>
#include <cstring>

#include "daemon.hpp"
#include "logging.hpp"
#include "module.hpp"

std::vector<mount_info> check_zygote_traces(uint32_t /*info_flags*/) {
    std::vector<mount_info> traces;

    UniqueFd fd(open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return traces;

    char buf[65536];
    ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
    if (bytes_read <= 0) return traces;
    buf[bytes_read] = '\0';

    if (!strstr(buf, "/adb/") && !strstr(buf, "magisk") &&
        !strstr(buf, "KSU") && !strstr(buf, "APatch") && !strstr(buf, "ksu_")) {
        LOGV("no relevant mounts found. Environment is clean.");
        return traces;
    }

    char* saveptr = nullptr;
    char* line = strtok_r(buf, "\n", &saveptr);

    while (line != nullptr) {
        char* separator = strstr(line, " - ");
        if (!separator) {
            line = strtok_r(nullptr, "\n", &saveptr);
            continue;
        }

        mount_info info = {};
        char root_buf[512] = {0};
        char target_buf[512] = {0};
        char type_buf[128] = {0};
        char source_buf[512] = {0};
        char options_buf[2048] = {0};

        if (sscanf(line, "%d %d %*s %511s %511s", &info.id, &info.parent, root_buf, target_buf) == 4) {
            info.root = root_buf;
            info.target = target_buf;
        }

        if (sscanf(separator + 3, "%127s %511s %2047s", type_buf, source_buf, options_buf) >= 2) {
            info.type = type_buf;
            info.source = source_buf;
        }

        info.raw_info = line;
        bool should_unmount = false;

        auto contains_root_trace = [](const char* text) {
            return strstr(text, "/adb/") || strstr(text, "magisk") ||
                   strstr(text, "KSU") || strstr(text, "APatch") || strstr(text, "ksu_");
        };

        if (contains_root_trace(root_buf) ||
            contains_root_trace(options_buf) ||
            contains_root_trace(source_buf) ||
            contains_root_trace(target_buf)) should_unmount = true;

        if (should_unmount) {
            traces.push_back(std::move(info));
            LOGV("Trace detected: Target[%s] Root[%s] Type[%s]", target_buf, root_buf, type_buf);
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
