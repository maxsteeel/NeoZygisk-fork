#include <fcntl.h>
#include <algorithm>
#include <string_view>

#include "daemon.hpp"
#include "logging.hpp"
#include "module.hpp"

static bool starts_with(std::string_view str, std::string_view prefix) {
    return str.starts_with(prefix);
}

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

    std::string kernel_su_module_source;
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

        if (sscanf(line, "%d %d %*s %511s %511s", &info.id, &info.parent, root_buf, target_buf) == 4) {
            info.root = root_buf;
            info.target = target_buf;
        }

        if (sscanf(separator + 3, "%127s %511s", type_buf, source_buf) == 2) {
            info.type = type_buf;
            info.source = source_buf;
        }

        info.raw_info = line;

        if (is_kernelsu && info.target == "/data/adb/modules" && starts_with(info.source, "/dev/block/loop")) {
            kernel_su_module_source = info.source;
        }

        const bool should_unmount =
            (strstr(line, "/adb/") != nullptr) || 
            (info.source == std::string(mount_source_name)) ||
            (!kernel_su_module_source.empty() && info.source == kernel_su_module_source);

        if (should_unmount) {
            traces.push_back(std::move(info));
        }

        line = strtok_r(nullptr, "\n", &saveptr);
    }

    if (traces.empty()) return traces;

    std::sort(traces.begin(), traces.end(),
              [](const mount_info& a, const mount_info& b) { return a.id > b.id; });

    LOGV("found %zu mounting traces to revert.", traces.size());
    return traces;
}
