#include <sys/sysmacros.h>  // For makedev
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "daemon.hpp"
#include "module.hpp"
#include "zygisk.hpp"

MountInfoList check_zygote_traces(uint32_t info_flags, bool* abort) {
    MountInfoList traces;
    if (abort) *abort = false; // NeoZygisk never aborts.

    const char* mount_source_name = nullptr;
    bool is_kernelsu = false;

    if (info_flags & PROCESS_ROOT_IS_APATCH) mount_source_name = "APatch";
    else if (info_flags & PROCESS_ROOT_IS_KSU) {
        mount_source_name = "KSU";
        is_kernelsu = true;
    }
    else if (info_flags & PROCESS_ROOT_IS_MAGISK) mount_source_name = "magisk";
    else return traces;

    UniqueFd fd(open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return traces;

    size_t capacity = 512 * 1024;
    char* buf = static_cast<char*>(mmap(nullptr, capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (buf == MAP_FAILED) return traces;

    size_t total_read = 0;
    while (total_read < capacity - 1) {
        ssize_t bytes = read(fd, buf + total_read, capacity - total_read - 1);
        if (bytes <= 0) {
            if (bytes < 0 && errno == EINTR) continue;
            break;
        }
        total_read += bytes;
    }
    buf[total_read] = '\0'; // Null terminate

    char ksu_module_source[256] = {0};
    char* p = buf;
    char* end = buf + total_read;

    while (p < end) {
        char* line_end = static_cast<char*>(__builtin_memchr(p, '\n', end - p));
        if (!line_end) line_end = end;
        *line_end = '\0';

        char* separator = __builtin_strstr(p, " - ");
        if (separator) {
            mount_info info = {};
            unsigned int maj = 0, min = 0;

            if (sscanf(p, "%u %u %u:%u %127s %255s", &info.id, &info.parent, &maj, &min, info.root, info.target) >= 6) {
                info.device = makedev(maj, min);

                if (sscanf(separator + 3, "%63s %255s", info.type, info.source) >= 2) {
                    
                    if (is_kernelsu && __builtin_strcmp(info.target, "/data/adb/modules") == 0 &&
                        __builtin_strncmp(info.source, "/dev/block/loop", 15) == 0) {
                        size_t src_len = __builtin_strlen(info.source);
                        if (src_len > 255) src_len = 255;
                        __builtin_memcpy(ksu_module_source, info.source, src_len);
                        ksu_module_source[src_len] = '\0';
                    }

                    if ((__builtin_strncmp(info.root, "/adb/modules", 12) == 0) ||
                        (__builtin_strncmp(info.target, "/data/adb/modules", 17) == 0) ||
                        (__builtin_strcmp(info.source, mount_source_name) == 0) ||
                        (ksu_module_source[0] != '\0' && __builtin_strcmp(info.source, ksu_module_source) == 0)) {
                        
                        traces.push_back(info);
                    }
                }
            }
        }
        p = line_end + 1;
    }
    munmap(buf, capacity);

    if (traces.size > 1) {
        size_t half = traces.size / 2;
        size_t max_idx = traces.size - 1;
        for (size_t i = 0; i < half; i++) {
            mount_info temp = traces.data[i];
            traces.data[i] = traces.data[max_idx - i];
            traces.data[max_idx - i] = temp;
        }
    }

    return traces;
}
