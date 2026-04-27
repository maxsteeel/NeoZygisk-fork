#include <sys/sysmacros.h>  // For makedev
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "module.hpp"
#include "zygisk.hpp"

MountInfoList check_zygote_traces(uint32_t info_flags, bool* abort) {
    MountInfoList traces;

    const char* mount_source_name = nullptr;
    bool is_kernelsu = false;
    bool is_magisk = info_flags & PROCESS_ROOT_IS_MAGISK;

    // Check flags early to avoid reading the file if we don't need to
    if (info_flags & PROCESS_ROOT_IS_APATCH) {
        mount_source_name = "APatch";
    } else if (info_flags & PROCESS_ROOT_IS_KSU) {
        mount_source_name = "KSU";
        is_kernelsu = true;
    } else if (is_magisk) {
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

    size_t capacity = 1024 * 128; // 128KB iniciales
    char* buf = static_cast<char*>(malloc(capacity));
    if (!buf) return traces;
    
    size_t total_read = 0;

    while (true) {
        if (total_read >= capacity - 1) {
            size_t new_capacity = capacity * 2;
            char* new_buf = static_cast<char*>(malloc(new_capacity));
            if (!new_buf) {
                free(buf);
                return traces; // OOM Fallback
            }
            __builtin_memcpy(new_buf, buf, total_read);
            free(buf);
            buf = new_buf;
            capacity = new_capacity;
        }
        ssize_t bytes_read = read(fd, buf + total_read, capacity - total_read - 1);
        if (bytes_read < 0) {
            if (errno == EINTR) continue; // if interrupted, retry
            PLOGE("Error leyendo /proc/self/mountinfo");
            break; // real error
        } else if (bytes_read == 0) {
            break; // EOF
        }
        total_read += bytes_read;
    }

    if (total_read == 0) {
        free(buf);
        return traces;
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
                        LOGV("detected KernelSU loop device module source: %s", ksu_module_source);
                    }

                    bool should_unmount = false;
                    if (__builtin_strncmp(info.root, "/adb/modules", 12) == 0) {
                        should_unmount = true;
                    } else if (__builtin_strncmp(info.target, "/data/adb/modules", 17) == 0) {
                        should_unmount = true;
                    } else if (__builtin_strcmp(info.source, mount_source_name) == 0) {
                        should_unmount = true;
                    } else if (ksu_module_source[0] != '\0' && __builtin_strcmp(info.source, ksu_module_source) == 0) {
                        should_unmount = true;
                    }

                    if (should_unmount) {
                        if (abort && __builtin_strncmp(info.target, "/product", 8) == 0) {
                            if (__builtin_strncmp(info.target, "/product/bin", 12) != 0 &&
                                (is_magisk || __builtin_strcmp(info.target, "/product") == 0)) {
                                LOGV("abort unmounting zygote due to prohibited target: [%s]", info.target);
                                *abort = true;
                                free(buf);
                                traces.size = 0;
                                return traces;
                            }
                        }

                        if (__builtin_strcmp(info.source, "magisk") == 0) {
                            info.skip_unmount = true;
                        }

                        traces.push_back(info);
                    }
                }
            }
        }
        p = line_end + 1;
    }

    free(buf);

    if (traces.size == 0) {
        if (abort) *abort = true;
        LOGV("no relevant mount points found to unmount.");
        return traces;
    }

    if (traces.size > 1) {
        for (size_t i = 1; i < traces.size; i++) {
            mount_info temp = traces.data[i];
            size_t j = i;
            while (j > 0 && traces.data[j - 1].id < temp.id) {
                traces.data[j] = traces.data[j - 1];
                j--;
            }
            traces.data[j] = temp;
        }
    }

    LOGV("found %zu mounting traces in zygote.", traces.size);
    return traces;
}
