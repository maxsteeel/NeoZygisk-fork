#include "misc.hpp"

#include <cstdint>
#include <string_view>
#include <sys/utsname.h>

#include "logging.hpp"

/**
 * @brief Checks if the running Linux kernel version is 5.9 or newer.
 *
 * This uses uname to get the release string and parses it optimally.
 * The result is cached for subsequent calls to minimize overhead.
 *
 * @return True if kernel version is >= 5.9, otherwise false.
 */
bool is_kernel_5_9_or_newer() {
    static int result = -1;
    if (likely(result != -1)) return result;

    struct utsname buffer;
    if (unlikely(uname(&buffer) != 0)) {
        result = 0;
        return false;
    }

    int major = 0, minor = 0;
    const char* p = buffer.release;

    // Parse major version
    while (*p >= '0' && *p <= '9') {
        major = major * 10 + (*p - '0');
        p++;
    }

    if (*p == '.') {
        p++;
        // Parse minor version
        while (*p >= '0' && *p <= '9') {
            minor = minor * 10 + (*p - '0');
            p++;
        }
    }

    result = (major > 5 || (major == 5 && minor >= 9));
    return result;
}
