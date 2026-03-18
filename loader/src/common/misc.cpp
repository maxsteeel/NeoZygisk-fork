#include "misc.hpp"

#include <cstdint>
#include <string_view>
#include <sys/utsname.h>

#include "logging.hpp"

/**
 * @brief Parses an integer from a string_view.
 *
 * This function uses a highly optimized manual parser.
 * It adheres to the original signature, returning an integer value.
 *
 * @param s The string_view to parse.
 * @return The parsed integer on success. Returns -1 on failure.
 */
int parse_int(std::string_view s) {
    const char* p = s.data();
    size_t len = s.size();

    if (unlikely(len == 0)) return -1;

    bool neg = false;
    if (*p == '-') {
        neg = true;
        p++;
        len--;
        if (unlikely(len == 0)) return -1;
    }

    // Max length for a 32-bit integer (including sign) is 11,
    // so max digits is 10.
    if (unlikely(len > 10)) return -1;

    uint64_t val = 0;
    const char* const end = p + len;
    while (p != end) {
        uint32_t digit = static_cast<uint32_t>(*p++) - '0';
        if (unlikely(digit > 9)) return -1;
        val = val * 10 + digit;
    }

    if (neg) {
        if (unlikely(val > 2147483648ULL)) return -1;
        return -static_cast<int>(val);
    } else {
        if (unlikely(val > 2147483647ULL)) return -1;
        return static_cast<int>(val);
    }
}

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
