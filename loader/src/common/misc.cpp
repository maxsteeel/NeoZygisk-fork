#include "misc.hpp"

#include <cstdint>
#include <string_view>

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
