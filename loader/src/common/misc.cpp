#include "misc.hpp"

#include <stdint.h>
#include <sys/utsname.h>
#include <stdlib.h>

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

/**
 * These stubs prevent the linker from pulling in the massive 
 * mangling parser used by libunwind and libc++.
 */

#define KEEP __attribute__((used, visibility("default")))

// ABI guards MUST always be compiled (both Debug and Release) to prevent 
// fatal 0x8 crashes during global static variable initialization.
extern "C" {
    KEEP int __cxa_guard_acquire(long* g) { return !(*(char*)(g)); }
    KEEP void __cxa_guard_release(long* g) { *(char*)g = 1; }
    KEEP void __cxa_guard_abort(long*) {}
    KEEP void __cxa_pure_virtual() { for (;;); }
    KEEP int __gxx_personality_v0(...) { return 0; }
}

namespace __cxxabiv1 {
    extern "C" {
        // This is the main entry point for demangling. 
        // Returning nullptr tells the caller that demangling failed.
        KEEP char* __cxa_demangle(const char*, char*, size_t*, int* status) {
            if (status) *status = -1;
            return nullptr;
        }
    }
}

void* operator new(size_t size) { if (size == 0) size = 1; return malloc(size); }
void* operator new[](size_t size) { if (size == 0) size = 1; return malloc(size); }
void operator delete(void* ptr) noexcept { free(ptr); }
void operator delete(void* ptr, size_t /* size */) noexcept { free(ptr); }
void operator delete[](void* ptr) noexcept { free(ptr); }
void operator delete[](void* ptr, size_t /* size */) noexcept { free(ptr); }

extern "C" {
    // These additional stubs are required to prevent the demangling parser from being linked in.
    KEEP void _ZN12_GLOBAL__N_117itanium_demangle22AbstractManglingParserINS0_14ManglingParserINS_16DefaultAllocatorEEES3_E9parseTypeEv() {}
    KEEP void _ZN12_GLOBAL__N_117itanium_demangle22AbstractManglingParserINS0_14ManglingParserINS_16DefaultAllocatorEEES3_E9parseExprEv() {}
    KEEP void _ZN12_GLOBAL__N_117itanium_demangle22AbstractManglingParserINS0_14ManglingParserINS_16DefaultAllocatorEEES3_E13parseEncodingEb() {}
    KEEP void _ZNSt6__ndk117__assoc_sub_state16__on_zero_sharedEv() {}
    KEEP void _ZNSt6__ndk117__assoc_sub_state9__executeEv() {}
    KEEP void _ZNSt6__ndk117__assoc_sub_state12__make_readyEv() {}
    KEEP void _Unwind_Resume(void*) {}
    KEEP int _Unwind_RaiseException(void*) { return 0; }
    KEEP int _Unwind_DeleteException(void*) { return 0; }
    KEEP void __stub_atexit([[maybe_unused]] void (*func)()) {}
    __attribute__((weak, alias("__stub_atexit"))) int atexit(void (*func)());
}
