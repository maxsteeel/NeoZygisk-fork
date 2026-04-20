#include <stddef.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

extern "C" [[gnu::visibility("default")]]
void entry(void* addr, size_t size, void (**init_array)(), size_t init_count) {

    if (init_array != nullptr && init_count > 0) {
        for (size_t i = 0; i < init_count; i++) {
            if (init_array[i] != nullptr) init_array[i]();
        }
    }

    LOGI("zygisk library natively initialized, version %s", ZKSU_VERSION);

    zygiskd::Init();

    if (!zygiskd::PingHeartbeat()) {
        LOGE("zygisk daemon is not running");
        return;
    }

    hook_entry(addr, size);
    send_seccomp_event_if_needed();
}

/**
 * @brief Intercepts calls to __cxa_atexit to prevent registration of exit handlers.
 *
 * This function serves as a local replacement for the __cxa_atexit provided by libc.
 * By providing our own version, the dynamic linker resolves any calls from within our
 * injector library (and its static dependencies) to this function instead of the real one.
 *
 * We silently swallow the registration. Logging or resolving symbols here via dladdr() 
 * during the volatile init_array phase is slow.
 */
extern "C" [[gnu::visibility("default")]] 
int __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
