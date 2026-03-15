#pragma once

#include <cstdint>

namespace root_impl {

enum class RootImpl {
    None,
    TooOld,
    Multiple,
    APatch,
    KernelSU,
    Magisk,
};

// Performs the root detection and caches the result.
void setup();

// Returns the detected root implementation.
RootImpl get();

// Checks if a given UID has been granted root privileges by the active root manager.
bool uid_granted_root(int32_t uid);

// Checks if mounts should be hidden (unmounted) for a given UID.
bool uid_should_umount(int32_t uid);

// Checks if a given UID belongs to the active root manager application.
bool uid_is_manager(int32_t uid);

} // namespace root_impl
