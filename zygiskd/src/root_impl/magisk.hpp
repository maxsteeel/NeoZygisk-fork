#pragma once
#include <optional>
#include <cstdint>

namespace magisk {
    enum class Version { Supported, TooOld };
    std::optional<Version> detect_version();
    bool uid_granted_root(int32_t uid);
    bool uid_should_umount(int32_t uid);
    bool uid_is_manager(int32_t uid);
}
