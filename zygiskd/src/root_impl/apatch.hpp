#pragma once
#include <optional>
#include <cstdint>

namespace apatch {
    enum class Version { Supported, TooOld };
    std::optional<Version> detect_version();
    bool uid_granted_root(int32_t uid);
    bool uid_should_umount(int32_t uid);
    bool uid_is_manager(int32_t uid);
    bool uid_is_manager(int32_t uid, int64_t now_ms);
    void refresh_cache();
}
