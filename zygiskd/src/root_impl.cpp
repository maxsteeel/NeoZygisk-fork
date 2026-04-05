#include "root_impl.hpp"

#include <mutex>
#include <optional>
#include "logging.hpp"

#include "root_impl/apatch.hpp"
#include "root_impl/kernelsu.hpp"
#include "root_impl/magisk.hpp"

namespace root_impl {

static std::optional<RootImpl> ROOT_IMPL;
static std::once_flag setup_flag;

static RootImpl detect_root() {
    auto apatch_version = apatch::detect_version();
    auto ksu_version = kernelsu::detect_version();
    auto magisk_version = magisk::detect_version();

    int detection_count = (apatch_version.has_value() ? 1 : 0) +
                          (ksu_version.has_value() ? 1 : 0) +
                          (magisk_version.has_value() ? 1 : 0);

    if (detection_count > 1) {
        return RootImpl::Multiple;
    }

    if (apatch_version.has_value()) {
        return apatch_version.value() == apatch::Version::Supported ? RootImpl::APatch : RootImpl::TooOld;
    }
    if (ksu_version.has_value()) {
        return ksu_version.value() == kernelsu::Version::Supported ? RootImpl::KernelSU : RootImpl::TooOld;
    }
    if (magisk_version.has_value()) {
        return magisk_version.value() == magisk::Version::Supported ? RootImpl::Magisk : RootImpl::TooOld;
    }

    return RootImpl::None;
}

void setup() {
    std::call_once(setup_flag, []() {
        ROOT_IMPL = detect_root();
    });
}

RootImpl get() {
    if (!ROOT_IMPL.has_value()) {
        LOGF("root_impl::setup() must be called before get()");
    }
    return ROOT_IMPL.value();
}

bool uid_granted_root(int32_t uid) {
    switch (get()) {
        case RootImpl::APatch: return apatch::uid_granted_root(uid);
        case RootImpl::KernelSU: return kernelsu::uid_granted_root(uid);
        case RootImpl::Magisk: return magisk::uid_granted_root(uid);
        default: return false;
    }
}

bool uid_should_umount(int32_t uid) {
    switch (get()) {
        case RootImpl::APatch: return apatch::uid_should_umount(uid);
        case RootImpl::KernelSU: return kernelsu::uid_should_umount(uid);
        case RootImpl::Magisk: return magisk::uid_should_umount(uid);
        default: return false;
    }
}

bool uid_is_manager(int32_t uid) {
    switch (get()) {
        case RootImpl::APatch: return apatch::uid_is_manager(uid);
        case RootImpl::KernelSU: return kernelsu::uid_is_manager(uid);
        case RootImpl::Magisk: return magisk::uid_is_manager(uid);
        default: return false;
    }
}

bool uid_is_manager(int32_t uid, int64_t now_ms) {
    switch (get()) {
        case RootImpl::APatch: return apatch::uid_is_manager(uid, now_ms);
        case RootImpl::KernelSU: return kernelsu::uid_is_manager(uid, now_ms);
        default: return false;
    }
}

void refresh_cache() {
    switch (get()) {
        case RootImpl::APatch: apatch::refresh_cache(); break;
        case RootImpl::Magisk: magisk::refresh_cache(); break;
        default: break;
    }
}

} // namespace root_impl
