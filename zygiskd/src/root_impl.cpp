#include "root_impl.hpp"

#include <pthread.h>
#include "logging.hpp"

namespace root_impl {

static RootImpl g_root_impl = RootImpl::None;
static pthread_once_t g_setup_once = PTHREAD_ONCE_INIT;

static void do_detect_root() {
    auto apatch_ver = apatch::detect_version();
    auto ksu_ver = kernelsu::detect_version();
    auto magisk_ver = magisk::detect_version();

    // In C++, booleans cast to 1 or 0 cleanly without ternary overhead
    int detection_count = (apatch_ver != Version::Null) + 
                          (ksu_ver != Version::Null) + 
                          (magisk_ver != Version::Null);

    if (detection_count > 1) {
        g_root_impl = RootImpl::Multiple;
        return;
    }

    if (apatch_ver != Version::Null) {
        g_root_impl = (apatch_ver == Version::Supported) ? RootImpl::APatch : RootImpl::TooOld;
        return;
    }
    if (ksu_ver != Version::Null) {
        g_root_impl = (ksu_ver == Version::Supported) ? RootImpl::KernelSU : RootImpl::TooOld;
        return;
    }
    if (magisk_ver != Version::Null) {
        g_root_impl = (magisk_ver == Version::Supported) ? RootImpl::Magisk : RootImpl::TooOld;
        return;
    }

    g_root_impl = RootImpl::None;
}

void setup() { pthread_once(&g_setup_once, do_detect_root); }

// We trust the daemon initializes this via setup() before the socket accepts clients.
RootImpl get() { return g_root_impl; }

// Hot paths use switch for fast O(1) jump tables.
bool uid_granted_root(int32_t uid) {
    switch (g_root_impl) {
        case RootImpl::APatch:   return apatch::uid_granted_root(uid);
        case RootImpl::KernelSU: return kernelsu::uid_granted_root(uid);
        case RootImpl::Magisk:   return magisk::uid_granted_root(uid);
        default:                 return false;
    }
}

bool uid_should_umount(int32_t uid) {
    switch (g_root_impl) {
        case RootImpl::APatch:   return apatch::uid_should_umount(uid);
        case RootImpl::KernelSU: return kernelsu::uid_should_umount(uid);
        case RootImpl::Magisk:   return magisk::uid_should_umount(uid);
        default:                 return false;
    }
}

bool uid_is_manager(int32_t uid) {
    switch (g_root_impl) {
        case RootImpl::APatch:   return apatch::uid_is_manager(uid);
        case RootImpl::KernelSU: return kernelsu::uid_is_manager(uid);
        case RootImpl::Magisk:   return magisk::uid_is_manager(uid);
        default:                 return false;
    }
}

bool uid_is_manager(int32_t uid, int64_t now_ms) {
    switch (g_root_impl) {
        case RootImpl::APatch:   return apatch::uid_is_manager(uid, now_ms);
        case RootImpl::KernelSU: return kernelsu::uid_is_manager(uid, now_ms);
        default:                 return false;
    }
}

void refresh_cache() {
    switch (g_root_impl) {
        case RootImpl::APatch: apatch::refresh_cache(); break;
        case RootImpl::Magisk: magisk::refresh_cache(); break;
        default:               break;
    }
}

} // namespace root_impl
