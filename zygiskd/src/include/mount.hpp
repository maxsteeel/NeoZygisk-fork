#pragma once

#include <sys/types.h>
#include <unistd.h>
#include "daemon.hpp"
#include "utils.hpp"

namespace zygisk_mount { // Renamed from mount to zygisk_mount

// Represents the two types of mount namespaces the daemon manages.
// MountNamespace enum is already defined in zygiskd::MountNamespace in daemon.hpp

// Switches the current thread into the mount namespace of a given process.
bool switch_mount_namespace(pid_t pid);

// Manages the lifecycle and caching of mount namespace file descriptors.
class MountNamespaceManager {
public:
    MountNamespaceManager();
    ~MountNamespaceManager() = default;

    // Gets the cached file descriptor for a given namespace type, if it exists.
    int get_namespace_fd(zygiskd::MountNamespace namespace_type) const;

    // Caches a handle to a specific mount namespace (`Clean` or `Root`).
    int save_mount_namespace(pid_t pid, zygiskd::MountNamespace namespace_type);

private:
    // Unmounts filesystems related to root solutions from the current mount namespace.
    static bool clean_mount_namespace();

    mutable SpinMutex mtx_;
    int clean_mnt_ns_fd_;
    int root_mnt_ns_fd_;
};

} // namespace zygisk_mount
