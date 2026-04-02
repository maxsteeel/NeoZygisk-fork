#include "daemon.hpp"

#include <linux/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <atomic>
#include <memory>

#include "logging.hpp"
#include "misc.hpp"
#include "socket_utils.hpp"
#include "constants.hpp"

constants::ZygiskSharedData* g_shared_data = nullptr;

namespace zygiskd {
static char TMP_PATH[256] = {0};
static char MODULE_DIR[256] = {0};
const char* kCPSocketName = (sizeof(void*) == 8) ? "cp64.sock" : "cp32.sock";

void UnmapSharedMemory() {
    if (g_shared_data) {
        munmap(g_shared_data, sizeof(constants::ZygiskSharedData));
        g_shared_data = nullptr;
    }
}

void Init(const char *path, const char *mod_dir) {
    if (path) strlcpy(TMP_PATH, path, sizeof(TMP_PATH));
    if (mod_dir) strlcpy(MODULE_DIR, mod_dir, sizeof(MODULE_DIR));
    setenv("TMP_PATH", TMP_PATH, 0);
    setenv("ZYGISK_MODDIR", MODULE_DIR, 0);
}

const char* GetTmpPath() { return TMP_PATH; }
const char* GetModDir() { return MODULE_DIR; }

int Connect(uint8_t retry) {
    UniqueFd fd(socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;

    memcpy(addr.sun_path + 1, kCPSocketName, strlen(kCPSocketName));
    socklen_t socklen = sizeof(addr.sun_family) + strlen(kCPSocketName) + 1;

    while (retry--) {
        int r = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), socklen);
        if (r == 0) return fd.release();
        if (retry) {
            LOGW("retrying to connect to zygiskd, sleep 1s");
            sleep(1);
        }
    }

    return -1;
}

bool PingHeartbeat() {
    UniqueFd fd = Connect(5);
    if (fd == -1) {
        PLOGE("connecting to zygiskd");
        return false;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::PingHeartbeat);
    return true;
}

uint32_t GetProcessFlags(uid_t uid) {
    if (g_shared_data) {
        // Read version to ensure we aren't reading during a write
        uint32_t version1 = g_shared_data->version.load(std::memory_order_acquire);

        if (version1 % 2 == 0) { // Not currently writing
            size_t index = uid & (constants::SHM_HASH_MAP_SIZE - 1); // uid & 8191
            size_t start_index = index;
            bool found = false;
            uint32_t cached_flags = 0;

            do {
                uint32_t current_uid = g_shared_data->entries[index].uid.load(std::memory_order_relaxed);
                if (current_uid == static_cast<uint32_t>(uid)) {
                    cached_flags = g_shared_data->entries[index].flags.load(std::memory_order_relaxed);
                    found = true;
                    break;
                } else if (current_uid == UINT32_MAX) {
                    break; // Empty slot found, UID is definitely not here
                }
                index = (index + 1) % constants::SHM_HASH_MAP_SIZE;
            } while (index != start_index);

            uint32_t version2 = g_shared_data->version.load(std::memory_order_acquire);
            if (version1 == version2) {
                if (found) {
                    return cached_flags | g_shared_data->global_root_flags.load(std::memory_order_relaxed);
                }
            }
        }
    }

    // Fallback to IPC
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetProcessFlags");
        return 0;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetProcessFlags);
    socket_utils::write_u32(fd, uid);
    return socket_utils::read_u32(fd);
}

int GetSharedMemoryFd() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetSharedMemoryFd");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetSharedMemoryFd);

    // Read Status Byte
    uint8_t status = socket_utils::read_u8(fd);
    if (status == 0) {
        return -1;
    }

    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) {
        PLOGE("GetSharedMemoryFd: failed to receive fd");
        return -1;
    }

    return namespace_fd;
}

int GetZygiskSharedData() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetZygiskSharedData");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetZygiskSharedData);

    // Read Status Byte
    uint8_t status = socket_utils::read_u8(fd);
    if (status == 0) {
        return -1;
    }

    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) {
        PLOGE("GetZygiskSharedData: failed to receive fd");
        return -1;
    }

    return namespace_fd;
}

void CacheMountNamespace(pid_t pid) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("CacheMountNamespace");
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::CacheMountNamespace);
    socket_utils::write_u32(fd, (uint32_t) pid);
}

// Returns the file descriptor >= 0 on success, or -1 on failure.
int UpdateMountNamespace(MountNamespace type) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("UpdateMountNamespace");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::UpdateMountNamespace);
    socket_utils::write_u8(fd, (uint8_t) type);

    // Read Status Byte
    uint8_t status = socket_utils::read_u8(fd);
    // Handle Failure Case (Not Cached)
    if (status == 0) {
        // Daemon explicitly told us it doesn't have it.
        return -1;
    }
    // Handle Success Case
    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) {
        PLOGE("UpdateMountNamespace: failed to receive fd");
        return -1;
    }

    return namespace_fd;
}

size_t ReadModules(Module* out_modules, size_t max_modules) {
    size_t count = 0;
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReadModules");
        return count;
    }

    uint8_t request = static_cast<uint8_t>(constants::DaemonSocketAction::ReadModules);
    socket_utils::write_u8(fd, request);

    size_t total_modules = socket_utils::read_usize(fd);
    for (size_t i = 0; i < total_modules; ++i) {
        // Read directly into a raw stack buffer
        char name_buf[256];
        socket_utils::read_string(fd, name_buf, sizeof(name_buf));
        
        // Receive the file descriptor (commonly named recv_fd or read_fd)
        // Using assignment '=' prevents C++ "Most Vexing Parse" compiler bug
        UniqueFd lib_fd = UniqueFd(socket_utils::recv_fd(fd)); 
        
        if (count < max_modules) {
            // Safely copy the string into the module's raw char array
            strlcpy(out_modules[count].name, name_buf, sizeof(out_modules[count].name));
            // Transfer ownership of the file descriptor
            out_modules[count].memfd = std::move(lib_fd);
            count++;
        }
        // If count >= max_modules, lib_fd goes out of scope here and automatically closes
    }
    return count;
}

int ConnectCompanion(size_t index) {
    UniqueFd fd(Connect(1));
    if (fd == -1) {
        PLOGE("ConnectCompanion");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::RequestCompanionSocket);
    socket_utils::write_usize(fd, index);
    if (socket_utils::read_u8(fd) == 1) {
        return fd.release(); 
    } else {
        return -1;
    }
}

int GetModuleDir(size_t index) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetModuleDir");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetModuleDir);
    socket_utils::write_usize(fd, index);
    return socket_utils::recv_fd(fd);
}

int ReportModuleCrash(size_t index) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReportModuleCrash: failed to connect to zygiskd");
        return -1;
    }

    uint8_t action = static_cast<uint8_t>(constants::DaemonSocketAction::ReportModuleCrash);
    if (!socket_utils::write_u8(fd, action)) {
        PLOGE("ReportModuleCrash: failed to write action");
        return -1;
    }

    if (!socket_utils::write_usize(fd, index)) {
        PLOGE("ReportModuleCrash: failed to write module index");
        return -1;
    }

    LOGI("Crash for module index %zu reported to daemon.", index);
    return 0;
}

void ZygoteRestart() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        if (errno == ENOENT) {
            LOGD("could not notify ZygoteRestart (maybe it hasn't been created)");
        } else {
            PLOGE("notify ZygoteRestart");
        }
        return;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::ZygoteRestart)) {
        PLOGE("request ZygoteRestart");
    }
}

void SystemServerStarted() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("report system server started");
    } else {
        if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::SystemServerStarted)) {
            PLOGE("report system server started");
        }
    }
}
}  // namespace zygiskd
