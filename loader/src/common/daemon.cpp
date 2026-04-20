#include "daemon.hpp"

#include <linux/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

#include "logging.hpp"
#include "misc.hpp"
#include "socket_utils.hpp"
#include "constants.hpp"

constants::ZygiskSharedData* g_shared_data = nullptr;

namespace zygiskd {
constexpr const char* kCPSocketName = (sizeof(void*) == 8) ? "cp64.sock" : "cp32.sock";
static struct sockaddr_un g_daemon_addr;
static socklen_t g_daemon_socklen = 0;

void UnmapSharedMemory() {
    if (g_shared_data) {
        munmap(g_shared_data, sizeof(constants::ZygiskSharedData));
        g_shared_data = nullptr;
    }
}

void Init() {
    g_daemon_addr.sun_family = AF_UNIX;
    size_t len = __builtin_strlen(kCPSocketName);
    __builtin_memcpy(g_daemon_addr.sun_path + 1, kCPSocketName, len);
    g_daemon_socklen = sizeof(g_daemon_addr.sun_family) + len + 1;
}

const char* GetModDir() { return kWorkDirectory; }

int Connect(uint8_t retry) {
    UniqueFd fd(socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (unlikely(fd < 0)) return -1;

    unsigned int delay_ms = 10;
    while (retry--) {
        if (connect(fd, reinterpret_cast<struct sockaddr*>(&g_daemon_addr), g_daemon_socklen) == 0) {
            return fd.release();
        }
        
        if (retry) {
            LOGW("retrying to connect to zygiskd, sleep %u ms", delay_ms);
            struct timespec ts;
            ts.tv_sec = delay_ms / 1000;
            ts.tv_nsec = (delay_ms % 1000) * 1000000L;
            nanosleep(&ts, nullptr);
            delay_ms *= 2;
            if (delay_ms > 1000) delay_ms = 1000;
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

        if ((version1 & 1) == 0) {
            size_t index = uid & (constants::SHM_HASH_MAP_SIZE - 1);
            size_t start_index = index;
            bool found = false;
            uint32_t cached_flags = 0;
            uint32_t target_uid = static_cast<uint32_t>(uid);

            do {
                uint32_t current_uid = g_shared_data->entries[index].uid.load(std::memory_order_relaxed);
                if (current_uid == target_uid) {
                    cached_flags = g_shared_data->entries[index].flags.load(std::memory_order_relaxed);
                    found = true;
                    break;
                } else if (current_uid == UINT32_MAX) {
                    break; 
                }
                index = (index + 1) & (constants::SHM_HASH_MAP_SIZE - 1);
            } while (index != start_index);

            if (found && (g_shared_data->version.load(std::memory_order_acquire) == version1)) {
                return cached_flags | g_shared_data->global_root_flags.load(std::memory_order_relaxed);
            }
        }
    }

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
    if (socket_utils::read_u8(fd) == 0) return -1;
    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) PLOGE("GetSharedMemoryFd: failed to receive fd");
    return namespace_fd;
}

int GetZygiskSharedData() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetZygiskSharedData");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetZygiskSharedData);
    if (socket_utils::read_u8(fd) == 0) return -1;
    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) PLOGE("GetZygiskSharedData: failed to receive fd");
    return namespace_fd;
}

void CacheMountNamespace(pid_t pid) {
    UniqueFd fd = Connect(1);
    if (fd != -1) {
        socket_utils::write_u8(fd, (uint8_t) SocketAction::CacheMountNamespace);
        socket_utils::write_u32(fd, (uint32_t) pid);
    } else {
        PLOGE("CacheMountNamespace");
    }
}

int UpdateMountNamespace(MountNamespace type) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("UpdateMountNamespace");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::UpdateMountNamespace);
    socket_utils::write_u8(fd, (uint8_t) type);
    if (socket_utils::read_u8(fd) == 0) return -1;
    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) PLOGE("UpdateMountNamespace: failed to receive fd");
    return namespace_fd;
}

size_t ReadModules(Module* out_modules, size_t max_modules) {
    size_t count = 0;
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReadModules");
        return count;
    }

    socket_utils::write_u8(fd, static_cast<uint8_t>(constants::DaemonSocketAction::ReadModules));
    size_t total_modules = socket_utils::read_usize(fd);
    for (size_t i = 0; i < total_modules; ++i) {
        char name_buf[256];
        socket_utils::read_string(fd, name_buf, sizeof(name_buf));
        
        int lib_fd = socket_utils::recv_fd(fd); 
        
        if (count < max_modules) {
            size_t len = __builtin_strlen(name_buf);
            if (len >= sizeof(out_modules[count].name)) len = sizeof(out_modules[count].name) - 1;
            __builtin_memcpy(out_modules[count].name, name_buf, len);
            out_modules[count].name[len] = '\0';
            out_modules[count].memfd = static_cast<UniqueFd&&>(lib_fd);
            count++;
        }
        // If count >= max_modules, lib_fd goes out of scope here and automatically closes
    }
    return count;
}

int ConnectCompanion(size_t index) {
    UniqueFd fd = Connect(1);
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

    if (!socket_utils::write_u8(fd, static_cast<uint8_t>(constants::DaemonSocketAction::ReportModuleCrash)) ||
        !socket_utils::write_usize(fd, index)) {
        PLOGE("ReportModuleCrash: failed to write data");
        return -1;
    }

    LOGI("Crash for module index %zu reported to daemon.", index);
    return 0;
}

void ZygoteRestart() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        if (errno == ENOENT) LOGD("could not notify ZygoteRestart (maybe it hasn't been created)");
        else PLOGE("notify ZygoteRestart");
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
