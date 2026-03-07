#include "daemon.hpp"

#include <linux/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/mman.h>  // mmap, PROT_READ, MAP_SHARED, MAP_FAILED
#include <sys/prctl.h> // Prctl

#include "logging.hpp"
#include "socket_utils.hpp"
#include "shared_memory.hpp"

zygisk::ZygiskSharedData* g_shared_data = nullptr;

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

namespace zygiskd {
static std::string TMP_PATH;
std::string kCPSocketName = (sizeof(void*) == 8) ? "cp64.sock" : "cp32.sock";

void Init(const char *path) { TMP_PATH = path; }

std::string GetTmpPath() { return TMP_PATH; }

int Connect(uint8_t retry) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;

    memcpy(addr.sun_path + 1, kCPSocketName.c_str(), kCPSocketName.size());
    socklen_t socklen = sizeof(addr.sun_family) + kCPSocketName.size() + 1;

    while (retry--) {
        int r = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), socklen);
        if (r == 0) return fd;
        if (retry) {
            LOGW("retrying to connect to zygiskd, sleep 1s");
            sleep(1);
        }
    }

    close(fd);
    return -1;
}

bool InitSharedMemory() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        LOGE("Failed to connect to daemon for shared memory.");
        return false;
    }

    // 1. Request the shared memory file descriptor from the daemon
    socket_utils::write_u8(fd, static_cast<uint8_t>(SocketAction::RequestSharedMemoryFd));

    // 2. Read a status byte to check if the daemon is willing to provide the shared memory FD
    uint8_t status = socket_utils::read_u8(fd);
    
    if (status == 1) {
        // 3. The daemon agreed to provide the shared memory FD, we read it from the socket
        int mem_fd = socket_utils::recv_fd(fd);
        
        if (mem_fd >= 0) {
            // 4. We map purely anonymous memory
            void* map = mmap(nullptr, sizeof(zygisk::ZygiskSharedData), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            
            if (map != MAP_FAILED) {
                // Roll back the FD to the beginning just in case and copy the bytes to anonymous memory
                lseek(mem_fd, 0, SEEK_SET);
                read(mem_fd, map, sizeof(zygisk::ZygiskSharedData));
                
                close(mem_fd); // Destroy the FD as soon as possible to leave 0 traces in the process. The memory will remain valid because it's now purely anonymous.

                // Return the memory to read-only for security
                mprotect(map, sizeof(zygisk::ZygiskSharedData), PROT_READ);

                g_shared_data = static_cast<zygisk::ZygiskSharedData*>(map);

                LOGI("Shared memory initialized successfully! Magic: 0x%X", g_shared_data->magic);
                return true;
            } else {
                close(mem_fd);
                LOGE("mmap MAP_ANONYMOUS failed: %s", strerror(errno));
            }
        } else {
            LOGE("Failed to receive shared memory FD.");
        }
    } else {
        LOGE("Daemon refused to provide shared memory FD.");
    }
    
    return false;
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
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetProcessFlags");
        return 0;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetProcessFlags);
    socket_utils::write_u32(fd, uid);
    return socket_utils::read_u32(fd);
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

std::vector<Module> ReadModules() {
    std::vector<Module> modules;
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReadModules");
        return modules;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::ReadModules);
    size_t len = socket_utils::read_usize(fd);
    for (size_t i = 0; i < len; i++) {
        std::string name = socket_utils::read_string(fd);
        int module_fd = socket_utils::recv_fd(fd);
        modules.emplace_back(name, module_fd);
    }
    return modules;
}

int ConnectCompanion(size_t index) {
    int fd = Connect(1);
    if (fd == -1) {
        PLOGE("ConnectCompanion");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::RequestCompanionSocket);
    socket_utils::write_usize(fd, index);
    if (socket_utils::read_u8(fd) == 1) {
        return fd;
    } else {
        close(fd);
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
