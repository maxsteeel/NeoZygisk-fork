#pragma once

#include <unistd.h>
#include <cstdint>
#include "misc.hpp"

#if defined(__LP64__)
#define LP_SELECT(lp32, lp64) lp64
#else
#define LP_SELECT(lp32, lp64) lp32
#endif

extern const char* kCPSocketName;

class UniqueFd {
    using Fd = int;

public:
    UniqueFd() = default;

    UniqueFd(Fd fd) : fd_(fd) {}

    ~UniqueFd() {
        if (fd_ >= 0) close(fd_);
    }

    // Disallow copy
    UniqueFd(const UniqueFd&) = delete;

    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    // Implicit cast to Fd
    operator const Fd&() const { return fd_; }

    // Relinquish ownership of the file descriptor without closing it.
    Fd release() {
        Fd temp = fd_;
        fd_ = -1;
        return temp;
    }

private:
    Fd fd_ = -1;
};

namespace zygiskd {

struct Module {
    char name[256];
    UniqueFd memfd;

    // Default constructor required for static array initialization
    inline Module() : memfd(-1) {
        name[0] = '\0';
    }

    inline explicit Module(const char* n, int fd) : memfd(fd) {
        strlcpy(name, n ? n : "", sizeof(name));
    }
};

enum class SocketAction {
    PingHeartbeat,
    GetProcessFlags,
    CacheMountNamespace,
    UpdateMountNamespace,
    ReadModules,
    RequestCompanionSocket,
    GetModuleDir,
    ZygoteRestart,
    SystemServerStarted,
    GetSharedMemoryFd,
    GetZygiskSharedData,
};

enum class MountNamespace { Clean, Root };

constexpr const char* kWorkDirectory = WORK_DIRECTORY;

void Init();

const char* GetModDir();

int Connect(uint8_t retry);

bool PingHeartbeat();

size_t ReadModules(Module* out_modules, size_t max_modules);

uint32_t GetProcessFlags(uid_t uid);

void CacheMountNamespace(pid_t pid);

int UpdateMountNamespace(MountNamespace type);

int ConnectCompanion(size_t index);

int GetModuleDir(size_t index);

int ReportModuleCrash(size_t index);

void ZygoteRestart();

void SystemServerStarted();

int GetSharedMemoryFd();

int GetZygiskSharedData();

void UnmapSharedMemory();

}  // namespace zygiskd
