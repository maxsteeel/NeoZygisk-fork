#pragma once

#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>

#if defined(__LP64__)
#define LP_SELECT(lp32, lp64) lp64
#else
#define LP_SELECT(lp32, lp64) lp32
#endif

extern std::string kCPSocketName;

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

    // Allow move
    UniqueFd(UniqueFd&& other) { std::swap(fd_, other.fd_); }

    UniqueFd& operator=(UniqueFd&& other) {
        std::swap(fd_, other.fd_);
        return *this;
    }

    // Implict cast to Fd
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
};

enum class MountNamespace { Clean, Root };

void Init(const char *path, const char *mod_dir);

std::string GetTmpPath();
std::string GetModDir();

bool PingHeartbeat();

std::vector<Module> ReadModules();

uint32_t GetProcessFlags(uid_t uid);

void CacheMountNamespace(pid_t pid);

int UpdateMountNamespace(MountNamespace type);

int ConnectCompanion(size_t index);

int GetModuleDir(size_t index);

void ZygoteRestart();

void SystemServerStarted();
}  // namespace zygiskd
