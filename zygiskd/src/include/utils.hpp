#pragma once

#include <string>
#include <dirent.h>
#include <utility>
#include <cstdio>
#include <vector>
#include <optional>

// Wrapper to automatically close FILE pointers when they go out of scope.
// Prevents memory and file descriptor leaks in case of early returns.
struct UniqueFile {
    FILE* fp = nullptr;

    UniqueFile() = default;

    explicit UniqueFile(FILE* f) : fp(f) {}

    ~UniqueFile() {
        if (fp) fclose(fp);
    }

    // Disallow copy
    UniqueFile(const UniqueFile&) = delete;
    UniqueFile& operator=(const UniqueFile&) = delete;

    // Allow move
    UniqueFile(UniqueFile&& other) noexcept {
        fp = std::exchange(other.fp, nullptr);
    }

    UniqueFile& operator=(UniqueFile&& other) noexcept {
        if (this != &other) {
            if (fp) fclose(fp);
            fp = std::exchange(other.fp, nullptr);
        }
        return *this;
    }

    // Implicit cast to FILE*
    operator FILE*() const { return fp; }
};

// Wrapper to automatically close FILE pointers created by popen().
// Uses pclose() instead of fclose() to prevent zombie processes.
struct UniquePipe {
    FILE* fp = nullptr;

    UniquePipe() = default;

    explicit UniquePipe(FILE* f) : fp(f) {}

    ~UniquePipe() {
        if (fp) pclose(fp);
    }

    // Disallow copy
    UniquePipe(const UniquePipe&) = delete;
    UniquePipe& operator=(const UniquePipe&) = delete;

    // Allow move
    UniquePipe(UniquePipe&& other) noexcept {
        fp = std::exchange(other.fp, nullptr);
    }

    UniquePipe& operator=(UniquePipe&& other) noexcept {
        if (this != &other) {
            if (fp) pclose(fp);
            fp = std::exchange(other.fp, nullptr);
        }
        return *this;
    }

    // Implicit cast to FILE*
    operator FILE*() const { return fp; }
};

// Wrapper to automatically close DIR pointers when they go out of scope.
// Prevents directory stream leaks in case of early returns.
struct UniqueDir {
    DIR* dir = nullptr;

    UniqueDir() = default;

    explicit UniqueDir(DIR* d) : dir(d) {}

    ~UniqueDir() {
        if (dir) closedir(dir);
    }

    // Disallow copy
    UniqueDir(const UniqueDir&) = delete;
    UniqueDir& operator=(const UniqueDir&) = delete;

    // Allow move
    UniqueDir(UniqueDir&& other) noexcept {
        dir = std::exchange(other.dir, nullptr);
    }

    UniqueDir& operator=(UniqueDir&& other) noexcept {
        if (this != &other) {
            if (dir) closedir(dir);
            dir = std::exchange(other.dir, nullptr);
        }
        return *this;
    }

    // Implicit cast to DIR*
    operator DIR*() const { return dir; }
};

// Extremely fast inline string-to-int parser (avoids atoi overhead)
inline int fast_atoi(const char *str) {
    int val = 0;
    while (*str >= '0' && *str <= '9') {
        val = val * 10 + (*str++ - '0');
    }
    return val;
}

namespace utils {

// --- SELinux and Android Property Utilities ---

// Sets the SELinux context for socket creation for the current thread.
bool set_socket_create_context(const char* context);

// Gets the current SELinux context of the process.
std::string get_current_attr();

// Retrieves an Android system property value.
std::string get_property(const char* name);

// --- Unix Socket and IPC Extensions ---

// Sends a datagram packet to a Unix socket path.
bool unix_datagram_sendto(const char* path, const void* buf, size_t len);

// Checks if a Unix socket is still alive and connected using `poll`.
bool is_socket_alive(int fd);

// Executes a shell command securely avoiding shell injection by directly using execvp.
std::optional<std::string> exec_command(const std::vector<std::string>& args);

} // namespace utils
