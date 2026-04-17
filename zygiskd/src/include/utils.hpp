#pragma once

#include <string>
#include <dirent.h>
#include <utility>
#include <cstdio>
#include <vector>
#include <optional>
#include <pthread.h>
#include <malloc.h>
#include <type_traits>
#include <utility>
#include <cstdlib> // malloc, realloc, free
#include <cstring> // strdup, strcmp
#include <algorithm> // std::binary_search
#include <string> // std::string_view

#define PROP_VALUE_MAX 92

struct IntList {
    int32_t* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;

    ~IntList() { free(data); }

    void clear() {
        free(data);
        data = nullptr;
        size = 0;
        capacity = 0;
    }

    void push_back(int32_t val) {
        if (size >= capacity) {
            capacity = capacity == 0 ? 32 : capacity * 2;
            data = (int32_t*)realloc(data, capacity * sizeof(int32_t));
        }
        data[size++] = val;
    }
};

struct StringList {
    char** data = nullptr;
    size_t size = 0;
    size_t capacity = 0;

    StringList() = default;

    // Move constructor
    StringList(StringList&& other) noexcept : data(other.data), size(other.size), capacity(other.capacity) {
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
    }

    // Move assignment
    StringList& operator=(StringList&& other) noexcept {
        if (this != &other) {
            clear();
            data = other.data;
            size = other.size;
            capacity = other.capacity;
            other.data = nullptr;
            other.size = 0;
            other.capacity = 0;
        }
        return *this;
    }

    StringList(const StringList&) = delete;
    StringList& operator=(const StringList&) = delete;

    ~StringList() { clear(); }

    void clear() {
        if (data) {
            for (size_t i = 0; i < size; ++i) {
                free(data[i]);
            }
            free(data);
            data = nullptr;
        }
        size = 0;
        capacity = 0;
    }

    void push_back(const char* str) {
        if (!str) return;
        if (size >= capacity) {
            capacity = capacity == 0 ? 16 : capacity * 2;
            data = (char**)realloc(data, capacity * sizeof(char*));
        }
        data[size++] = strdup(str);
    }

    void push_back(std::string_view str) {
        if (str.empty()) return;
        if (size >= capacity) {
            capacity = capacity == 0 ? 16 : capacity * 2;
            data = (char**)realloc(data, capacity * sizeof(char*));
        }
        data[size++] = str.empty() ? nullptr : strndup(str.data(), str.size());
    }
};

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

// Creates a detached background thread with a minimal 64KB stack 
// instead of Android's default 1MB in Release build.
static inline void spawn_thread(void* (*thread_func)(void*), void* arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);

#ifdef NDEBUG
    // Set stack size to 64KB (minimum recommended for basic C/C++ logic)
    size_t stack_size = 64 * 1024; 
    pthread_attr_setstacksize(&attr, stack_size);
#endif
    
    pthread_t thread;
    if (pthread_create(&thread, &attr, thread_func, arg) == 0) {
        // Detach immediately to free thread resources upon exit
        pthread_detach(thread);
    }
    
    pthread_attr_destroy(&attr);
}

// Template wrapper to spawn a detached pthread.
template <typename F>
static inline void spawn_thread(F&& lambda) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);

#ifdef NDEBUG
    // Set stack size to 64KB (minimum recommended for basic C/C++ logic)
    size_t stack_size = 64 * 1024; 
    pthread_attr_setstacksize(&attr, stack_size);
#endif

    // Heap-allocate the lambda so it survives the scope transition
    using LambdaType = std::decay_t<F>;
    auto* arg = new LambdaType(std::forward<F>(lambda));

    pthread_t thread;
    int ret = pthread_create(&thread, &attr, [](void* data) -> void* {
        auto* func = static_cast<LambdaType*>(data);
        (*func)();       // Execute the lambda
        delete func;     // Free the lambda memory
        return nullptr;
    }, arg);

    if (ret == 0) {
        pthread_detach(thread);
    } else {
        // Prevent memory leak if thread creation fails
        delete arg; 
    }
    
    pthread_attr_destroy(&attr);
}

namespace utils {

// --- SELinux and Android Property Utilities ---

// Sets the SELinux context for socket creation for the current thread.
bool set_socket_create_context(const char* context);

// Gets the current SELinux context of the process.
const char* get_current_attr();

// Retrieves an Android system property value.
const char* get_property(const char* name);

// --- Unix Socket and IPC Extensions ---

// Sends a datagram packet to a Unix socket path.
bool unix_datagram_sendto(const char* path, const void* buf, size_t len);

// Checks if a Unix socket is still alive and connected using `poll`.
bool is_socket_alive(int fd);

// Executes a shell command securely avoiding shell injection by directly using execvp.
bool exec_command(std::initializer_list<const char*> args, char* out_buf, size_t out_size);

} // namespace utils
