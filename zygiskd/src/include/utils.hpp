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
#include <cstdlib> 
#include <cstring> 
#include <string_view>

#define PROP_VALUE_MAX 92

struct linux_dirent64 {
    uint64_t d_ino [[maybe_unused]];
    int64_t d_off [[maybe_unused]];
    unsigned short d_reclen;
    unsigned char d_type [[maybe_unused]];
    char d_name[];
};

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
            size_t new_cap = capacity == 0 ? 32 : capacity * 2;
            int32_t* new_data = (int32_t*)realloc(data, new_cap * sizeof(int32_t));
            if (!new_data) return; // SAFE: Prevent memory leak and segfault if OOM
            data = new_data;
            capacity = new_cap;
        }
        data[size++] = val;
    }
};

struct StringList {
    char** data = nullptr;
    size_t size = 0;
    size_t capacity = 0;

    StringList() = default;

    StringList(StringList&& other) noexcept : data(other.data), size(other.size), capacity(other.capacity) {
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
    }

    StringList& operator=(StringList&& other) noexcept {
        if (this != &other) {
            clear();
            data = std::exchange(other.data, nullptr);
            size = std::exchange(other.size, 0);
            capacity = std::exchange(other.capacity, 0);
        }
        return *this;
    }

    StringList(const StringList&) = delete;
    StringList& operator=(const StringList&) = delete;

    ~StringList() { clear(); }

    void clear() {
        if (data) {
            for (size_t i = 0; i < size; ++i) free(data[i]);
            free(data);
            data = nullptr;
        }
        size = 0;
        capacity = 0;
    }

    void push_back(const char* str) {
        if (!str) return;
        if (size >= capacity) {
            size_t new_cap = capacity == 0 ? 16 : capacity * 2;
            char** new_data = (char**)realloc(data, new_cap * sizeof(char*));
            if (!new_data) return; // SAFE
            data = new_data;
            capacity = new_cap;
        }
        data[size++] = strdup(str);
    }

    void push_back(std::string_view str) {
        if (str.empty()) return;
        if (size >= capacity) {
            size_t new_cap = capacity == 0 ? 16 : capacity * 2;
            char** new_data = (char**)realloc(data, new_cap * sizeof(char*));
            if (!new_data) return; // SAFE
            data = new_data;
            capacity = new_cap;
        }
        data[size++] = strndup(str.data(), str.size());
    }
};

// --- RAII Wrappers ---

struct UniqueFile {
    FILE* fp = nullptr;
    UniqueFile() = default;
    explicit UniqueFile(FILE* f) : fp(f) {}
    ~UniqueFile() { if (fp) fclose(fp); }
    UniqueFile(const UniqueFile&) = delete;
    UniqueFile& operator=(const UniqueFile&) = delete;
    UniqueFile(UniqueFile&& other) noexcept { fp = std::exchange(other.fp, nullptr); }
    UniqueFile& operator=(UniqueFile&& other) noexcept {
        if (this != &other) {
            if (fp) fclose(fp);
            fp = std::exchange(other.fp, nullptr);
        }
        return *this;
    }
    operator FILE*() const { return fp; }
    explicit operator bool() const { return fp != nullptr; } // Safer boolean check
};

struct UniquePipe {
    FILE* fp = nullptr;
    UniquePipe() = default;
    explicit UniquePipe(FILE* f) : fp(f) {}
    ~UniquePipe() { if (fp) pclose(fp); }
    UniquePipe(const UniquePipe&) = delete;
    UniquePipe& operator=(const UniquePipe&) = delete;
    UniquePipe(UniquePipe&& other) noexcept { fp = std::exchange(other.fp, nullptr); }
    UniquePipe& operator=(UniquePipe&& other) noexcept {
        if (this != &other) {
            if (fp) pclose(fp);
            fp = std::exchange(other.fp, nullptr);
        }
        return *this;
    }
    operator FILE*() const { return fp; }
    explicit operator bool() const { return fp != nullptr; }
};

struct UniqueDir {
    DIR* dir = nullptr;
    UniqueDir() = default;
    explicit UniqueDir(DIR* d) : dir(d) {}
    ~UniqueDir() { if (dir) closedir(dir); }
    UniqueDir(const UniqueDir&) = delete;
    UniqueDir& operator=(const UniqueDir&) = delete;
    UniqueDir(UniqueDir&& other) noexcept { dir = std::exchange(other.dir, nullptr); }
    UniqueDir& operator=(UniqueDir&& other) noexcept {
        if (this != &other) {
            if (dir) closedir(dir);
            dir = std::exchange(other.dir, nullptr);
        }
        return *this;
    }
    operator DIR*() const { return dir; }
    explicit operator bool() const { return dir != nullptr; }
};

// --- Fast Parsers and Threading ---

inline int fast_atoi(const char *str) {
    int val = 0;
    while (*str >= '0' && *str <= '9') {
        val = val * 10 + (*str++ - '0');
    }
    return val;
}

static inline void spawn_thread(void* (*thread_func)(void*), void* arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
#ifdef NDEBUG
    pthread_attr_setstacksize(&attr, 64 * 1024);
#endif
    pthread_t thread;
    if (pthread_create(&thread, &attr, thread_func, arg) == 0) {
        pthread_detach(thread);
    }
    pthread_attr_destroy(&attr);
}

namespace utils {
    bool set_socket_create_context(const char* context);
    const char* get_current_attr(char* out_buf, size_t max_len);
    const char* get_property(const char* name, char* out_buf);
    bool unix_datagram_sendto(const char* path, const void* buf, size_t len);
    bool is_socket_alive(int fd);
    bool exec_command(const char* const* args, char* out_buf, size_t out_size);
}
