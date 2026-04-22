#pragma once

#include <dirent.h>
#include <malloc.h>
#include <unistd.h>

// --- RAII Wrappers ---

struct UniqueFile {
    FILE* fp = nullptr;
    UniqueFile() = default;
    explicit UniqueFile(FILE* f) : fp(f) {}
    ~UniqueFile() { if (fp) fclose(fp); }
    UniqueFile(const UniqueFile&) = delete;
    UniqueFile& operator=(const UniqueFile&) = delete;
    UniqueFile(UniqueFile&& other) noexcept : fp(other.fp) { other.fp = nullptr; }
    UniqueFile& operator=(UniqueFile&& other) noexcept {
        if (this != &other) {
            if (fp) fclose(fp);
            fp = other.fp;
            other.fp = nullptr;
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
    UniquePipe(UniquePipe&& other) noexcept : fp(other.fp) { other.fp = nullptr; }
    UniquePipe& operator=(UniquePipe&& other) noexcept {
        if (this != &other) {
            if (fp) pclose(fp);
            fp = other.fp;
            other.fp = nullptr;
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
    UniqueDir(UniqueDir&& other) noexcept : dir(other.dir) { other.dir = nullptr; }
    UniqueDir& operator=(UniqueDir&& other) noexcept {
        if (this != &other) {
            if (dir) closedir(dir);
            dir = other.dir;
            other.dir = nullptr;
        }
        return *this;
    }
    operator DIR*() const { return dir; }
    explicit operator bool() const { return dir != nullptr; }
};

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

template <typename T>
struct UniqueList {
    T* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;

    // Default constructor
    UniqueList() = default;

    // Block copies to prevent Double-Free and Use-After-Free
    UniqueList(const UniqueList&) = delete;
    UniqueList& operator=(const UniqueList&) = delete;

    // Allow move semantics (Transfer ownership)
    UniqueList(UniqueList&& other) noexcept : data(other.data), size(other.size), capacity(other.capacity) {
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
    }

    UniqueList& operator=(UniqueList&& other) noexcept {
        if (this != &other) {
            free(data); 
            data = other.data;
            size = other.size;
            capacity = other.capacity;

            // Invalidate donor
            other.data = nullptr;
            other.size = 0;
            other.capacity = 0;
        }
        return *this;
    }

    ~UniqueList() { 
        free(data); 
    }

    void clear() {
        size = 0; 
    }

    void push_back(const T& val) {
        if (size >= capacity) {
            size_t new_cap = capacity == 0 ? 8 : capacity * 2;
            T* new_data = static_cast<T*>(malloc(new_cap * sizeof(T)));
            if (!new_data) return; // Prevent segfault on OOM
            if (data && size > 0) { __builtin_memcpy(new_data, data, size * sizeof(T)); }
            if (data) free(data);
            data = new_data;
            capacity = new_cap;
        }
        data[size++] = val;
    }

    void resize(size_t new_size) {
        if (new_size > capacity) {
            size_t old_cap = capacity;
            size_t new_cap = old_cap == 0 ? (new_size > 256 ? new_size : 256) : old_cap * 2;
            while (new_size > new_cap) { new_cap *= 2; }
            T* new_data = static_cast<T*>(malloc(new_cap * sizeof(T)));
            if (!new_data) return;
            if (data && old_cap > 0) { __builtin_memcpy(new_data, data, old_cap * sizeof(T)); }
            if (data) free(data);
            data = new_data;
            capacity = new_cap;
            __builtin_memset((void*)(data + old_cap), 0, (new_cap - old_cap) * sizeof(T));
        }
        size = new_size;
    }
};

template <typename T>
struct RegexUniqueList {
    T* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;

    RegexUniqueList() = default;
    RegexUniqueList(const RegexUniqueList&) = delete;
    RegexUniqueList& operator=(const RegexUniqueList&) = delete;
    RegexUniqueList(RegexUniqueList&& other) noexcept : data(other.data), size(other.size), capacity(other.capacity) {
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
    }
    RegexUniqueList& operator=(RegexUniqueList&& other) noexcept {
        if (this != &other) {
            clear_regexes();
            free(data);
            data = other.data;
            size = other.size;
            capacity = other.capacity;
            other.data = nullptr;
            other.size = 0;
            other.capacity = 0;
        }
        return *this;
    }
    ~RegexUniqueList() { 
        clear_regexes();
        free(data); 
    }
    void clear() {
        clear_regexes();
        size = 0;
    }
    void push_back(const T& val) {
        if (size >= capacity) {
            size_t new_cap = capacity == 0 ? 8 : capacity * 2;
            T* new_data = static_cast<T*>(malloc(new_cap * sizeof(T)));
            if (!new_data) return; 
            if (data && size > 0) { __builtin_memcpy(new_data, data, size * sizeof(T)); }
            if (data) free(data);
            data = new_data;
            capacity = new_cap;
        }
        data[size++] = val;
    }

private:
    void clear_regexes() {
        if (data) {
            for (size_t i = 0; i < size; ++i) {
                if (data[i].is_regex) {
                    regfree(&data[i].regex);
                    data[i].is_regex = false;
                }
            }
        }
    }
};

using IntList = UniqueList<int32_t>;
using BoolList = UniqueList<bool>;
