#pragma once

#include <dirent.h>
#include <pthread.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include "unique.hpp"

#define PROP_VALUE_MAX 92

struct linux_dirent64 {
    uint64_t d_ino [[maybe_unused]];
    int64_t d_off [[maybe_unused]];
    unsigned short d_reclen;
    unsigned char d_type [[maybe_unused]];
    char d_name[];
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
            for (size_t i = 0; i < size; ++i) { if (data[i]) free(data[i]); }
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
            char** new_data = static_cast<char**>(malloc(new_cap * sizeof(char*)));
            if (!new_data) return; // SAFE OOM
            if (data && size > 0) { __builtin_memcpy(new_data, data, size * sizeof(char*)); }
            if (data) free(data);
            data = new_data;
            capacity = new_cap;
        }
        size_t len = __builtin_strlen(str) + 1;
        char* dup = static_cast<char*>(malloc(len));
        if (dup) {
            __builtin_memcpy(dup, str, len);
            data[size++] = dup;
        }
    }
};

using once_flag = _Atomic(int);

template<class Callable>
inline void call_once(::once_flag& flag, Callable func) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(&flag, &expected, 1, memory_order_acquire, memory_order_relaxed)) {
        func();
        atomic_store_explicit(&flag, 2, memory_order_release);
    } else {
        while (atomic_load_explicit(&flag, memory_order_acquire) == 1) {
#if defined(__aarch64__) || defined(__arm__)
            asm volatile("yield" ::: "memory");
#elif defined(__i386__) || defined(__x86_64__)
            asm volatile("pause" ::: "memory");
#endif
        }
    }
}

/**
 * @brief RAII wrapper for a pthread_rwlock_t (Read-Write Lock)
 */
class RWLock {
    pthread_rwlock_t rwlock_;

public:
    RWLock() { pthread_rwlock_init(&rwlock_, nullptr); }
    ~RWLock() { pthread_rwlock_destroy(&rwlock_); }

    // No copy, no move
    RWLock(const RWLock&) = delete;
    RWLock& operator=(const RWLock&) = delete;

    void lock_shared() { pthread_rwlock_rdlock(&rwlock_); }
    void unlock_shared() { pthread_rwlock_unlock(&rwlock_); }

    void lock_exclusive() { pthread_rwlock_wrlock(&rwlock_); }
    void unlock_exclusive() { pthread_rwlock_unlock(&rwlock_); }
};

// RAII for Read (Multiple threads at once)
class SharedMutexGuard {
    RWLock& lock_;
public:
    explicit SharedMutexGuard(RWLock& l) : lock_(l) { lock_.lock_shared(); }
    ~SharedMutexGuard() { lock_.unlock_shared(); }
};

// RAII for Write (Only one thread, blocks readers too)
class UniqueMutexGuard {
    RWLock& lock_;
public:
    explicit UniqueMutexGuard(RWLock& l) : lock_(l) { lock_.lock_exclusive(); }
    ~UniqueMutexGuard() { lock_.unlock_exclusive(); }
};

// --- Fast Parsers and Threading ---

__attribute__((always_inline))
static inline int fast_atoi(const char *str) {
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
    bool unix_datagram_sendto(const char* name, const void* buf, size_t len);
    bool is_socket_alive(int fd);
    bool exec_command(const char* const* args, char* out_buf, size_t out_size);
}
