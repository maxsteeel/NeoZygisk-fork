#pragma once

#include <pthread.h>
#include <string.h>

#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)

template<class It, class Compare>
inline void sort(It first, It last, Compare comp) {
    size_t n = last - first;
    if (n <= 1) return;
    
    // Insertion sort is faster for very small arrays
    if (n < 32) {
        for (size_t i = 1; i < n; i++) {
            auto temp = *(first + i);
            size_t j;
            for (j = i; j > 0 && comp(temp, *(first + (j - 1))); j--) {
                *(first + j) = *(first + (j - 1));
            }
            *(first + j) = temp;
        }
        return;
    }
    
    // Shell sort with dynamic gap sequence (Knuth's sequence: 1, 4, 13, 40...)
    size_t gap = 1;
    while (gap < n / 3) gap = 3 * gap + 1;
    
    for (; gap > 0; gap /= 3) {
        for (size_t i = gap; i < n; i++) {
            auto temp = *(first + i);
            size_t j;
            for (j = i; j >= gap && comp(temp, *(first + (j - gap))); j -= gap) {
                *(first + j) = *(first + (j - gap));
            }
            *(first + j) = temp;
        }
    }
}

__attribute__((always_inline))
static inline uint64_t fast_strtoull(const char* str, char** endptr, int base) {
    uint64_t result = 0;
    const char* p = str;
    while (*p == ' ' || *p == '\t') p++;
    if (base == 16) {
        while (true) {
            char c = *p;
            uint64_t digit;
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                digit = c - 'A' + 10;
            } else {
                break;
            }
            result = (result << 4) | digit; 
            p++;
        }
    } else if (base == 10) {
        while (true) {
            char c = *p;
            if (c >= '0' && c <= '9') {
                result = result * 10 + (c - '0');
                p++;
            } else {
                break;
            }
        }
    }
    if (endptr) *endptr = const_cast<char*>(p);
    return result;
}

// Force the compiler to execute the memory wiping code,
// even if it thinks the memory is not used afterward.
static inline void memzero(void *s, size_t n) {
    if (n > 0) {
        memset(s, 0, n);
        __asm__ volatile("" : : "r"(s) : "memory");
    }
}

// Constants for Android Isolated UID range.
// Reference:
// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libcutils/include/private/android_filesystem_config.h
#define AID_ISOLATED_START 90000 /* start of uids for fully isolated sandboxed processes */
#define AID_ISOLATED_END 99999   /* end of uids for fully isolated sandboxed processes */

/**
 * @brief A basic RAII (Resource Acquisition Is Initialization) wrapper for a pthread_mutex_t.
 *
 * This class ensures that a pthread mutex is properly unlocked when the
 * guard goes out of scope.
 *
 * NOTE: For new C++ code, prefer using the standard library's std::mutex
 * and std::lock_guard (or std::unique_lock) from the <mutex> header. They
 * are more portable and integrate better with standard C++ features.
 */
class mutex_guard {
public:
    explicit mutex_guard(pthread_mutex_t& m) : mutex(&m) { pthread_mutex_lock(mutex); }

    ~mutex_guard() {
        if (mutex) {
            pthread_mutex_unlock(mutex);
        }
    }

    // This class manages a resource and should not be copied or moved.
    mutex_guard(const mutex_guard&) = delete;
    mutex_guard& operator=(const mutex_guard&) = delete;
    mutex_guard(mutex_guard&&) = delete;
    mutex_guard& operator=(mutex_guard&&) = delete;

    /**
     * @brief Manually unlocks the mutex before the guard is destroyed.
     * This prevents the mutex from being unlocked again in the destructor.
     */
    void unlock() {
        if (mutex) {
            pthread_mutex_unlock(mutex);
            mutex = nullptr;
        }
    }

private:
    pthread_mutex_t* mutex;
};

// Returns true if the current kernel is greater than or equal to req_major.req_minor
bool is_kernel_version_at_least(int req_major, int req_minor);
