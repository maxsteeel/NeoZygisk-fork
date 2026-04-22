#pragma once

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "logging.hpp"

namespace socket_utils {

__attribute__((noinline))
inline ssize_t xread(int fd, void* buf, size_t count) {
    if (count == 0) [[unlikely]] return 0;
    uint8_t* ptr = static_cast<uint8_t*>(buf);
    const uint8_t* const end = ptr + count;

    ssize_t ret_initial = read(fd, ptr, count);
    if (ret_initial == static_cast<ssize_t>(count)) [[likely]] {
        return count;
    } else if (ret_initial > 0) {
        ptr += ret_initial;
    } else if (ret_initial < 0 && errno != EINTR) [[unlikely]] {
        PLOGE("read");
        return -1;
    } else if (ret_initial == 0) [[unlikely]] {
        return 0; // EOF on first read
    }

    while (ptr < end) [[likely]] {
        ssize_t ret = read(fd, ptr, end - ptr);
        if (ret > 0) [[likely]] {
            ptr += ret;
        } else if (ret == 0) [[unlikely]] {
            break;
        } else if (errno != EINTR) [[unlikely]] {
            PLOGE("read");
            return -1;
        }
    }

    size_t read_sz = ptr - static_cast<uint8_t*>(buf);
    if (read_sz != count) [[unlikely]] {
        PLOGE("read (%zu != %zu)", count, read_sz);
    }
    return read_sz;
}

__attribute__((noinline))
inline size_t xwrite(int fd, const void* buf, size_t count) {
    if (count == 0) [[unlikely]] return 0;
    const uint8_t* ptr = static_cast<const uint8_t*>(buf);
    const uint8_t* const end = ptr + count;

    ssize_t ret_initial = write(fd, ptr, count);
    if (ret_initial == static_cast<ssize_t>(count)) [[likely]] {
        return count;
    } else if (ret_initial > 0) {
        ptr += ret_initial;
    } else if (ret_initial < 0 && errno != EINTR) [[unlikely]] {
        PLOGE("write");
        return 0;
    }

    while (ptr < end) [[likely]] {
        ssize_t ret = write(fd, ptr, end - ptr);
        if (ret > 0) [[likely]] {
            ptr += ret;
        } else if (ret == 0) [[unlikely]] {
            break;
        } else if (errno != EINTR) [[unlikely]] {
            PLOGE("write");
            return ptr - static_cast<const uint8_t*>(buf);
        }
    }

    size_t write_sz = ptr - static_cast<const uint8_t*>(buf);
    if (write_sz != count) [[unlikely]] {
        PLOGE("write (%zu != %zu)", count, write_sz);
    }
    return write_sz;
}


template <typename T>
__attribute__((noinline))
inline T read_exact_or(int fd, T fail) {
    T res;
    return sizeof(T) == xread(fd, &res, sizeof(T)) ? res : fail;
}

template <typename T>
__attribute__((noinline))
inline bool write_exact(int fd, T val) {
    return sizeof(T) == xwrite(fd, &val, sizeof(T));
}

__attribute__((always_inline)) 
inline ssize_t xrecvmsg(int sockfd, struct msghdr* msg, int flags) {
    int rec = recvmsg(sockfd, msg, flags);
    if (rec < 0) PLOGE("recvmsg");
    return rec;
}

__attribute__((always_inline)) 
inline ssize_t xsendmsg(int sockfd, const struct msghdr* msg, int flags) {
    int sent = sendmsg(sockfd, msg, flags);
    if (sent < 0) PLOGE("sendmsg");
    return sent;
}

__attribute__((noinline))
inline void* recv_fds(int sockfd, char* cmsgbuf, size_t bufsz, int cnt) {
    int dummy_data;

    iovec iov = {
        .iov_base = &dummy_data,
        .iov_len = sizeof(dummy_data),
    };
    msghdr msg = {.msg_name = nullptr,
                  .msg_namelen = 0,
                  .msg_iov = &iov,
                  .msg_iovlen = 1,
                  .msg_control = cmsgbuf,
                  .msg_controllen = bufsz,
                  .msg_flags = 0};

    ssize_t rec = xrecvmsg(sockfd, &msg, MSG_WAITALL | MSG_CMSG_CLOEXEC);

    if (rec != sizeof(dummy_data)) {
        PLOGE("recv_fds: IO failure. Read %zd bytes, expected %zu", rec, sizeof(dummy_data));
    }

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg == nullptr) {
        LOGE("recv_fds: No control headers received. msg_controllen=%zu", (size_t) msg.msg_controllen);
        return nullptr;
    }

    if (msg.msg_controllen != bufsz) {
        LOGW("recv_fds: Size mismatch. Buffer capacity: %zu, Received len: %zu", bufsz, (size_t) msg.msg_controllen);
    }

    size_t expected_cmsg_len = CMSG_LEN(sizeof(int) * cnt);
    if (cmsg->cmsg_len != expected_cmsg_len) {
        LOGW("recv_fds: CMSG header len mismatch. Header says: %zu, Calculated: %zu (cnt=%d)",
             (size_t) cmsg->cmsg_len, expected_cmsg_len, cnt);
    }

    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        LOGW("recv_fds: Protocol mismatch. Level: %d (exp %d), Type: %d (exp %d)", cmsg->cmsg_level,
             SOL_SOCKET, cmsg->cmsg_type, SCM_RIGHTS);
    }

    return CMSG_DATA(cmsg);
}

inline uint8_t read_u8(int fd) { return read_exact_or<uint8_t>(fd, 0); }
inline uint32_t read_u32(int fd) { return read_exact_or<uint32_t>(fd, 0); }
inline size_t read_usize(int fd) { return read_exact_or<size_t>(fd, 0); }
inline bool write_usize(int fd, size_t val) { return write_exact<size_t>(fd, val); }
inline bool write_u8(int fd, uint8_t val) { return write_exact<uint8_t>(fd, val); }
inline bool write_u32(int fd, uint32_t val) { return write_exact<uint32_t>(fd, val); }

__attribute__((noinline))
inline void read_string(int fd, char* buf, size_t buf_size) {
    auto len = read_usize(fd);
    if (len == 0) [[unlikely]] {
        buf[0] = '\0';
        return;
    }
    size_t read_len = (len < buf_size) ? len : (buf_size - 1);
    xread(fd, buf, read_len);
    buf[read_len] = '\0';

    if (len > read_len) [[unlikely]] {
        char trash[1024]; 
        size_t remain = len - read_len;
        while (remain > 0) {
            size_t to_read = (remain < sizeof(trash)) ? remain : sizeof(trash);
            xread(fd, trash, to_read);
            remain -= to_read;
        }
    }
}

__attribute__((noinline))
inline bool write_string(int fd, const char* str) {
    size_t len = str ? __builtin_strlen(str) : 0;
    struct iovec iov[2];
    iov[0].iov_base = &len;
    iov[0].iov_len = sizeof(len);
    iov[1].iov_base = const_cast<char*>(str ? str : "");
    iov[1].iov_len = len;

    size_t total = sizeof(len) + len;
    size_t written = 0;

    while (written < total) {
        ssize_t ret = writev(fd, iov, 2);
        if (ret > 0) [[likely]] {
            written += ret;
            if (written < total) [[unlikely]] {
                if (static_cast<size_t>(ret) >= iov[0].iov_len) {
                    size_t str_written = ret - iov[0].iov_len;
                    iov[1].iov_base = static_cast<char*>(iov[1].iov_base) + str_written;
                    iov[1].iov_len -= str_written;
                    iov[0].iov_len = 0;
                } else {
                    iov[0].iov_base = static_cast<char*>(iov[0].iov_base) + ret;
                    iov[0].iov_len -= ret;
                }
            }
        } else if (ret == 0) [[unlikely]] {
            break;
        } else if (errno != EINTR) [[unlikely]] {
            PLOGE("writev");
            return false;
        }
    }
    return written == total;
}

__attribute__((noinline))
inline int recv_fd(int sockfd) {
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    void* data = recv_fds(sockfd, cmsgbuf, sizeof(cmsgbuf), 1);
    if (data == nullptr) return -1;

    int result;
    __builtin_memcpy(&result, data, sizeof(int));
    return result;
}

__attribute__((noinline))
inline bool send_fd(int sockfd, int fd) {
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    int dummy_data = 0;
    iovec iov = {.iov_base = &dummy_data, .iov_len = sizeof(dummy_data)};
    msghdr msg = {
        .msg_name = nullptr,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
        .msg_flags = 0,
    };

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    __builtin_memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ssize_t sent = xsendmsg(sockfd, &msg, 0);
    if (sent != sizeof(dummy_data)) {
        LOGE("send_fd: IO failure. Sent %zd bytes, expected %zu", sent, sizeof(dummy_data));
        return false;
    }
    return true;
}

}  // namespace socket_utils
