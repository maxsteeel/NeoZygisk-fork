#pragma once

#include <string.h>
#include <cstdint>

namespace socket_utils {

    ssize_t xread(int fd, void *buf, size_t count);

    size_t xwrite(int fd, const void *buf, size_t count);

    template <typename T>
    inline T read_exact_or(int fd, T fail) {
        T res;
        return sizeof(T) == xread(fd, &res, sizeof(T)) ? res : fail;
    }

    template <typename T>
    inline bool write_exact(int fd, T val) {
        return sizeof(T) == xwrite(fd, &val, sizeof(T));
    }

    uint8_t read_u8(int fd);

    uint32_t read_u32(int fd);

    size_t read_usize(int fd);

    void read_string(int fd, char* buf, size_t buf_size);

    bool write_u8(int fd, uint8_t val);

    bool write_u32(int fd, uint32_t val);

    int recv_fd(int fd);

    bool send_fd(int sockfd, int fd);

    bool write_usize(int fd, size_t val);

    bool write_string(int fd, const char* str);
}
