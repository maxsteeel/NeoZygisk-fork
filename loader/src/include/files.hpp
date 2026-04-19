#pragma once
#include "../../../zygiskd/src/include/utils.hpp"

#include <dirent.h>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "daemon.hpp"

static inline UniqueDir open_dir(const char *path) { return UniqueDir(opendir(path)); }
static inline UniqueFile xopen_file(const char *path, const char *mode) { return UniqueFile(fopen(path, mode)); }
static inline UniqueFile xopen_file(int fd, const char *mode) { return UniqueFile(fdopen(fd, mode)); }

template <typename Func>
inline void file_readline(bool trim, int fd, Func fn) {
    if (fd < 0) return;

    char buf[4096]; 
    ssize_t bytes_read;
    size_t current_pos = 0;

    while ((bytes_read = read(fd, buf + current_pos, sizeof(buf) - current_pos - 1)) > 0) {
        size_t total_bytes = current_pos + bytes_read;
        buf[total_bytes] = '\0';

        char *line_start = buf;
        char *line_end;

        while ((line_end = static_cast<char*>(__builtin_memchr(line_start, '\n', total_bytes - (line_start - buf)))) != nullptr) {
            *line_end = '\0';
            char *start = line_start;
            size_t len = line_end - line_start;

            if (trim) {
                while (len > 0 && (start[len - 1] == '\r' || start[len - 1] == ' ')) {
                    start[len - 1] = '\0'; len--;
                }
                while (len > 0 && *start == ' ') {
                    start++; len--;
                }
            }

            if (!fn(start)) return;
            line_start = line_end + 1;
        }

        size_t remaining = total_bytes - (line_start - buf);
        if (remaining > 0 && remaining < sizeof(buf)) {
            __builtin_memmove(buf, line_start, remaining);
            current_pos = remaining;
        } else {
            current_pos = 0;
        }
    }
}

template <typename Func>
inline void file_readline(bool trim, FILE *fp, Func fn) {
    if (fp) file_readline(trim, fileno(fp), fn);
}

template <typename Func>
inline void file_readline(bool trim, const char *file, Func fn) {
    UniqueFd fd(open(file, O_RDONLY | O_CLOEXEC));
    if (fd >= 0) file_readline(trim, fd, fn);
}

template <typename Func>
inline void file_readline(const char *file, Func fn) {
    file_readline(false, file, fn);
}
