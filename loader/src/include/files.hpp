#pragma once

#include <dirent.h>
#include <memory>
#include <string_view>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include "daemon.hpp"

using sFILE = std::unique_ptr<FILE, decltype(&fclose)>;
using sDIR = std::unique_ptr<DIR, decltype(&closedir)>;

sDIR make_dir(DIR *dp) {
    return sDIR(dp, [](DIR *dp) { return dp ? closedir(dp) : 1; });
}

sFILE make_file(FILE *fp) {
    return sFILE(fp, [](FILE *fp) { return fp ? fclose(fp) : 1; });
}

static inline sDIR open_dir(const char *path) { return make_dir(opendir(path)); }

static inline sFILE xopen_file(const char *path, const char *mode) {
    return make_file(fopen(path, mode));
}
static inline sFILE xopen_file(int fd, const char *mode) { return make_file(fdopen(fd, mode)); }

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

        while ((line_end = strchr(line_start, '\n')) != nullptr) {
            *line_end = '\0';

            char *start = line_start;
            size_t len = line_end - line_start;

            if (trim) {
                while (len > 0 && (start[len - 1] == '\r' || start[len - 1] == ' ')) {
                    start[len - 1] = '\0';
                    len--;
                }
                while (*start == ' ') {
                    start++;
                    len--;
                }
            }

            if (!fn(std::string_view(start, len))) return;

            line_start = line_end + 1;
        }

        size_t remaining = total_bytes - (line_start - buf);
        if (remaining > 0 && remaining < sizeof(buf)) {
            memmove(buf, line_start, remaining);
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
    file_readline(trim, fd, fn);
}

template <typename Func>
inline void file_readline(const char *file, Func fn) {
    file_readline(false, file, fn);
}
