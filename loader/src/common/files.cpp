#include "files.hpp"

#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std::string_view_literals;

void file_readline(bool trim, FILE *fp, const std::function<bool(std::string_view)> &fn) {
    if (!fp) return;

    char buf[4096]; 

    int fd = fileno(fp);
    if (fd < 0) return;

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

void file_readline(bool trim, const char *file, const std::function<bool(std::string_view)> &fn) {
    if (auto fp = open_file(file, "re")) file_readline(trim, fp.get(), fn);
}
void file_readline(const char *file, const std::function<bool(std::string_view)> &fn) {
    file_readline(false, file, fn);
}

sDIR make_dir(DIR *dp) {
    return sDIR(dp, [](DIR *dp) { return dp ? closedir(dp) : 1; });
}

sFILE make_file(FILE *fp) {
    return sFILE(fp, [](FILE *fp) { return fp ? fclose(fp) : 1; });
}
