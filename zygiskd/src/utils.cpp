#include "utils.hpp"
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "daemon.hpp"
#include "logging.hpp"
#include "socket_utils.hpp"

#ifndef __NR_close_range
#define __NR_close_range 436
#endif

namespace utils {

bool set_socket_create_context(const char* context) {
    if (!context || !*context) return false;
    int fd = open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC);
    
    if (fd < 0) {
        char path[64];
        char* ptr = path + sizeof(path) - 1;
        *ptr = '\0';

        ptr -= 16;
        __builtin_memcpy(ptr, "/attr/sockcreate", 16);

        int tid = gettid();
        do {
            *(--ptr) = '0' + (tid % 10);
            tid /= 10;
        } while (tid > 0);

        ptr -= 16;
        __builtin_memcpy(ptr, "/proc/self/task/", 16);
        
        fd = open(ptr, O_WRONLY | O_CLOEXEC);
    }
    
    if (fd >= 0) {
        size_t len = __builtin_strlen(context);
        bool success = (socket_utils::xwrite(fd, context, len) == len);
        close(fd); 
        return success;
    }
    return false;
}

// Caller provides the buffer. No 'thread_local' hidden locks.
const char* get_current_attr(char* out_buf, size_t max_len) {
    out_buf[0] = '\0';
    UniqueFd fd(open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC));
    if (fd >= 0) {
        ssize_t r = read(fd, out_buf, max_len - 1);
        if (r > 0) {
            // Trim trailing newlines
            while (r > 0 && (out_buf[r - 1] == '\n' || out_buf[r - 1] == '\r')) {
                r--;
            }
            out_buf[r] = '\0';
            return out_buf;
        }
    }
    return "";
}

// Caller provides the buffer. No static guard variables.
const char* get_property(const char* name, char* out_buf) {
    out_buf[0] = '\0';
    if (__system_property_get(name, out_buf) > 0) return out_buf;
    return "";
}

bool unix_datagram_sendto(const char* name, const void* buf, size_t len) {
    char attr_buf[256];
    const char* attr = get_current_attr(attr_buf, sizeof(attr_buf));
    if (!set_socket_create_context(attr)) return false;

    UniqueFd fd(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (fd < 0) return false;

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    size_t name_len = __builtin_strlen(name);
    if (name_len >= sizeof(addr.sun_path) - 1) return false;
    
    __builtin_memcpy(addr.sun_path + 1, name, name_len);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) return false;
    
    ssize_t w = send(fd, buf, len, 0);
    set_socket_create_context("u:r:zygote:s0");
    return w == static_cast<ssize_t>(len);
}

bool is_socket_alive(int fd) {
    struct pollfd pfd = {fd, POLLIN, 0};
    return poll(&pfd, 1, 0) >= 0 && (pfd.revents & ~POLLIN) == 0;
}

bool exec_command(const char* const* args, char* out_buf, size_t out_size) {
    if (!args || !args[0] || !out_buf || out_size == 0) return false;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) return false;

    UniqueFd read_pipe(pipefd[0]);
    UniqueFd write_pipe(pipefd[1]);

    pid_t pid = fork();
    if (pid == -1) return false;

    if (pid == 0) {
        read_pipe = UniqueFd();
        if (write_pipe != STDOUT_FILENO) dup2(write_pipe, STDOUT_FILENO);
        else write_pipe.release(); 

        UniqueFd null_fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
        if (null_fd >= 0) {
            if (null_fd != STDERR_FILENO) dup2(null_fd, STDERR_FILENO);
            else null_fd.release(); 
        }

        // Close all FDs except 0, 1, 2
        if (syscall(__NR_close_range, 3, ~0U, 0) != 0) {
            UniqueFd fd_dir(open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (fd_dir >= 0) {
                // Fetch all FDs in one kernel context switch
                alignas(struct linux_dirent64) char buf[8192];
                int nread;
                while ((nread = syscall(__NR_getdents64, (int)fd_dir, buf, sizeof(buf))) > 0) {
                    for (int bpos = 0; bpos < nread;) {
                        auto d = reinterpret_cast<struct linux_dirent64*>(buf + bpos);
                        char c = d->d_name[0];
                        if (c >= '1' && c <= '9') { // FD 0 is ignored anyway
                            const char* s = d->d_name;
                            int fd_val = fast_atoi(s);
                            if (fd_val > 2 && fd_val != (int)fd_dir) {
                                syscall(SYS_close, fd_val);
                            }
                        }
                        bpos += d->d_reclen;
                    }
                }
            }
        }
        execvp(args[0], const_cast<char* const*>(args));
        _exit(127);
    }

    write_pipe = UniqueFd();
    size_t total_read = 0;
    
    struct pollfd pfd = {read_pipe, POLLIN, 0};
    while (total_read < out_size - 1) {
        if (poll(&pfd, 1, 1000) <= 0) break;
        ssize_t n = read(read_pipe, out_buf + total_read, out_size - 1 - total_read);
        if (n <= 0) break;
        total_read += n;
    }
    
    out_buf[total_read] = '\0';
    int status;
    waitpid(pid, &status, 0);

    return total_read > 0;
}

}  // namespace utils
