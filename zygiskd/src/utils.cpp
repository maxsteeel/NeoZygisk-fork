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
#include <optional>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "misc.hpp"
#include "socket_utils.hpp"

#ifndef __NR_close_range
#define __NR_close_range 436
#endif

// Structure for the getdents64 syscall
struct linux_dirent64 {
    uint64_t d_ino [[maybe_unused]];
    int64_t d_off [[maybe_unused]];
    unsigned short d_reclen;
    unsigned char d_type [[maybe_unused]];
    char d_name[];
};

namespace utils {

// --- SELinux and Android Property Utilities ---

bool set_socket_create_context(const char* context) {
    // Try the modern path first.
    UniqueFd fd(open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC));
    if (fd < 0) {
        // Fallback for older kernels.
        char fallback_path[64];
        snprintf(fallback_path, sizeof(fallback_path), "/proc/self/task/%d/attr/sockcreate",
                 gettid());
        fd = UniqueFd(open(fallback_path, O_WRONLY | O_CLOEXEC));
    }

    if (fd >= 0) {
        size_t len = strlen(context);
        ssize_t w = socket_utils::xwrite(fd, context, len);
        return w == static_cast<ssize_t>(len);
    }
    return false;
}

const char* get_current_attr() {
    thread_local char buf[256] = {0};
    memset(buf, 0, sizeof(buf));
    UniqueFd fd(open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC));
    if (fd >= 0) {
        // Use normal 'read', since the file has variable size
        ssize_t r = read(fd, buf, sizeof(buf) - 1);
        if (r > 0) {
            // Trim trailing newline if any
            while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r')) {
                buf[r - 1] = '\0';
                r--;
            }
            return buf;
        }
    }
    return "";
}

const char* get_property(const char* name) {
    static char value[PROP_VALUE_MAX] = {0};
    memset(value, 0, sizeof(value));
    if (__system_property_get(name, value) > 0) {
        return value;
    }
    return "";
}

// --- Unix Socket and IPC Extensions ---

bool unix_datagram_sendto(const char* path, const void* buf, size_t len) {
    const char* attr = get_current_attr();
    if (!set_socket_create_context(attr)) {
        PLOGE("unix_datagram_sendto: set_socket_create_context(attr)");
        return false;
    }

    UniqueFd fd(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (fd < 0) {
        PLOGE("unix_datagram_sendto: socket");
        return false;
    }

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(addr.sun_path)) {
        LOGE("unix_datagram_sendto: path too long");
        return false;
    }
    // Abstract socket name (first byte is 0) or regular? The Rust code used
    // SocketAddrUnix::new(path.as_bytes()) which binds an abstract socket if path doesn't contain
    // null bytes but standard path strings. Wait, Rust new() uses standard path unless
    // from_abstract_name is used. We use standard paths for datagram sendto.
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + path_len + 1;

    // We don't need to connect for DGRAM, but connect+send was used in Rust.
    // Equivalent to sendto.
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) {
        PLOGE("unix_datagram_sendto: connect");
        return false;
    }

    ssize_t w = send(fd, buf, len, 0);
    if (w < 0) {
        PLOGE("unix_datagram_sendto: send");
    }

    if (!set_socket_create_context("u:r:zygote:s0")) {
        PLOGE("unix_datagram_sendto: restore context to zygote");
        return false;
    }

    return w == static_cast<ssize_t>(len);
}

bool is_socket_alive(int fd) {
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, 0);
    if (ret < 0) {
        return false;
    }
    return (pfd.revents & ~POLLIN) == 0;
}

bool exec_command(std::initializer_list<const char*> args, char* out_buf, size_t out_size) {
    if (args.size() == 0 || out_buf == nullptr) return false;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        return false;
    }

    UniqueFd read_pipe(pipefd[0]);
    UniqueFd write_pipe(pipefd[1]);

    pid_t pid = fork();
    if (pid == -1) {
        return false;
    }

    if (pid == 0) {
        read_pipe = UniqueFd();

        // Redirect write_pipe to STDOUT
        if (write_pipe != STDOUT_FILENO) {
            dup2(write_pipe, STDOUT_FILENO);
        } else {
            write_pipe.release(); // Prevents destructor from closing FD 1
        }

        // Redirect /dev/null to STDERR
        UniqueFd null_fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
        if (null_fd >= 0) {
            if (null_fd != STDERR_FILENO) {
                dup2(null_fd, STDERR_FILENO);
            } else {
                null_fd.release(); // Prevents destructor from closing FD 2
            }
        }

        char** c_args = (char**) alloca((args.size() + 1) * sizeof(char*));
        size_t i = 0;
        for (const auto& arg : args) {
            c_args[i] = const_cast<char*>(arg);
            i++;
        }
        c_args[i] = nullptr;

        if (syscall(__NR_close_range, 3, ~0U, 0) != 0) {
            UniqueFd fd_dir(open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (fd_dir >= 0) {
                alignas(struct linux_dirent64) char buf[1024];
                int nread;
                int fds_to_close[256]{};
                int fd_count = 0;
                while ((nread = syscall(__NR_getdents64, (int) fd_dir, buf, sizeof(buf))) > 0) {
                    for (int bpos = 0; bpos < nread;) {
                        auto d = reinterpret_cast<struct linux_dirent64*>(buf + bpos);
                        if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                            int fd = fast_atoi(d->d_name);
                            if (fd > 2 && fd != (int) fd_dir) {
                                fds_to_close[fd_count++] = fd;
                                if (fd_count == 256) {
                                    for (int i = 0; i < 256; i++) {
                                        close(fds_to_close[i]);
                                    }
                                    fd_count = 0;
                                }
                            }
                        }
                        bpos += d->d_reclen;
                    }
                }
                for (int i = 0; i < fd_count; i++) {
                    close(fds_to_close[i]);
                }
            }
        }

        execvp(c_args[0], c_args);
        _exit(127);
    }

    write_pipe = UniqueFd();
    size_t total_read = 0;
    ssize_t n;

    // Trim trailing whitespace and newlines
    while (total_read < out_size - 1 &&
           (n = read(read_pipe, out_buf + total_read, out_size - 1 - total_read)) > 0) {
        total_read += n;
    }
    out_buf[total_read] = '\0';  // null terminator

    // Wait for the child process to avoid leaving zombies
    int status;
    waitpid(pid, &status, 0);

    return total_read > 0;
}

}  // namespace utils
