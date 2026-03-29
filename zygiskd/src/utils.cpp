#include "utils.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <optional>

#include "daemon.hpp"
#include "logging.hpp"
#include "socket_utils.hpp"
#include "misc.hpp"
#include <sys/syscall.h>

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
        snprintf(fallback_path, sizeof(fallback_path), "/proc/self/task/%d/attr/sockcreate", gettid());
        fd = UniqueFd(open(fallback_path, O_WRONLY | O_CLOEXEC));
    }

    if (fd >= 0) {
        size_t len = strlen(context);
        ssize_t w = socket_utils::xwrite(fd, context, len);
        return w == static_cast<ssize_t>(len);
    }
    return false;
}

std::string get_current_attr() {
    char buf[256] = {0};
    UniqueFd fd(open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC));
    if (fd >= 0) {
        // Use normal 'read', since the file has variable size
        ssize_t r = read(fd, buf, sizeof(buf) - 1); 
        if (r > 0) {
            // Trim trailing newline if any
            while (r > 0 && (buf[r-1] == '\n' || buf[r-1] == '\r')) {
                buf[r-1] = '\0';
                r--;
            }
            return std::string(buf, r);
        }
    }
    return "";
}

std::string get_property(const char* name) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(name, value) > 0) {
        return std::string(value);
    }
    return "";
}

// --- Unix Socket and IPC Extensions ---

bool unix_datagram_sendto(const char* path, const void* buf, size_t len) {
    std::string attr = get_current_attr();
    if (!set_socket_create_context(attr.c_str())) {
        PLOGE("unix_datagram_sendto: set_socket_create_context(attr)");
        return false;
    }

    UniqueFd fd(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (fd < 0) {
        PLOGE("unix_datagram_sendto: socket");
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(addr.sun_path)) {
        LOGE("unix_datagram_sendto: path too long");
        return false;
    }
    // Abstract socket name (first byte is 0) or regular? The Rust code used SocketAddrUnix::new(path.as_bytes())
    // which binds an abstract socket if path doesn't contain null bytes but standard path strings. Wait, Rust new()
    // uses standard path unless from_abstract_name is used. We use standard paths for datagram sendto.
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
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, 0);
    if (ret < 0) {
        return false;
    }
    return (pfd.revents & ~POLLIN) == 0;
}

std::optional<std::string> exec_command(std::initializer_list<const char*> args) {
    if (args.size() == 0) return std::nullopt;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        return std::nullopt;
    }

    UniqueFd read_pipe(pipefd[0]);
    UniqueFd write_pipe(pipefd[1]);

    pid_t pid = fork();
    if (pid == -1) {
        return std::nullopt;
    }

    if (pid == 0) {
        read_pipe = UniqueFd();

        if (write_pipe != STDOUT_FILENO) {
            dup2(write_pipe, STDOUT_FILENO);
            write_pipe = UniqueFd();
        }

        UniqueFd null_fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
        if (null_fd >= 0) {
            if (null_fd != STDERR_FILENO) {
                dup2(null_fd, STDERR_FILENO);
                null_fd = UniqueFd();
            }
        }

        std::vector<char*> c_args;
        c_args.reserve(args.size() + 1);
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg));
        }
        c_args.push_back(nullptr);

        if (syscall(__NR_close_range, 3, ~0U, 0) != 0) {
            UniqueFd fd_dir(open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (fd_dir >= 0) {
                char buf[1024];
                int nread;
                int fds_to_close[256]; 
                int fd_count = 0;
                while ((nread = syscall(__NR_getdents64, (int)fd_dir, buf, sizeof(buf))) > 0) {
                    for (int bpos = 0; bpos < nread;) {
                        auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);
                        if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                            int fd = fast_atoi(d->d_name);
                            if (fd > 2 && fd != (int)fd_dir) {
                                if (fd_count < 256) {
                                    fds_to_close[fd_count++] = fd;
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

        execvp(c_args[0], c_args.data());
        _exit(127);
    }

    write_pipe = UniqueFd();
    std::string result;
    char buf[256];
    ssize_t n;

    while ((n = read(read_pipe, buf, sizeof(buf))) > 0) {
        result.append(buf, n);
    }

    int status;
    waitpid(pid, &status, 0);

    // Trim trailing whitespace and newlines
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
        result.pop_back();
    }

    if (result.empty()) return std::nullopt;
    return result;
}

} // namespace utils
