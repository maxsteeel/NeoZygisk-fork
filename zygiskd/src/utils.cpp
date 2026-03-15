#include "utils.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include "daemon.hpp"
#include "logging.hpp"
#include "socket_utils.hpp"
#include "misc.hpp"

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
        ssize_t r = socket_utils::xread(fd, buf, sizeof(buf) - 1);
        if (r > 0) {
            // Trim trailing newline if any
            while (r > 0 && (buf[r-1] == '\n' || buf[r-1] == '\r')) {
                buf[r-1] = '\0';
                r--;
            }
            return std::string(buf);
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

} // namespace utils
