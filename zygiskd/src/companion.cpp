#include "companion.hpp"

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <cstring>
#include <thread>

#include "logging.hpp"
#include "socket_utils.hpp"
#include "utils.hpp"
#include "daemon.hpp" // For UniqueFd

namespace companion {

// The function signature for a module's companion entry point.
typedef void (*ZygiskCompanionEntryFn)(int);

static void handle_client(UniqueFd stream, ZygiskCompanionEntryFn entry) {
    // Stat the socket before handing it off to the module.
    struct stat st0;
    bool pre_stat_ok = (fstat(stream, &st0) == 0);

    // Call into the module's code.
    entry(stream);

    // After the module code returns, check if the file descriptor is still valid
    // and points to the same underlying file. This prevents us from accidentally
    // closing a new file descriptor if the module closed the original one and
    // the OS reused the FD number.
    if (pre_stat_ok) {
        struct stat st1;
        if (fstat(stream, &st1) == 0) {
            // If the device and inode numbers don't match, the FD has been reused.
            if (st0.st_dev != st1.st_dev || st0.st_ino != st1.st_ino) {
                stream.release(); // The FD was reused. Release the control to not close it.
                return;
            }
        } else {
            stream.release(); // The FD was already closed. Release so as not to do a double close().
            return;
        }
    }
    // If the function terminates normally without doing 'release()',
    // the UniqueFd does automatic and safe close().
}

static ZygiskCompanionEntryFn load_module_entry(UniqueFd fd) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", (int)fd);

    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        LOGE("load_module_entry: dlopen failed: %s", dlerror());
        return nullptr;
    }

    void* entry_ptr = dlsym(handle, "zygisk_companion_entry");
    if (!entry_ptr) {
        // Module has no companion entry point
        return nullptr;
    }

    return reinterpret_cast<ZygiskCompanionEntryFn>(entry_ptr);
}

static void run_companion(int fd) {
    // 1. Receive module name and library FD from the main daemon.
    char name[256];
    socket_utils::read_string(fd, name, sizeof(name));
    UniqueFd library_fd(socket_utils::recv_fd(fd));

    if (library_fd < 0) {
        LOGE("Companion: Failed to receive library FD for module `%s`", name);
        socket_utils::write_u8(fd, 0);
        return;
    }

    // 2. Dynamically load the module library and find its companion entry point.
    ZygiskCompanionEntryFn entry_fn = load_module_entry(std::move(library_fd));

    if (entry_fn) {
        LOGD("Companion entry point found for module `%s`", name);
        // Signal success back to the daemon.
        socket_utils::write_u8(fd, 1);
    } else {
        LOGD("Module `%s` has no companion entry point or failed to load.", name);
        // Signal failure and exit.
        socket_utils::write_u8(fd, 0);
        return;
    }

    // 3. Main loop: wait for requests from the module code injected in apps.
    while (true) {
        // Block until the daemon socket is readable or closed.
        if (!utils::is_socket_alive(fd)) {
            LOGI("Daemon socket closed, terminating companion for `%s`.", name);
            break;
        }

        // Receive a client socket FD from the daemon.
        UniqueFd client_fd(socket_utils::recv_fd(fd));
        if (client_fd < 0) {
            LOGE("Failed to receive client FD for module `%s`", name);
            break;
        }

        LOGV("New companion request for module `%s` on fd=`%d`", name, (int)client_fd);

        // Let the client know we've received the request.
        socket_utils::write_u8(client_fd, 1);

        // Spawn a new thread to handle this client.
        int raw_client = client_fd.release();
        std::thread([raw_client, entry_fn]() {
            handle_client(UniqueFd(raw_client), entry_fn);
        }).detach();
    }
}

void entry(int raw_fd) {
    UniqueFd fd(raw_fd);
    LOGI("Companion process started with fd=%d", (int)fd);
    run_companion(fd);
    LOGI("Companion process exiting.");
}

} // namespace companion
