#include "main.hpp"

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>

#include "logging.hpp"
#include "socket_utils.hpp"
#include "utils.hpp"
#include "daemon.hpp" 

namespace companion {

typedef void (*ZygiskCompanionEntryFn)(int);

struct alignas(void*) ClientData {
    int fd;
    ZygiskCompanionEntryFn entry;
};

static char* build_proc_fd_path(char* buf_end, int fd) {
    char* ptr = buf_end - 1;
    *ptr = '\0'; // Null terminator

    // We write the number from back to front
    do {
        *(--ptr) = '0' + (fd % 10);
        fd /= 10;
    } while (fd > 0);

    // We write the prefix before the number.
    ptr -= 14;
    __builtin_memcpy(ptr, "/proc/self/fd/", 14);

    return ptr; // We return the exact start of the chain
}

static void* handle_client_thread(void* arg) {
    ClientData data = *static_cast<ClientData*>(arg);
    free(arg);

    int raw_fd = data.fd;
    struct stat st0, st1;
    bool pre_stat_ok = (fstat(raw_fd, &st0) == 0);

    // Call into the module's code.
    data.entry(raw_fd);
    bool should_close = true;

    if (pre_stat_ok) {
        if (fstat(raw_fd, &st1) == 0) {
            // If device/inode changed, the module closed it and the OS reused the FD number.
            if (st0.st_dev != st1.st_dev || st0.st_ino != st1.st_ino) {
                should_close = false; 
            }
        } else {
            // fstat failed, meaning the FD is already closed.
            should_close = false;
        }
    }

    if (should_close) close(raw_fd);

    mallopt(M_PURGE, 0);

    return nullptr;
}

static ZygiskCompanionEntryFn load_module_entry(UniqueFd library_fd) {
    char path_buf[64];
    const char* path = build_proc_fd_path(path_buf + sizeof(path_buf), (int)library_fd);

    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        const char* err = dlerror();
        LOGE("load_module_entry: dlopen failed: %s", err ? err : "Unknown error");
        return nullptr;
    }

    void* entry_ptr = dlsym(handle, "zygisk_companion_entry");
    if (!entry_ptr) return nullptr;

    return reinterpret_cast<ZygiskCompanionEntryFn>(entry_ptr);
}

static void run_companion(int fd) {
    char name[256];
    socket_utils::read_string(fd, name, sizeof(name));
    UniqueFd library_fd(socket_utils::recv_fd(fd));

    if (library_fd < 0) {
        LOGE("Companion: Failed to receive library FD for module `%s`", name);
        socket_utils::write_u8(fd, 0);
        return;
    }

    ZygiskCompanionEntryFn entry_fn = load_module_entry(static_cast<UniqueFd&&>(library_fd));

    if (entry_fn) {
        LOGD("Companion entry point found for module `%s`", name);
        socket_utils::write_u8(fd, 1);
    } else {
        LOGD("Module `%s` has no companion entry point or failed to load.", name);
        socket_utils::write_u8(fd, 0);
        return;
    }

    // Main loop
    while (true) {
        UniqueFd client_fd(socket_utils::recv_fd(fd));
        if (client_fd < 0) {
            LOGI("Daemon socket closed or error, terminating companion for `%s`.", name);
            break;
        }

        LOGV("New companion request for module `%s` on fd=`%d`", name, (int)client_fd);
        socket_utils::write_u8((int)client_fd, 1);

        // malloc is fast, but aligning the struct to pointer boundaries guarantees single-cycle memory fetches
        ClientData* data = static_cast<ClientData*>(malloc(sizeof(ClientData)));
        if (data) {
            data->fd = client_fd.release();
            data->entry = entry_fn;
            spawn_thread(handle_client_thread, data);
        } else {
            LOGE("Companion: Failed to allocate memory for thread data.");
            // UniqueFd will auto-close client_fd if malloc fails.
        }
    }
}

void entry(int raw_fd) {
    UniqueFd fd(raw_fd);
    LOGI("Companion process started with fd=%d", (int)fd);
    run_companion((int)fd);
    LOGI("Companion process exiting.");
}

} // namespace companion
