#include "zygiskd_main.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include <cerrno>
#include <csignal>

#include <sys/mman.h>
#include <linux/memfd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>

#include "logging.hpp"
#include "companion.hpp"
#include "constants.hpp"
#include "socket_utils.hpp"
#include "utils.hpp"
#include "mount.hpp"
#include "root_impl.hpp"
#include "daemon.hpp" // For SocketAction, Module (modified for zygiskd daemon side)

// memfd_create is usually declared in <sys/mman.h>, but might need syscall directly if not present in Bionic
#ifndef memfd_create
#include <sys/syscall.h>
static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}
#endif

// F_ADD_SEALS etc
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL     0x0001
#define F_SEAL_SHRINK   0x0002
#define F_SEAL_GROW     0x0004
#define F_SEAL_WRITE    0x0008
#endif

namespace zygiskd_main {

using constants::DaemonSocketAction;
using constants::ProcessFlags;
using zygisk_mount::MountNamespaceManager;
using zygisk_mount::switch_mount_namespace;

struct Module {
    char name[256];
    UniqueFd lib_fd;
    std::mutex companion_mutex;
    UniqueFd companion_fd;

    Module() = default;   
};

#define MAX_MODULES 32
struct AppContext {
    Module* modules[MAX_MODULES];
    size_t module_count = 0;
    MountNamespaceManager* mount_manager;
};

static char TMP_PATH[256] = {0};
static char CONTROLLER_SOCKET[256] = {0};
static const char* const DAEMON_SOCKET_PATH = LP_SELECT("cp32.sock", "cp64.sock");

static UniqueFd g_shm_fd;
static constants::ZygiskSharedData* g_shm_base = nullptr;
static std::mutex g_shm_write_mutex;

static bool initialize_globals() {
    const char* env_tmp = getenv("TMP_PATH");
    if (!env_tmp) {
        LOGE("TMP_PATH environment variable not set");
        return false;
    }
    strlcpy(TMP_PATH, env_tmp, sizeof(TMP_PATH));
    snprintf(CONTROLLER_SOCKET, sizeof(CONTROLLER_SOCKET), "%s/init_monitor", TMP_PATH);

    // Initialize Shared Memory
    g_shm_fd = UniqueFd(memfd_create("zygisk-shm", MFD_ALLOW_SEALING | MFD_CLOEXEC));
    if (g_shm_fd < 0) {
        PLOGE("memfd_create zygisk-shm failed");
        return false;
    }
    if (ftruncate(g_shm_fd, sizeof(constants::ZygiskSharedData)) < 0) {
        PLOGE("ftruncate zygisk-shm failed");
        return false;
    }

    // We do NOT add F_SEAL_WRITE yet, so we can write to it on the fly when new requests come in.
    int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (fcntl(g_shm_fd, F_ADD_SEALS, seals) == -1) {
        LOGW("Failed to add seals to shm memfd: %s", strerror(errno));
    }

    g_shm_base = static_cast<constants::ZygiskSharedData*>(mmap(nullptr, sizeof(constants::ZygiskSharedData), PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0));
    if (g_shm_base == MAP_FAILED) {
        PLOGE("mmap zygisk-shm failed");
        return false;
    }

    // Initialize all UID slots to UINT32_MAX to allow UID 0 (root) caching
    ProcessFlags global_flags = ProcessFlags::NONE;
    auto root = root_impl::get();
    if (root == root_impl::RootImpl::APatch) global_flags |= ProcessFlags::PROCESS_ROOT_IS_APATCH;
    else if (root == root_impl::RootImpl::KernelSU) global_flags |= ProcessFlags::PROCESS_ROOT_IS_KSU;
    else if (root == root_impl::RootImpl::Magisk) global_flags |= ProcessFlags::PROCESS_ROOT_IS_MAGISK;
    
    g_shm_base->global_root_flags.store(static_cast<uint32_t>(global_flags), std::memory_order_relaxed);
    g_shm_base->version.store(0, std::memory_order_relaxed);
    for (size_t i = 0; i < constants::SHM_HASH_MAP_SIZE; ++i) {
        g_shm_base->entries[i].uid.store(UINT32_MAX, std::memory_order_relaxed);
        g_shm_base->entries[i].flags.store(0, std::memory_order_relaxed);
    }

    return true;
}

static void shm_refresh_thread() {
    prctl(PR_SET_NAME, "zygiskd-refresh");
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        if (!g_shm_base) continue;
        
        root_impl::refresh_cache();

        // Calculate time once per loop
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t now_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;

        bool changed = false;

        for (size_t i = 0; i < constants::SHM_HASH_MAP_SIZE; ++i) {
            uint32_t uid = g_shm_base->entries[i].uid.load(std::memory_order_relaxed);
            if (uid == UINT32_MAX) continue;

            ProcessFlags new_flags = ProcessFlags::NONE;
            // Pass now_ms to avoid redundant syscalls
            if (root_impl::uid_is_manager(uid, now_ms)) {
                new_flags |= ProcessFlags::PROCESS_IS_MANAGER;
            } else {
                if (root_impl::uid_granted_root(uid)) new_flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
                if (root_impl::uid_should_umount(uid)) new_flags |= ProcessFlags::PROCESS_ON_DENYLIST;
            }

            uint32_t new_val = static_cast<uint32_t>(new_flags);
            uint32_t old_val = g_shm_base->entries[i].flags.load(std::memory_order_relaxed);

            if (new_val != old_val) {
                // Lock only when a change is detected
                std::lock_guard<std::mutex> lock(g_shm_write_mutex);

                uint32_t current_ver = g_shm_base->version.load(std::memory_order_relaxed);
                g_shm_base->version.store(current_ver + 1, std::memory_order_release);
                g_shm_base->entries[i].flags.store(new_val, std::memory_order_relaxed);
                g_shm_base->version.store(current_ver + 2, std::memory_order_release);
                changed = true;
            }
        }

        if (changed) {
            LOGD("Refresh thread updated process flags based on system changes.");
        }
    }
}

static bool send_startup_info(Module** modules, size_t module_count) {
    uint8_t msg[4096];
    memset(msg, 0, sizeof(msg));

    uint32_t* magic_ptr = reinterpret_cast<uint32_t*>(msg);
    char* info_ptr = reinterpret_cast<char*>(msg + 8);
    size_t max_info_sz = sizeof(msg) - 8 - 1;

    auto root = root_impl::get();
    const char* root_name = "Unknown";
    if (root == root_impl::RootImpl::APatch) root_name = "APatch";
    else if (root == root_impl::RootImpl::KernelSU) root_name = "KernelSU";
    else if (root == root_impl::RootImpl::Magisk) root_name = "Magisk";

    if (strcmp(root_name, "Unknown") == 0) {
        *magic_ptr = constants::DAEMON_SET_ERROR_INFO;
        strlcpy(info_ptr, "\t\tInvalid root implementation.", max_info_sz);
    } else {
        *magic_ptr = constants::DAEMON_SET_INFO;
        int written = snprintf(info_ptr, max_info_sz, "\t\tRoot: %s", root_name);
        if (module_count > 0) {
            written += snprintf(info_ptr + written, max_info_sz - written, 
                                "\n\t\tModules (%zu):\n\t\t\t", module_count);

            for (size_t i = 0; i < module_count; ++i) {
                written += snprintf(info_ptr + written, max_info_sz - written, "%s", modules[i]->name);
                if (i != module_count - 1) {
                    written += snprintf(info_ptr + written, max_info_sz - written, "\n\t\t\t");
                }
                if (written >= (int)max_info_sz - 10) break; 
            }
        }
    }

    uint32_t text_len = strlen(info_ptr) + 1;
    memcpy(msg + 4, &text_len, 4);

    size_t total_msg_len = 8 + text_len;
    return utils::unix_datagram_sendto(CONTROLLER_SOCKET, msg, total_msg_len);
}

static const char* get_arch() {
    char abi[PROP_VALUE_MAX];
    if (__system_property_get("ro.product.cpu.abi", abi) > 0) {
        if (strstr(abi, "arm")) return LP_SELECT("armeabi-v7a", "arm64-v8a");
        if (strstr(abi, "x86")) return LP_SELECT("x86", "x86_64");
    }
    return "";
}

static int create_library_fd(int raw_file_fd) {
    UniqueFd file_fd(raw_file_fd);

    UniqueFd memfd(memfd_create("zygisk-module", MFD_ALLOW_SEALING | MFD_CLOEXEC));
    if (memfd < 0) {
        PLOGE("memfd_create");
        return -1;
    }

    char buf[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, buf, sizeof(buf))) > 0) {
        if (socket_utils::xwrite(memfd, buf, bytes_read) != static_cast<size_t>(bytes_read)) {
            PLOGE("write memfd");
            return -1;
        }
    }

    int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
    if (fcntl(memfd, F_ADD_SEALS, seals) == -1) {
        LOGW("Failed to add seals to memfd: %s", strerror(errno));
    }

    if (fchmod(memfd, S_IRUSR | S_IRGRP | S_IROTH) == -1) {
        LOGW("Failed to set read-only permissions: %s", strerror(errno));
    }

    return memfd.release();
}

static void load_modules(AppContext* context) {
    context->module_count = 0;
    const char* arch = get_arch();

    if (arch[0] == '\0') {
        LOGE("Unsupported system architecture");
        return;
    }

    LOGD("Daemon architecture: %s", arch);

    UniqueDir dir(opendir(constants::PATH_MODULES_DIR));
    if (!dir) {
        LOGW("Failed to read modules directory %s", constants::PATH_MODULES_DIR);
        return;
    }

    int dir_fd = dirfd(dir);
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        if (context->module_count >= MAX_MODULES) {
            LOGW("Max modules limit (%d) reached! Skipping `%s`", MAX_MODULES, entry->d_name);
            break;
        }

        char disable_path[256];
        snprintf(disable_path, sizeof(disable_path), "%s/disable", entry->d_name);
        if (faccessat(dir_fd, disable_path, F_OK, 0) == 0) continue; // Disabled

        char so_path[256];
        snprintf(so_path, sizeof(so_path), "%s/zygisk/%s.so", entry->d_name, arch);

        int raw_file_fd = openat(dir_fd, so_path, O_RDONLY | O_CLOEXEC);
        if (raw_file_fd < 0) continue; // No so file

        int lib_fd = create_library_fd(raw_file_fd);
        if (lib_fd >= 0) {
            LOGI("Loading module `%s`...", entry->d_name);
            Module* mod = new Module(); 
            strlcpy(mod->name, entry->d_name, sizeof(mod->name));
            mod->lib_fd = lib_fd;
            context->modules[context->module_count] = mod;
            context->module_count++;
        } else {
            LOGW("Failed to create memfd for `%s`", entry->d_name);
        }
    }
}

static int create_daemon_socket() {
    UniqueFd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (fd < 0) return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, DAEMON_SOCKET_PATH, sizeof(addr.sun_path) - 2);

    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(DAEMON_SOCKET_PATH) + 1;

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) {
        PLOGE("bind");
        // Use _exit(1) instead of return to prevent C++ global 
        // destructors from crashing detached threads.
        _exit(1);
    }

    if (listen(fd, 10) < 0) {
        PLOGE("listen");
        _exit(1);
    }

    return fd.release();
}

static int spawn_companion(const char* name) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
        PLOGE("socketpair");
        return -1;
    }

    UniqueFd daemon_sock(pair[0]);
    UniqueFd companion_sock(pair[1]);

    char self_exe[256];
    ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (len < 0) {
        PLOGE("readlink /proc/self/exe");
        return -1;
    }
    self_exe[len] = '\0';

    char nice_name[256];
    const char* base_name = strrchr(self_exe, '/');
    base_name = base_name ? base_name + 1 : "zygiskd";
    strlcpy(nice_name, base_name, sizeof(nice_name));

    pid_t pid = fork();
    if (pid < 0) {
        PLOGE("fork");
        return -1;
    }

    if (pid == 0) {
        // Child
        daemon_sock = UniqueFd();

        // Remove CLOEXEC from companion_sock
        int flags = fcntl(companion_sock, F_GETFD);
        fcntl(companion_sock, F_SETFD, flags & ~FD_CLOEXEC);

        char arg0[256];
        snprintf(arg0, sizeof(arg0), "%s-%s", nice_name, name);

        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", (int)companion_sock);

        // exec
        const char* argv[] = {arg0, "companion", fd_str, nullptr};
#ifndef NDEBUG
        // set env for child process
        setenv("ZYGISK_COMPANION_FD", fd_str, 1);
#endif

        execv(self_exe, const_cast<char**>(argv));
        PLOGE("execv");
        _exit(1);
    }

    // Parent
    companion_sock = UniqueFd();

    // Now, establish communication with the newly spawned companion.
    socket_utils::write_string(daemon_sock, name);

    return daemon_sock.release();
}

static int spawn_companion_complete(const char* name, int lib_fd) {
    UniqueFd daemon_sock(spawn_companion(name));
    if (daemon_sock < 0) return -1;
    if (!socket_utils::send_fd(daemon_sock, lib_fd))  return -1;

    uint8_t status = socket_utils::read_u8(daemon_sock);
    if (status == 1) return daemon_sock.release();

    return -1;
}


static void handle_get_process_flags(int stream) {
    int32_t uid = socket_utils::read_u32(stream);
    ProcessFlags flags = ProcessFlags::NONE;
    
    root_impl::refresh_cache();

    if (root_impl::uid_is_manager(uid)) {
        flags |= ProcessFlags::PROCESS_IS_MANAGER;
    } else {
        if (root_impl::uid_granted_root(uid)) {
            flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
        }
        if (root_impl::uid_should_umount(uid)) {
            flags |= ProcessFlags::PROCESS_ON_DENYLIST;
        }
    }

    auto root = root_impl::get();
    if (root == root_impl::RootImpl::APatch) flags |= ProcessFlags::PROCESS_ROOT_IS_APATCH;
    else if (root == root_impl::RootImpl::KernelSU) flags |= ProcessFlags::PROCESS_ROOT_IS_KSU;
    else if (root == root_impl::RootImpl::Magisk) flags |= ProcessFlags::PROCESS_ROOT_IS_MAGISK;

    uint32_t flags_val = static_cast<uint32_t>(flags);

    if (g_shm_base) {
        std::lock_guard<std::mutex> lock(g_shm_write_mutex);

        // Find slot in hash map using linear probing
        size_t index = uid % constants::SHM_HASH_MAP_SIZE;
        size_t start_index = index;
        bool inserted = false;

        // We increment version to denote we are writing
        uint32_t current_version = g_shm_base->version.load(std::memory_order_relaxed);
        if (current_version % 2 == 0) {
            g_shm_base->version.store(current_version + 1, std::memory_order_release);
        }

        do {
            uint32_t current_uid = g_shm_base->entries[index].uid.load(std::memory_order_relaxed);
            if (current_uid == UINT32_MAX || current_uid == static_cast<uint32_t>(uid)) {
                g_shm_base->entries[index].uid.store(uid, std::memory_order_relaxed);
                g_shm_base->entries[index].flags.store(flags_val, std::memory_order_relaxed);
                inserted = true;
                break;
            }
            index = (index + 1) % constants::SHM_HASH_MAP_SIZE;
        } while (index != start_index);

        if (!inserted) {
            LOGW("ShmMap is full! Could not cache uid %d", uid);
        }

        // Finish update
        g_shm_base->version.store(g_shm_base->version.load(std::memory_order_relaxed) + 1, std::memory_order_release);
    }

    socket_utils::write_u32(stream, flags_val);
}

static void handle_update_mount_namespace(int stream, AppContext* context) {
    uint8_t type_val = socket_utils::read_u8(stream);
    zygiskd::MountNamespace ns_type = (type_val == 0) ? zygiskd::MountNamespace::Clean : zygiskd::MountNamespace::Root;

    int fd = context->mount_manager->get_namespace_fd(ns_type);
    if (fd >= 0) {
        socket_utils::write_u8(stream, 1);
        socket_utils::send_fd(stream, fd);
    } else {
        LOGW("Namespace is not cached yet.");
        socket_utils::write_u8(stream, 0);
    }
}

static void handle_read_modules(int stream, AppContext* context) {
    socket_utils::write_usize(stream, context->module_count);
    for (size_t i = 0; i < context->module_count; ++i) {
        auto module = context->modules[i];
        socket_utils::write_string(stream, module->name);
        socket_utils::send_fd(stream, module->lib_fd);
    }
}

static void handle_request_companion_socket(int stream, AppContext* context) {
    size_t index = socket_utils::read_usize(stream);
    if (index >= context->module_count) {
        socket_utils::write_u8(stream, 0);
        return;
    }

    auto module = context->modules[index];
    std::lock_guard<std::mutex> lock(module->companion_mutex);

    if (module->companion_fd >= 0) {
        if (!utils::is_socket_alive(module->companion_fd)) {
            LOGE("Companion for module `%s` appears to have crashed.", module->name);
            module->companion_fd = UniqueFd();
        }
    }

    if (module->companion_fd < 0) {
        int sock = spawn_companion_complete(module->name, module->lib_fd);
        if (sock >= 0) {
            LOGV("Spawned new companion for `%s`.", module->name);
            module->companion_fd = UniqueFd(sock);
        } else {
            LOGW("Module `%s` does not have a companion entry point or failed.", module->name);
        }
    }

    if (module->companion_fd >= 0) {
        if (!socket_utils::send_fd(module->companion_fd, stream)) {
            LOGE("Failed to send companion socket FD for module `%s`", module->name);
            socket_utils::write_u8(stream, 0);
        }
    } else {
        socket_utils::write_u8(stream, 0);
    }
}

static void handle_get_module_dir(int stream, AppContext* context) {
    size_t index = socket_utils::read_usize(stream);
    if (index >= context->module_count) return;
    auto module = context->modules[index];
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "%s/%s", constants::PATH_MODULES_DIR, module->name);
    UniqueFd dir_fd(open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (dir_fd >= 0) socket_utils::send_fd(stream, dir_fd);
}

static void handle_report_module_crash(int stream, AppContext* context) {
    size_t index = socket_utils::read_usize(stream);
    if (index >= context->module_count) return;

    auto module = context->modules[index];
    char disable_path[256];
    snprintf(disable_path, sizeof(disable_path), "%s/%s/disable", constants::PATH_MODULES_DIR, module->name);

    int fd = open(disable_path, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    if (fd >= 0) {
        close(fd);
        LOGI("Module `%s` has been disabled by daemon after crash report.", module->name);
    } else {
        PLOGE("Failed to create disable file for `%s`", module->name);
    }
}

static void handle_threaded_action(DaemonSocketAction action, int stream, AppContext* context) {
    switch (action) {
        case DaemonSocketAction::GetProcessFlags: handle_get_process_flags(stream); break;
        case DaemonSocketAction::UpdateMountNamespace: handle_update_mount_namespace(stream, context); break;
        case DaemonSocketAction::ReadModules: handle_read_modules(stream, context); break;
        case DaemonSocketAction::RequestCompanionSocket: handle_request_companion_socket(stream, context); break;
        case DaemonSocketAction::GetModuleDir: handle_get_module_dir(stream, context); break;
        case DaemonSocketAction::ReportModuleCrash: handle_report_module_crash(stream, context); break;
        default: break;
    }
}

static void handle_connection(UniqueFd stream, AppContext* context) {
    uint8_t action_val = socket_utils::read_u8(stream);
    auto action = static_cast<DaemonSocketAction>(action_val);

    switch (action) {
        case DaemonSocketAction::CacheMountNamespace: {
            pid_t pid = socket_utils::read_u32(stream);
            context->mount_manager->save_mount_namespace(pid, zygiskd::MountNamespace::Clean);
            context->mount_manager->save_mount_namespace(pid, zygiskd::MountNamespace::Root);
            break;
        }
        case DaemonSocketAction::PingHeartbeat: {
            uint32_t val = constants::ZYGOTE_INJECTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET, &val, sizeof(val));
            break;
        }
        case DaemonSocketAction::ZygoteRestart: {
            LOGI("Zygote restarted, cleaning up companion sockets.");
            for (size_t i = 0; i < context->module_count; ++i) {
                auto module = context->modules[i];
                std::lock_guard<std::mutex> lock(module->companion_mutex);
                if (module->companion_fd >= 0) {
                    module->companion_fd = UniqueFd();
                }
            }
            break;
        }
        case DaemonSocketAction::SystemServerStarted: {
            uint32_t val = constants::SYSTEM_SERVER_STARTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET, &val, sizeof(val));
            break;
        }
        case DaemonSocketAction::GetSharedMemoryFd:
        case DaemonSocketAction::GetZygiskSharedData: {
            if (g_shm_fd >= 0) {
                socket_utils::write_u8(stream, 1);
                socket_utils::send_fd((int)stream, (int)g_shm_fd);
            } else {
                socket_utils::write_u8(stream, 0);
            }
            break;
        }
        default: {
            int raw_fd = stream.release(); 
            spawn_thread([action, raw_fd, context]() {
                UniqueFd thread_stream(raw_fd);
                handle_threaded_action(action, thread_stream, context);
            #ifdef M_PURGE
                // Force the allocator to release cached free memory back to the OS
                // after the companion client disconnects and the thread finishes.
                mallopt(M_PURGE, 0);
            #endif
            });
            break;
        }
    }
}

int main() {
    // Prevent RAM dumping of the daemon
    prctl(PR_SET_DUMPABLE, 0);

    // Anti-debugging (Self-debugging trick)
    // We spawn a dummy child thread that calls PTRACE_TRACEME and sleeps forever.
    // When tools like Frida (or other reverse engineering tools) iterate through
    // /proc/<pid>/task/ to attach to all threads in the process group, they will
    // encounter EBUSY/EPERM when trying to attach to this thread. This graceful
    // trick causes the injection process to fail without the resource overhead of
    // actively proxying signals for the main process.
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    // Use an extremely small 16KB stack size to save RAM since every byte counts.
    pthread_attr_setstacksize(&attr, 16384);
    pthread_t guard_thread;
    pthread_create(&guard_thread, &attr, [](void*) -> void* {
        prctl(PR_SET_NAME, "zygiskd-guard");
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        while (true) pause();
        return nullptr;
    }, nullptr);
    pthread_attr_destroy(&attr);
    pthread_detach(guard_thread);

    // Ignore SIGPIPE to prevent the daemon from crashing if a client disconnects unexpectedly
    signal(SIGPIPE, SIG_IGN);

    // Ignore SIGCHLD to prevent zombie processes when companions exit
    signal(SIGCHLD, SIG_IGN);

    LOGI("Welcome to NeoZygisk (%s) !", ZKSU_VERSION);

    if (!initialize_globals()) {
        return 1;
    }

    spawn_thread([](void*) -> void* {
        shm_refresh_thread();
        return nullptr;
    }, nullptr);

    AppContext* context = new AppContext();
    context->mount_manager = new MountNamespaceManager();
    load_modules(context); 

    send_startup_info(context->modules, context->module_count);

    UniqueFd listener(create_daemon_socket());
    if (listener < 0) {
        return 1;
    }

    LOGI("Daemon listening on %s", DAEMON_SOCKET_PATH);

    while (true) {
        UniqueFd stream = accept(listener, nullptr, nullptr);
        if (stream >= 0) {
            handle_connection(std::move(stream), context);
        } else {
            LOGW("Failed to accept incoming connection");
        }
    }

    return 0;
}

} // namespace zygiskd_main
