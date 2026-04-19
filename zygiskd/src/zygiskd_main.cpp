#include "main.hpp"

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
#include <cerrno>
#include <csignal>

#include <sys/mman.h>
#include <linux/memfd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <limits.h> // For PTHREAD_STACK_MIN

#include "logging.hpp"
#include "constants.hpp"
#include "socket_utils.hpp"
#include "utils.hpp"
#include "mount.hpp"
#include "root_impl.hpp"
#include "daemon.hpp" 

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_SEAL_SEAL     0x0001
#define F_SEAL_SHRINK   0x0002
#define F_SEAL_GROW     0x0004
#define F_SEAL_WRITE    0x0008
#endif

namespace zygiskd_main {

using constants::DaemonSocketAction;
using constants::ProcessFlags;
using zygisk_mount::MountNamespaceManager;

struct Module {
    char name[256];
    UniqueFd lib_fd;
    pthread_mutex_t companion_mutex = PTHREAD_MUTEX_INITIALIZER;
    UniqueFd companion_fd;
};

#define MAX_MODULES 32
struct AppContext {
    Module modules[MAX_MODULES];
    size_t module_count = 0;
    MountNamespaceManager mount_manager;
};

struct ThreadPayload {
    DaemonSocketAction action;
    int raw_fd;
    AppContext* context;
};

static const char* const DAEMON_SOCKET_PATH = LP_SELECT("cp32.sock", "cp64.sock");
static UniqueFd g_shm_fd;
static constants::ZygiskSharedData* g_shm_base = nullptr;

static pthread_mutex_t g_shm_write_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_refresh_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_refresh_cv = PTHREAD_COND_INITIALIZER;
static bool g_needs_refresh = false;

static void trigger_shm_refresh() {
    pthread_mutex_lock(&g_refresh_mutex);
    g_needs_refresh = true;
    pthread_cond_signal(&g_refresh_cv);
    pthread_mutex_unlock(&g_refresh_mutex);
}

static bool initialize_globals() {
    int raw_fd = syscall(SYS_memfd_create, "zygisk-shm", MFD_ALLOW_SEALING | MFD_CLOEXEC);
    if (raw_fd < 0) {
        PLOGE("memfd_create zygisk-shm failed");
        return false;
    }
    g_shm_fd = UniqueFd(raw_fd);

    if (ftruncate(g_shm_fd, sizeof(constants::ZygiskSharedData)) < 0) return false;

    int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    fcntl(g_shm_fd, F_ADD_SEALS, seals);

    g_shm_base = static_cast<constants::ZygiskSharedData*>(mmap(nullptr, sizeof(constants::ZygiskSharedData), PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0));
    if (g_shm_base == MAP_FAILED) return false;

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

static void* shm_refresh_thread(void*) {
    prctl(PR_SET_NAME, "zygiskd-refresh");

    while (true) {
        pthread_mutex_lock(&g_refresh_mutex);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10; 
        while (!g_needs_refresh) {
            if (pthread_cond_timedwait(&g_refresh_cv, &g_refresh_mutex, &ts) == ETIMEDOUT) break;
        }
        g_needs_refresh = false;
        pthread_mutex_unlock(&g_refresh_mutex);

        if (!g_shm_base) continue;
        
        root_impl::refresh_cache();

        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t now_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
        bool changed = false;

        for (size_t i = 0; i < constants::SHM_HASH_MAP_SIZE; ++i) {
            uint32_t uid = g_shm_base->entries[i].uid.load(std::memory_order_relaxed);
            if (uid == UINT32_MAX) continue;

            ProcessFlags new_flags = ProcessFlags::NONE;
            if (root_impl::uid_is_manager(uid, now_ms)) {
                new_flags |= ProcessFlags::PROCESS_IS_MANAGER;
            } else {
                if (root_impl::uid_granted_root(uid)) new_flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
                if (root_impl::uid_should_umount(uid)) new_flags |= ProcessFlags::PROCESS_ON_DENYLIST;
            }

            uint32_t new_val = static_cast<uint32_t>(new_flags);
            uint32_t old_val = g_shm_base->entries[i].flags.load(std::memory_order_relaxed);

            if (new_val != old_val) {
                pthread_mutex_lock(&g_shm_write_mutex);
                uint32_t current_ver = g_shm_base->version.load(std::memory_order_relaxed);
                g_shm_base->version.store(current_ver + 1, std::memory_order_release);
                g_shm_base->entries[i].flags.store(new_val, std::memory_order_relaxed);
                g_shm_base->version.store(current_ver + 2, std::memory_order_release);
                pthread_mutex_unlock(&g_shm_write_mutex);
                changed = true;
            }
        }
        if (changed) LOGD("Refresh thread updated process flags.");
    }
    return nullptr;
}

static void send_startup_info(AppContext* context) {
    uint8_t msg[1024]; 
    memset(msg, 0, sizeof(msg));

    uint32_t* magic_ptr = reinterpret_cast<uint32_t*>(msg);
    char* info_ptr = reinterpret_cast<char*>(msg + 8);
    size_t max_info_sz = sizeof(msg) - 8 - 1;
    int written = 0;

    auto root = root_impl::get();
    const char* root_name = (root == root_impl::RootImpl::APatch) ? "APatch" :
                            (root == root_impl::RootImpl::KernelSU) ? "KernelSU" :
                            (root == root_impl::RootImpl::Magisk) ? "Magisk" : "Unknown";

    if (strcmp(root_name, "Unknown") == 0) {
        *magic_ptr = constants::DAEMON_SET_ERROR_INFO;
        written = snprintf(info_ptr, max_info_sz, "\t\tInvalid root implementation.");
    } else {
        *magic_ptr = constants::DAEMON_SET_INFO;
        written = snprintf(info_ptr, max_info_sz, "\t\tRoot: %s", root_name);
        if (context->module_count > 0) {
            written += snprintf(info_ptr + written, max_info_sz - written, "\n\t\tModules (%zu):\n\t\t\t", context->module_count);
            for (size_t i = 0; i < context->module_count; ++i) {
                written += snprintf(info_ptr + written, max_info_sz - written, "%s", context->modules[i].name);
                if (i != context->module_count - 1) written += snprintf(info_ptr + written, max_info_sz - written, "\n\t\t\t");
                if (written >= static_cast<int>(max_info_sz) - 10) break; 
            }
        }
    }

    uint32_t text_len = static_cast<uint32_t>(written) + 1;
    memcpy(msg + 4, &text_len, 4);
    utils::unix_datagram_sendto("init_monitor", msg, 8 + text_len);
}

static int create_library_fd(int raw_file_fd) {
    UniqueFd file_fd(raw_file_fd);
    int raw_memfd = syscall(SYS_memfd_create, "zygisk-module", MFD_ALLOW_SEALING | MFD_CLOEXEC);
    if (raw_memfd < 0) return -1;
    UniqueFd memfd(raw_memfd);

    struct stat st;
    if (fstat(file_fd, &st) < 0) return -1;

    off_t offset = 0;
    while (offset < st.st_size) {
        ssize_t res = sendfile(memfd, file_fd, &offset, st.st_size - offset);
        if (res <= 0) return -1;
    }

    int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
    fcntl(memfd, F_ADD_SEALS, seals);
    fchmod(memfd, S_IRUSR | S_IRGRP | S_IROTH);

    return memfd.release();
}

static void load_modules(AppContext* context) {
    char abi[PROP_VALUE_MAX];
    if (__system_property_get("ro.product.cpu.abi", abi) <= 0) return;
    const char* arch = strstr(abi, "arm") ? LP_SELECT("armeabi-v7a", "arm64-v8a") : 
                       strstr(abi, "x86") ? LP_SELECT("x86", "x86_64") : "";
    if (arch[0] == '\0') return;

    LOGD("Daemon architecture: %s", arch);

    int dir_fd = open(constants::PATH_MODULES_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) return;

    UniqueDir dir(fdopendir(dir_fd));
    if (!dir) {
        close(dir_fd);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        if (context->module_count >= MAX_MODULES) break;

        char path[256];
        snprintf(path, sizeof(path), "%s/disable", entry->d_name);
        if (faccessat(dir_fd, path, F_OK, 0) == 0) continue; 

        snprintf(path, sizeof(path), "%s/zygisk/%s.so", entry->d_name, arch);
        int raw_file_fd = openat(dir_fd, path, O_RDONLY | O_CLOEXEC);
        if (raw_file_fd < 0) continue;

        int lib_fd = create_library_fd(raw_file_fd);
        if (lib_fd >= 0) {
            LOGI("Loading module `%s`...", entry->d_name);
            Module& mod = context->modules[context->module_count++];
            strlcpy(mod.name, entry->d_name, sizeof(mod.name));
            mod.lib_fd = UniqueFd(lib_fd);
            // companion_mutex and companion_fd are already initialized safely
        }
    }
}

static int create_daemon_socket() {
    UniqueFd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (fd < 0) return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strlcpy(addr.sun_path + 1, DAEMON_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(DAEMON_SOCKET_PATH) + 1;
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0 || listen(fd, 10) < 0) {
        _exit(1);
    }
    return fd.release();
}

static int spawn_companion(const char* name) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) return -1;

    UniqueFd daemon_sock(pair[0]);
    UniqueFd companion_sock(pair[1]);

    char self_exe[256];
    ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (len < 0) return -1;
    self_exe[len] = '\0';

    const char* base_name = strrchr(self_exe, '/');
    base_name = base_name ? base_name + 1 : "zygiskd";

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        daemon_sock = UniqueFd();
        fcntl(companion_sock, F_SETFD, fcntl(companion_sock, F_GETFD) & ~FD_CLOEXEC);

        char arg0[256], fd_str[32];
        snprintf(arg0, sizeof(arg0), "%s-%s", base_name, name);
        snprintf(fd_str, sizeof(fd_str), "%d", (int)companion_sock);

        const char* argv[] = {arg0, "companion", fd_str, nullptr};
        execv(self_exe, const_cast<char**>(argv));
        _exit(1);
    }

    companion_sock = UniqueFd();
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

    if (root_impl::uid_is_manager(uid)) flags |= ProcessFlags::PROCESS_IS_MANAGER;
    else {
        if (root_impl::uid_granted_root(uid)) flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
        if (root_impl::uid_should_umount(uid)) flags |= ProcessFlags::PROCESS_ON_DENYLIST;
    }

    auto root = root_impl::get();
    if (root == root_impl::RootImpl::APatch) flags |= ProcessFlags::PROCESS_ROOT_IS_APATCH;
    else if (root == root_impl::RootImpl::KernelSU) flags |= ProcessFlags::PROCESS_ROOT_IS_KSU;
    else if (root == root_impl::RootImpl::Magisk) flags |= ProcessFlags::PROCESS_ROOT_IS_MAGISK;

    uint32_t flags_val = static_cast<uint32_t>(flags);

    if (g_shm_base) {
        pthread_mutex_lock(&g_shm_write_mutex);
        size_t index = uid % constants::SHM_HASH_MAP_SIZE;
        size_t start_index = index;

        uint32_t current_version = g_shm_base->version.load(std::memory_order_relaxed);
        if (current_version % 2 == 0) g_shm_base->version.store(current_version + 1, std::memory_order_release);

        do {
            uint32_t current_uid = g_shm_base->entries[index].uid.load(std::memory_order_relaxed);
            if (current_uid == UINT32_MAX || current_uid == 0 || current_uid == static_cast<uint32_t>(uid)) {
                g_shm_base->entries[index].uid.store(uid, std::memory_order_relaxed);
                g_shm_base->entries[index].flags.store(flags_val, std::memory_order_relaxed);
                break;
            }
            index = (index + 1) % constants::SHM_HASH_MAP_SIZE;
        } while (index != start_index);

        g_shm_base->version.store(g_shm_base->version.load(std::memory_order_relaxed) + 1, std::memory_order_release);
        pthread_mutex_unlock(&g_shm_write_mutex);
    }

    socket_utils::write_u32(stream, flags_val);
}

static void* threaded_action_handler(void* arg) {
    ThreadPayload payload = *static_cast<ThreadPayload*>(arg);
    free(arg);

    UniqueFd thread_stream(payload.raw_fd);
    AppContext* context = payload.context;

    switch (payload.action) {
        case DaemonSocketAction::GetProcessFlags: handle_get_process_flags(thread_stream); break;
        case DaemonSocketAction::UpdateMountNamespace: {
            auto ns_type = (socket_utils::read_u8(thread_stream) == 0) ? zygiskd::MountNamespace::Clean : zygiskd::MountNamespace::Root;
            int fd = context->mount_manager.get_namespace_fd(ns_type);
            socket_utils::write_u8(thread_stream, fd >= 0 ? 1 : 0);
            if (fd >= 0) socket_utils::send_fd(thread_stream, fd);
            break;
        }
        case DaemonSocketAction::ReadModules: {
            socket_utils::write_usize(thread_stream, context->module_count);
            for (size_t i = 0; i < context->module_count; ++i) {
                socket_utils::write_string(thread_stream, context->modules[i].name);
                socket_utils::send_fd(thread_stream, context->modules[i].lib_fd);
            }
            break;
        }
        case DaemonSocketAction::RequestCompanionSocket: {
            size_t index = socket_utils::read_usize(thread_stream);
            if (index >= context->module_count) {
                socket_utils::write_u8(thread_stream, 0);
                break;
            }
            Module& module = context->modules[index];
            pthread_mutex_lock(&module.companion_mutex);
            if (module.companion_fd >= 0 && !utils::is_socket_alive(module.companion_fd)) {
                module.companion_fd = UniqueFd();
            }
            if (module.companion_fd < 0) {
                int sock = spawn_companion_complete(module.name, module.lib_fd);
                if (sock >= 0) module.companion_fd = UniqueFd(sock);
            }
            bool sent = (module.companion_fd >= 0) && socket_utils::send_fd(module.companion_fd, thread_stream);
            pthread_mutex_unlock(&module.companion_mutex);
            if (!sent) socket_utils::write_u8(thread_stream, 0);
            break;
        }
        case DaemonSocketAction::GetModuleDir: {
            size_t index = socket_utils::read_usize(thread_stream);
            if (index < context->module_count) {
                char dir_path[256];
                snprintf(dir_path, sizeof(dir_path), "%s/%s", constants::PATH_MODULES_DIR, context->modules[index].name);
                UniqueFd dir_fd(open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
                if (dir_fd >= 0) socket_utils::send_fd(thread_stream, dir_fd);
            }
            break;
        }
        case DaemonSocketAction::ReportModuleCrash: {
            size_t index = socket_utils::read_usize(thread_stream);
            if (index < context->module_count) {
                char disable_path[256];
                snprintf(disable_path, sizeof(disable_path), "%s/%s/disable", constants::PATH_MODULES_DIR, context->modules[index].name);
                int fd = open(disable_path, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
                if (fd >= 0) close(fd);
            }
            break;
        }
        default: break;
    }
#ifdef M_PURGE
    mallopt(M_PURGE, 0);
#endif
    return nullptr;
}

static void handle_connection(UniqueFd stream, AppContext* context) {
    auto action = static_cast<DaemonSocketAction>(socket_utils::read_u8(stream));

    switch (action) {
        case DaemonSocketAction::CacheMountNamespace: {
            pid_t pid = socket_utils::read_u32(stream);
            context->mount_manager.save_mount_namespace(pid, zygiskd::MountNamespace::Clean);
            context->mount_manager.save_mount_namespace(pid, zygiskd::MountNamespace::Root);
            break;
        }
        case DaemonSocketAction::PingHeartbeat: {
            uint32_t val = constants::ZYGOTE_INJECTED;
            utils::unix_datagram_sendto("init_monitor", &val, sizeof(val));
            break;
        }
        case DaemonSocketAction::ZygoteRestart: {
            for (size_t i = 0; i < context->module_count; ++i) {
                Module& module = context->modules[i];
                pthread_mutex_lock(&module.companion_mutex);
                module.companion_fd = UniqueFd();
                pthread_mutex_unlock(&module.companion_mutex);
            }
            break;
        }
        case DaemonSocketAction::SystemServerStarted: {
            uint32_t val = constants::SYSTEM_SERVER_STARTED;
            utils::unix_datagram_sendto("init_monitor", &val, sizeof(val));
            break;
        }
        case DaemonSocketAction::GetSharedMemoryFd:
        case DaemonSocketAction::GetZygiskSharedData: {
            trigger_shm_refresh();
            if (g_shm_fd >= 0) {
                socket_utils::write_u8(stream, 1);
                socket_utils::send_fd((int)stream, (int)g_shm_fd);
            } else {
                socket_utils::write_u8(stream, 0);
            }
            break;
        }
        default: {
            ThreadPayload* payload = static_cast<ThreadPayload*>(malloc(sizeof(ThreadPayload)));
            if (payload) {
                payload->action = action;
                payload->raw_fd = stream.release(); 
                payload->context = context;
                spawn_thread(threaded_action_handler, payload);
            }
            break;
        }
    }
}

int main() {
    prctl(PR_SET_DUMPABLE, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t min_stack = PTHREAD_STACK_MIN < 16384 ? 16384 : PTHREAD_STACK_MIN;
    pthread_attr_setstacksize(&attr, min_stack);

    pthread_t guard_thread;
    pthread_create(&guard_thread, &attr, [](void*) -> void* {
        prctl(PR_SET_NAME, "zygiskd-guard");
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        while (true) pause();
        return nullptr;
    }, nullptr);
    pthread_attr_destroy(&attr);
    pthread_detach(guard_thread);

    LOGI("Welcome to NeoZygisk (%s) !", ZKSU_VERSION);

    if (!initialize_globals()) return 1;

    spawn_thread(shm_refresh_thread, nullptr);

    AppContext* context = new AppContext();
    load_modules(context); 

    send_startup_info(context);

    UniqueFd listener(create_daemon_socket());
    if (listener < 0) return 1;

    LOGI("Daemon listening on %s", DAEMON_SOCKET_PATH);

    while (true) {
        UniqueFd stream = accept(listener, nullptr, nullptr);
        if (stream >= 0) handle_connection(static_cast<UniqueFd&&>(stream), context);
    }

    return 0;
}

} // namespace zygiskd_main
