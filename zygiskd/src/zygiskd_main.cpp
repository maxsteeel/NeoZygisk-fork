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
    std::string name;
    UniqueFd lib_fd;
    std::mutex companion_mutex;
    UniqueFd companion_fd;

    Module() = default;   
};

struct AppContext {
    std::vector<std::unique_ptr<Module>> modules;
    std::shared_ptr<MountNamespaceManager> mount_manager;
};

static std::string TMP_PATH;
static std::string CONTROLLER_SOCKET;
static std::string DAEMON_SOCKET_PATH;

static UniqueFd g_shm_fd;
static constants::ZygiskSharedData* g_shm_base = nullptr;
static std::mutex g_shm_write_mutex;

static bool initialize_globals() {
    const char* tmp = getenv("TMP_PATH");
    if (!tmp) {
        LOGE("TMP_PATH environment variable not set");
        return false;
    }
    TMP_PATH = tmp;

    CONTROLLER_SOCKET = TMP_PATH + "/init_monitor";
    DAEMON_SOCKET_PATH = LP_SELECT("cp32.sock", "cp64.sock");

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

static bool send_startup_info(const std::vector<std::unique_ptr<Module>>& modules) {
    std::vector<uint8_t> msg;

    auto root = root_impl::get();
    std::string info;

    if (root == root_impl::RootImpl::APatch || root == root_impl::RootImpl::KernelSU || root == root_impl::RootImpl::Magisk) {
        uint32_t magic = constants::DAEMON_SET_INFO;
        msg.insert(msg.end(), reinterpret_cast<uint8_t*>(&magic), reinterpret_cast<uint8_t*>(&magic) + 4);

        std::string root_name;
        if (root == root_impl::RootImpl::APatch) root_name = "APatch";
        else if (root == root_impl::RootImpl::KernelSU) root_name = "KernelSU";
        else if (root == root_impl::RootImpl::Magisk) root_name = "Magisk";

        if (!modules.empty()) {
            info = "\t\tRoot: " + root_name + "\n\t\tModules (" + std::to_string(modules.size()) + "):\n\t\t\t";
            for (size_t i = 0; i < modules.size(); ++i) {
                info += modules[i]->name;
                if (i != modules.size() - 1) info += "\n\t\t\t";
            }
        } else {
            info = "\t\tRoot: " + root_name;
        }
    } else {
        uint32_t magic = constants::DAEMON_SET_ERROR_INFO;
        msg.insert(msg.end(), reinterpret_cast<uint8_t*>(&magic), reinterpret_cast<uint8_t*>(&magic) + 4);
        info = "\t\tInvalid root implementation.";
    }

    uint32_t len = info.size() + 1;
    msg.insert(msg.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
    msg.insert(msg.end(), info.begin(), info.end());
    msg.push_back('\0');

    return utils::unix_datagram_sendto(CONTROLLER_SOCKET.c_str(), msg.data(), msg.size());
}

static std::string get_arch() {
    std::string system_arch = utils::get_property("ro.product.cpu.abi");
    if (system_arch.find("arm") != std::string::npos) {
        return LP_SELECT("armeabi-v7a", "arm64-v8a");
    } else if (system_arch.find("x86") != std::string::npos) {
        return LP_SELECT("x86", "x86_64");
    }
    return "";
}

static int create_library_fd(const char* so_path) {
    UniqueFd memfd(memfd_create("zygisk-module", MFD_ALLOW_SEALING | MFD_CLOEXEC));
    if (memfd < 0) {
        PLOGE("memfd_create");
        return -1;
    }

    UniqueFd file_fd(open(so_path, O_RDONLY | O_CLOEXEC));
    if (file_fd < 0) {
        PLOGE("open %s", so_path);
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

    return memfd.release();
}

static std::vector<std::unique_ptr<Module>> load_modules() {
    std::string arch = get_arch();
    std::vector<std::unique_ptr<Module>> modules;

    if (arch.empty()) {
        LOGE("Unsupported system architecture");
        return modules;
    }

    LOGD("Daemon architecture: %s", arch.c_str());

    UniqueDir dir(opendir(constants::PATH_MODULES_DIR));
    if (!dir) {
        LOGW("Failed to read modules directory %s", constants::PATH_MODULES_DIR);
        return modules;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        char disable_path[256];
        snprintf(disable_path, sizeof(disable_path), "%s/%s/disable", constants::PATH_MODULES_DIR, entry->d_name);
        struct stat st;
        if (stat(disable_path, &st) == 0) continue; // Disabled

        char so_path[256];
        snprintf(so_path, sizeof(so_path), "%s/%s/zygisk/%s.so", constants::PATH_MODULES_DIR, entry->d_name, arch.c_str());
        if (stat(so_path, &st) != 0) continue; // No so file

        LOGI("Loading module `%s`...", entry->d_name);
        int lib_fd = create_library_fd(so_path);
        if (lib_fd >= 0) {
            auto mod = std::make_unique<Module>();
            mod->name = entry->d_name;
            mod->lib_fd = lib_fd;
            modules.push_back(std::move(mod));
        } else {
            LOGW("Failed to create memfd for `%s`", entry->d_name);
        }
    }

    return modules;
}

static int create_daemon_socket() {
    UniqueFd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (fd < 0) return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, DAEMON_SOCKET_PATH.c_str(), sizeof(addr.sun_path) - 2);

    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + DAEMON_SOCKET_PATH.size() + 1;

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) {
        PLOGE("bind");
        return -1;
    }

    if (listen(fd, 10) < 0) {
        PLOGE("listen");
        return -1;
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
        execv(self_exe, const_cast<char**>(argv));
        PLOGE("execv");
        _exit(1);
    }

    // Parent
    companion_sock = UniqueFd();

    // Now, establish communication with the newly spawned companion.
    socket_utils::write_string(daemon_sock, name);
    // Use write_u8 to mimic rust code passing fd and write logic correctly

    // send_fd is needed here, need to implement send_fd.
    // However, existing socket_utils.hpp does not have send_fd!
    // Wait, loader socket_utils only implements recv_fd because the injector only receives.
    // I need to implement send_fd.

    return daemon_sock.release(); // We will handle send_fd locally in a bit
}

// Implement send_fd
static bool send_fd(int sockfd, int fd) {
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    int dummy_data = 0;
    struct iovec iov = {&dummy_data, sizeof(dummy_data)};
    struct msghdr msg = {
        nullptr, 0,
        &iov, 1,
        cmsgbuf, sizeof(cmsgbuf),
        0
    };

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ssize_t sent = sendmsg(sockfd, &msg, 0);
    if (sent != sizeof(dummy_data)) {
        PLOGE("send_fd: sendmsg failed");
        return false;
    }
    return true;
}

// Wait, the above spawn_companion needs to be refactored to use this
static int spawn_companion_complete(const char* name, int lib_fd) {
    UniqueFd daemon_sock(spawn_companion(name));
    if (daemon_sock < 0) return -1;
    if (!send_fd(daemon_sock, lib_fd))  return -1;

    uint8_t status = socket_utils::read_u8(daemon_sock);
    if (status == 1) return daemon_sock.release();

    return -1;
}


static void handle_get_process_flags(int stream) {
    int32_t uid = socket_utils::read_u32(stream);
    ProcessFlags flags = ProcessFlags::NONE;

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
    socket_utils::write_u32(stream, flags_val);

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
}

static void handle_update_mount_namespace(int stream, AppContext* context) {
    uint8_t type_val = socket_utils::read_u8(stream);
    zygiskd::MountNamespace ns_type = (type_val == 0) ? zygiskd::MountNamespace::Clean : zygiskd::MountNamespace::Root;

    int fd = context->mount_manager->get_namespace_fd(ns_type);
    if (fd >= 0) {
        socket_utils::write_u8(stream, 1);
        send_fd(stream, fd);
    } else {
        LOGW("Namespace is not cached yet.");
        socket_utils::write_u8(stream, 0);
    }
}

static void handle_read_modules(int stream, AppContext* context) {
    socket_utils::write_usize(stream, context->modules.size());
    for (const auto& module : context->modules) {
        socket_utils::write_string(stream, module->name);
        send_fd(stream, module->lib_fd);
    }
}

static void handle_request_companion_socket(int stream, AppContext* context) {
    size_t index = socket_utils::read_usize(stream);
    if (index >= context->modules.size()) {
        socket_utils::write_u8(stream, 0);
        return;
    }

    auto& module = context->modules[index];
    std::lock_guard<std::mutex> lock(module->companion_mutex);

    if (module->companion_fd >= 0) {
        if (!utils::is_socket_alive(module->companion_fd)) {
            LOGE("Companion for module `%s` appears to have crashed.", module->name.c_str());
            module->companion_fd = UniqueFd();
        }
    }

    if (module->companion_fd < 0) {
        int sock = spawn_companion_complete(module->name.c_str(), module->lib_fd);
        if (sock >= 0) {
            LOGV("Spawned new companion for `%s`.", module->name.c_str());
            module->companion_fd = UniqueFd(sock);
        } else {
            LOGW("Module `%s` does not have a companion entry point or failed.", module->name.c_str());
        }
    }

    if (module->companion_fd >= 0) {
        if (!send_fd(module->companion_fd, stream)) {
            LOGE("Failed to send companion socket FD for module `%s`", module->name.c_str());
            socket_utils::write_u8(stream, 0);
        }
    } else {
        socket_utils::write_u8(stream, 0);
    }
}

static void handle_get_module_dir(int stream, AppContext* context) {
    size_t index = socket_utils::read_usize(stream);
    if (index >= context->modules.size()) return;
    auto& module = context->modules[index];
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "%s/%s", constants::PATH_MODULES_DIR, module->name.c_str());
    UniqueFd dir_fd(open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (dir_fd >= 0) send_fd(stream, dir_fd);
}


static void handle_threaded_action(DaemonSocketAction action, int stream, std::shared_ptr<AppContext> context) {
    switch (action) {
        case DaemonSocketAction::GetProcessFlags: handle_get_process_flags(stream); break;
        case DaemonSocketAction::UpdateMountNamespace: handle_update_mount_namespace(stream, context.get()); break;
        case DaemonSocketAction::ReadModules: handle_read_modules(stream, context.get()); break;
        case DaemonSocketAction::RequestCompanionSocket: handle_request_companion_socket(stream, context.get()); break;
        case DaemonSocketAction::GetModuleDir: handle_get_module_dir(stream, context.get()); break;
        default: break;
    }
}

static void handle_connection(UniqueFd stream, std::shared_ptr<AppContext> context) {
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
            utils::unix_datagram_sendto(CONTROLLER_SOCKET.c_str(), &val, sizeof(val));
            break;
        }
        case DaemonSocketAction::ZygoteRestart: {
            LOGI("Zygote restarted, cleaning up companion sockets.");
            for (auto& module : context->modules) {
                std::lock_guard<std::mutex> lock(module->companion_mutex);
                if (module->companion_fd >= 0) {
                    module->companion_fd = UniqueFd();
                }
            }
            break;
        }
        case DaemonSocketAction::SystemServerStarted: {
            uint32_t val = constants::SYSTEM_SERVER_STARTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET.c_str(), &val, sizeof(val));
            break;
        }
        case DaemonSocketAction::GetSharedMemoryFd:
        case DaemonSocketAction::GetZygiskSharedData: {
            if (g_shm_fd >= 0) {
                socket_utils::write_u8(stream, 1);
                send_fd((int)stream, (int)g_shm_fd);
            } else {
                socket_utils::write_u8(stream, 0);
            }
            break;
        }
        default: {
            int raw_fd = stream.release(); 
            std::thread([action, raw_fd, context]() {
                UniqueFd thread_stream(raw_fd);
                handle_threaded_action(action, thread_stream, context);
            }).detach();
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

    auto modules = load_modules();
    send_startup_info(modules);

    auto context = std::make_shared<AppContext>();
    context->modules = std::move(modules);
    context->mount_manager = std::make_shared<MountNamespaceManager>();

    UniqueFd listener(create_daemon_socket());
    if (listener < 0) {
        return 1;
    }

    LOGI("Daemon listening on %s", DAEMON_SOCKET_PATH.c_str());

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
