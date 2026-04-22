#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "root_impl.hpp"
#include "constants.hpp"
#include "daemon.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace kernelsu {

// --- KernelSU Communication Method Enum & Cached State ---

static ::once_flag ksu_result_flag = 0;
static UniqueFd g_ksu_fd; // RAII safety for the driver FD
static Version g_ksu_version = Version::TooOld;
static bool g_is_detected = false;

static _Atomic(int32_t) g_ksu_manager_uid = -1;
static _Atomic(int64_t) g_ksu_last_stat_time_ms = 0;

static bool (*uid_granted_root_impl)(int32_t) = [](int32_t) { return false; };
static bool (*uid_should_umount_impl)(int32_t) = [](int32_t) { return false; };
static int32_t (*get_manager_uid_impl)() = []() -> int32_t { return -2; };

// --- Modern `ioctl` Interface Constants and Structs ---

constexpr uint32_t KSU_INSTALL_MAGIC1 = 0xDEADBEEF;
constexpr uint32_t KSU_INSTALL_MAGIC2 = 0xCAFEBABE;

constexpr uint32_t KSU_IOCTL_GET_INFO = 0x80004B02;
constexpr uint32_t KSU_IOCTL_UID_GRANTED_ROOT = 0xC0004B08;
constexpr uint32_t KSU_IOCTL_UID_SHOULD_UMOUNT = 0xC0004B09;
constexpr uint32_t KSU_IOCTL_GET_MANAGER_UID = 0x80004B0A;

#pragma pack(push, 1)
struct KsuGetInfoCmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
};

struct KsuUidGrantedRootCmd {
    uint32_t uid;
    uint8_t granted;
};

struct KsuUidShouldUmountCmd {
    uint32_t uid;
    uint8_t should_umount;
};

struct KsuGetManagerUidCmd {
    uint32_t uid;
};
#pragma pack(pop)

// --- Legacy `prctl` Interface Constants ---

constexpr int KERNEL_SU_OPTION = static_cast<int>(0xdeadbeefu);
constexpr size_t CMD_GET_VERSION = 2;
constexpr size_t CMD_UID_GRANTED_ROOT = 12;
constexpr size_t CMD_UID_SHOULD_UMOUNT = 13;
constexpr size_t CMD_GET_MANAGER_UID = 16;
constexpr size_t CMD_HOOK_MODE = 0xC0DEAD1A;

enum class KernelSuVariant { Official, Next };
static KernelSuVariant legacy_variant;
static bool legacy_supports_manager_uid = false;

// --- `ioctl` Implementation Details ---

static int scan_driver_fd() {
    UniqueDir dir(opendir("/proc/self/fd"));
    if (!dir) return -1;

    int dir_fd = dirfd(dir.dir); 
    if (dir_fd < 0) return -1;

    struct dirent* entry;
    char target[256]; 

    while ((entry = readdir(dir.dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        ssize_t len = readlinkat(dir_fd, entry->d_name, target, sizeof(target) - 1);
        
        if (len > 0) {
            target[len] = '\0';
            if (len >= 12 && __builtin_memcmp(target + len - 12, "[ksu_driver]", 12) == 0) {
                return fast_atoi(entry->d_name);
            }
        }
    }
    return -1;
}

static int init_driver_fd() {
    int fd = scan_driver_fd();
    if (fd >= 0) return fd;

    syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd);
    return fd; // Might return -1 if failed
}

template <typename T>
static bool ksuctl_ioctl(int fd, uint32_t request, T* arg) {
    return ioctl(fd, request, arg) >= 0;
}

// --- `prctl` Implementation Details ---

template <typename... Args>
static int ksuctl_prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0, unsigned long arg4 = 0, unsigned long arg5 = 0) {
    return prctl(option, arg2, arg3, arg4, arg5);
}

// Fixed C++ variadic template recursion to avoid compiler garbage
template <typename T>
static unsigned long to_prctl_arg(T arg) {
    return (unsigned long)arg;
}

static void init_legacy_variant_probe() {
    char mode[16] = {0};
    ksuctl_prctl(KERNEL_SU_OPTION, CMD_HOOK_MODE, reinterpret_cast<unsigned long>(mode));
    mode[15] = '\0'; // Safety boundary against kernel leaks
    legacy_variant = (mode[0] != 0) ? KernelSuVariant::Next : KernelSuVariant::Official;
    int result_ok = 0;
    ksuctl_prctl(KERNEL_SU_OPTION, CMD_GET_MANAGER_UID, 0, 0, reinterpret_cast<unsigned long>(&result_ok));
    legacy_supports_manager_uid = (result_ok == KERNEL_SU_OPTION);
}

// --- Split Implementations ---

static bool ioctl_granted_root(int32_t uid) {
    KsuUidGrantedRootCmd cmd = {static_cast<uint32_t>(uid), 0};
    if (ksuctl_ioctl(g_ksu_fd, KSU_IOCTL_UID_GRANTED_ROOT, &cmd)) {
        return cmd.granted != 0;
    }
    return false;
}

static bool prctl_granted_root(int32_t uid) {
    int result_payload = 0;
    uint32_t result_ok = 0;
    ksuctl_prctl(KERNEL_SU_OPTION, CMD_UID_GRANTED_ROOT, static_cast<unsigned long>(uid), 
                 reinterpret_cast<unsigned long>(&result_payload), reinterpret_cast<unsigned long>(&result_ok));
    return (result_ok == static_cast<uint32_t>(KERNEL_SU_OPTION)) && (result_payload != 0);
}

static bool ioctl_should_umount(int32_t uid) {
    KsuUidShouldUmountCmd cmd = {static_cast<uint32_t>(uid), 0};
    if (ksuctl_ioctl(g_ksu_fd, KSU_IOCTL_UID_SHOULD_UMOUNT, &cmd)) {
        return cmd.should_umount != 0;
    }
    return false;
}

static bool prctl_should_umount(int32_t uid) {
    int result_payload = 0;
    uint32_t result_ok = 0;
    ksuctl_prctl(KERNEL_SU_OPTION, CMD_UID_SHOULD_UMOUNT, static_cast<unsigned long>(uid), 
                 reinterpret_cast<unsigned long>(&result_payload), reinterpret_cast<unsigned long>(&result_ok));
    return (result_ok == static_cast<uint32_t>(KERNEL_SU_OPTION)) && (result_payload != 0);
}

static int32_t ioctl_get_manager_uid() {
    KsuGetManagerUidCmd cmd = {0};
    if (ksuctl_ioctl(g_ksu_fd, KSU_IOCTL_GET_MANAGER_UID, &cmd)) {
        return static_cast<int32_t>(cmd.uid);
    }
    return -2;
}

static int32_t prctl_get_manager_uid() {
    if (legacy_supports_manager_uid) {
        uint32_t manager_uid = 0;
        uint32_t result_ok = 0;
        ksuctl_prctl(KERNEL_SU_OPTION, CMD_GET_MANAGER_UID, reinterpret_cast<unsigned long>(&manager_uid), 
                     0, reinterpret_cast<unsigned long>(&result_ok));
        if (result_ok == static_cast<uint32_t>(KERNEL_SU_OPTION)) {
            return static_cast<int32_t>(manager_uid);
        }
    }

    const char* manager_path = (legacy_variant == KernelSuVariant::Official) 
        ? "/data/user_de/0/me.weishu.kernelsu" 
        : "/data/user_de/0/com.rifsxd.ksunext";

    struct stat st;
    if (stat(manager_path, &st) == 0) {
        return static_cast<int32_t>(st.st_uid);
    }
    return -2;
}

// --- Core Detection and Dispatch Logic ---

static void detect_and_init() {
    ::call_once(ksu_result_flag, []() {
        // Wrap the raw integer immediately. If this function exits early,
        // the destructor of local_fd will automatically close the descriptor.
        UniqueFd local_fd(init_driver_fd());
        if (local_fd >= 0) {
            KsuGetInfoCmd cmd = {0, 0, 0};
            // Use the implicit cast operator of UniqueFd to pass the int
            if (ksuctl_ioctl((int)local_fd, KSU_IOCTL_GET_INFO, &cmd)) { 
                int version_code = static_cast<int>(cmd.version);
                if (version_code > 0) {
                    struct stat st;
                    bool ksud_exists = (stat("/data/adb/ksud", &st) == 0);
                    if (version_code >= MIN_KSU_VERSION && ksud_exists) {
                        if (version_code > MAX_KSU_VERSION) {
                            LOGW("Support for current KernelSU (variant) could be incomplete");
                        }
                        // Transfer ownership from local to global.
                        g_ksu_fd = static_cast<UniqueFd&&>(local_fd);
                        
                        g_ksu_version = Version::Supported;
                        uid_granted_root_impl = ioctl_granted_root;
                        uid_should_umount_impl = ioctl_should_umount;
                        get_manager_uid_impl = ioctl_get_manager_uid;
                        g_is_detected = true;
                        return;
                    } else if (version_code < MIN_KSU_VERSION) {
                        g_ksu_version = Version::TooOld;
                        g_is_detected = true;
                        // local_fd falls out of scope here and auto-closes. No manual close() needed!
                        return;
                    }
                }
            }
            // local_fd falls out of scope here and auto-closes. No manual close() needed!
        }

        // Fallback to legacy prctl
        int version_code = 0;
        ksuctl_prctl(KERNEL_SU_OPTION, CMD_GET_VERSION, reinterpret_cast<unsigned long>(&version_code));
        if (version_code > 0) {
            init_legacy_variant_probe();
            struct stat st;
            bool ksud_exists = (stat("/data/adb/ksud", &st) == 0);
            if (version_code >= MIN_KSU_VERSION && ksud_exists) {
                if (version_code > MAX_KSU_VERSION) {
                    LOGW("Support for current KernelSU (variant) could be incomplete");
                }
                g_ksu_version = Version::Supported;
                uid_granted_root_impl = prctl_granted_root;
                uid_should_umount_impl = prctl_should_umount;
                get_manager_uid_impl = prctl_get_manager_uid;
                g_is_detected = true;
                return;
            } else if (version_code < MIN_KSU_VERSION) {
                g_ksu_version = Version::TooOld;
                g_is_detected = true;
                return;
            }
        }
    });
}

Version detect_version() {
    detect_and_init();
    if (g_is_detected) return g_ksu_version;
    return Version::Null;
}

bool uid_granted_root(int32_t uid) { return uid_granted_root_impl(uid); }
bool uid_should_umount(int32_t uid) { return uid_should_umount_impl(uid); }

bool uid_is_manager(int32_t uid, int64_t now_ms) {
    // Memory Barrier pairing (Acquire/Release) to prevent data races
    int64_t last_stat = atomic_load_explicit(&g_ksu_last_stat_time_ms, memory_order_acquire);
    int32_t manager_uid = atomic_load_explicit(&g_ksu_manager_uid, memory_order_relaxed);

    if (manager_uid <= -1 || now_ms - last_stat > 1000) {
        manager_uid = get_manager_uid_impl(); 
        atomic_store_explicit(&g_ksu_manager_uid, manager_uid, memory_order_relaxed);
        atomic_store_explicit(&g_ksu_last_stat_time_ms, now_ms, memory_order_release); // Release pairs with Acquire
    }

    if (manager_uid < 0) return false;
    return static_cast<int32_t>(uid) == manager_uid;
}

bool uid_is_manager(int32_t uid) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    return uid_is_manager(uid, now_ms);
}

} // namespace kernelsu

