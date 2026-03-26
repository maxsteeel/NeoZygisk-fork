#include "kernelsu.hpp"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <mutex>

#include "constants.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace kernelsu {

// --- KernelSU Communication Method Enum & Cached State ---

static std::once_flag ksu_result_flag;
static int g_ksu_fd = -1;
static std::optional<Version> g_ksu_version;
static std::atomic<int32_t> g_ksu_manager_uid{-1};
static std::atomic<int64_t> g_ksu_last_stat_time_ms{0};

static bool (*uid_granted_root_impl)(int32_t) = [](int32_t) { return false; };
static bool (*uid_should_umount_impl)(int32_t) = [](int32_t) { return false; };
static int32_t (*get_manager_uid_impl)() = []() -> int32_t { return -2; };

// --- Modern `ioctl` Interface Constants and Structs ---

constexpr uint32_t KSU_INSTALL_MAGIC1 = 0xDEADBEEF;
constexpr uint32_t KSU_INSTALL_MAGIC2 = 0xCAFEBABE;

constexpr uint32_t KSU_IOCTL_GET_INFO = 0x80004B02;          // nr=2, dir=R
constexpr uint32_t KSU_IOCTL_UID_GRANTED_ROOT = 0xC0004B08;  // nr=8, dir=RW
constexpr uint32_t KSU_IOCTL_UID_SHOULD_UMOUNT = 0xC0004B09; // nr=9, dir=RW
constexpr uint32_t KSU_IOCTL_GET_MANAGER_UID = 0x80004B0A;   // nr=10, dir=R

#pragma pack(push, 1)

struct KsuGetInfoCmd {
    uint32_t version;
    [[maybe_unused]] uint32_t flags;
    [[maybe_unused]] uint32_t features;
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

static std::once_flag legacy_variant_flag;
static KernelSuVariant legacy_variant;
static bool legacy_supports_manager_uid;

// --- `ioctl` Implementation Details ---

static std::optional<int> scan_driver_fd() {
    UniqueDir dir(opendir("/proc/self/fd"));
    if (!dir) return std::nullopt;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        char target[256];
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            if (strstr(target, "[ksu_driver]")) {
                return std::stoi(entry->d_name);
            }
        }
    }

    return std::nullopt;
}

static std::optional<int> init_driver_fd() {
    if (auto fd = scan_driver_fd()) {
        return fd;
    }

    int fd = -1;
    syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd);
    if (fd >= 0) {
        return fd;
    }
    return std::nullopt;
}

template <typename T>
static bool ksuctl_ioctl(int fd, uint32_t request, T* arg) {
    int ret = ioctl(fd, request, arg);
    return ret >= 0;
}

// --- `prctl` Implementation Details ---

template <typename T>
static unsigned long to_prctl_arg(T arg) {
    if constexpr (std::is_pointer_v<T>) {
        return reinterpret_cast<unsigned long>(arg);
    } else {
        return static_cast<unsigned long>(arg);
    }
}

template <typename... Args>
static int ksuctl_prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0, unsigned long arg4 = 0,
                        unsigned long arg5 = 0) {
    return prctl(option, arg2, arg3, arg4, arg5);
}

template <typename T1, typename... Args>
static int ksuctl_prctl(int option, T1 arg2, Args... args) {
    return ksuctl_prctl(option, to_prctl_arg(arg2), to_prctl_arg(args)...);
}

static void init_legacy_variant_probe() {
    std::call_once(legacy_variant_flag, []() {
        char mode[16] = {0};
        ksuctl_prctl(KERNEL_SU_OPTION, CMD_HOOK_MODE, mode);
        if (mode[0] != 0) {
            legacy_variant = KernelSuVariant::Next;
        } else {
            legacy_variant = KernelSuVariant::Official;
        }

        int result_ok = 0;
        ksuctl_prctl(KERNEL_SU_OPTION, CMD_GET_MANAGER_UID, 0, 0, &result_ok);
        legacy_supports_manager_uid = (result_ok == KERNEL_SU_OPTION);
    });
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
    ksuctl_prctl(KERNEL_SU_OPTION, CMD_UID_GRANTED_ROOT, uid, &result_payload, &result_ok);
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
    ksuctl_prctl(KERNEL_SU_OPTION, CMD_UID_SHOULD_UMOUNT, uid, &result_payload, &result_ok);
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
        ksuctl_prctl(KERNEL_SU_OPTION, CMD_GET_MANAGER_UID, &manager_uid, 0, &result_ok);
        if (result_ok == static_cast<uint32_t>(KERNEL_SU_OPTION)) {
            return static_cast<int32_t>(manager_uid);
        }
    }

    const char* manager_path = nullptr;
    if (legacy_variant == KernelSuVariant::Official) {
        manager_path = "/data/user_de/0/me.weishu.kernelsu";
    } else if (legacy_variant == KernelSuVariant::Next) {
        manager_path = "/data/user_de/0/com.rifsxd.ksunext";
    } else {
        return -2;
    }

    struct stat st;
    if (stat(manager_path, &st) == 0) {
        return static_cast<int32_t>(st.st_uid);
    }
    return -2;
}

// --- Core Detection and Dispatch Logic ---

static void detect_and_init() {
    std::call_once(ksu_result_flag, []() {
        if (auto fd_opt = init_driver_fd()) {
            int fd = fd_opt.value();
            KsuGetInfoCmd cmd = {0, 0, 0};
            if (ksuctl_ioctl(fd, KSU_IOCTL_GET_INFO, &cmd)) {
                (void)cmd.flags; (void)cmd.features;
                int version_code = static_cast<int>(cmd.version);
                if (version_code > 0) {
                    struct stat st;
                    bool ksud_exists = (stat("/data/adb/ksud", &st) == 0);
                    if (version_code >= MIN_KSU_VERSION && ksud_exists) {
                        if (version_code > MAX_KSU_VERSION) {
                            LOGW("Support for current KernelSU (variant) could be incomplete");
                        }
                        g_ksu_fd = fd;
                        g_ksu_version = Version::Supported;
                        uid_granted_root_impl = ioctl_granted_root;
                        uid_should_umount_impl = ioctl_should_umount;
                        get_manager_uid_impl = ioctl_get_manager_uid;
                        return;
                    } else if (version_code < MIN_KSU_VERSION) {
                        g_ksu_fd = fd;
                        g_ksu_version = Version::TooOld;
                        return;
                    }
                }
            }
        }

        int version_code = 0;
        ksuctl_prctl(KERNEL_SU_OPTION, CMD_GET_VERSION, &version_code);
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
                return;
            } else if (version_code < MIN_KSU_VERSION) {
                g_ksu_version = Version::TooOld;
                return;
            }
        }
    });
}

std::optional<Version> detect_version() {
    detect_and_init();
    return g_ksu_version;
}

bool uid_granted_root(int32_t uid) {
    return uid_granted_root_impl(uid);
}

bool uid_should_umount(int32_t uid) {
    return uid_should_umount_impl(uid);
}

bool uid_is_manager(int32_t uid, int64_t now_ms) {
    int32_t manager_uid = g_ksu_manager_uid.load(std::memory_order_relaxed);
    int64_t last_stat = g_ksu_last_stat_time_ms.load(std::memory_order_relaxed);

    if (manager_uid <= -1 || now_ms - last_stat > 1000) {
        manager_uid = get_manager_uid_impl(); 
        g_ksu_manager_uid.store(manager_uid, std::memory_order_relaxed);
        g_ksu_last_stat_time_ms.store(now_ms, std::memory_order_relaxed);
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
