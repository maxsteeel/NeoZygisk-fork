#pragma once

#include <atomic>
#include <cstdint>

// --- Versioning Constants ---
// These are set at compile time from environment variables via CMake definitions.

#ifndef ZKSU_VERSION
#define ZKSU_VERSION "unknown"
#endif

#ifndef MIN_APATCH_VERSION
#define MIN_APATCH_VERSION 0
#endif

#ifndef MIN_KSU_VERSION
#define MIN_KSU_VERSION 0
#endif

#ifndef MAX_KSU_VERSION
#define MAX_KSU_VERSION 0
#endif

#ifndef MIN_MAGISK_VERSION
#define MIN_MAGISK_VERSION 0
#endif

namespace constants {

// --- Configuration Constants ---

// The relative path to the directory where Zygisk modules are stored.
constexpr const char* PATH_MODULES_DIR = "..";

// --- IPC Constants ---
// These are magic numbers used in communication with the controller.

// IPC code indicating that Zygote has been successfully injected.
constexpr int32_t ZYGOTE_INJECTED = 4;
// IPC code for sending daemon status information.
constexpr int32_t DAEMON_SET_INFO = 5;
// IPC code for sending daemon error information.
constexpr int32_t DAEMON_SET_ERROR_INFO = 6;
// IPC code indicating that the Android system server has started.
constexpr int32_t SYSTEM_SERVER_STARTED = 7;

// Defines the set of actions that can be requested from the daemon over its main Unix socket.
enum class DaemonSocketAction : uint8_t {
    PingHeartbeat = 0,
    GetProcessFlags,
    CacheMountNamespace,
    UpdateMountNamespace,
    ReadModules,
    RequestCompanionSocket,
    GetModuleDir,
    ZygoteRestart,
    SystemServerStarted,
    GetSharedMemoryFd,
    GetZygiskSharedData,
};

// ProcessFlags bitmask
enum class ProcessFlags : uint32_t {
    NONE = 0,
    /// The process has been granted root privileges.
    PROCESS_GRANTED_ROOT = 1 << 0,
    /// The process is on the denylist and module mounts should be hidden.
    PROCESS_ON_DENYLIST = 1 << 1,
    /// The process is the root manager application itself.
    PROCESS_IS_MANAGER = 1 << 27,
    /// The active root solution is APatch.
    PROCESS_ROOT_IS_APATCH = 1 << 28,
    /// The active root solution is KernelSU.
    PROCESS_ROOT_IS_KSU = 1 << 29,
    /// The active root solution is Magisk.
    PROCESS_ROOT_IS_MAGISK = 1 << 30,
};

inline ProcessFlags operator|(ProcessFlags a, ProcessFlags b) {
    return static_cast<ProcessFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline ProcessFlags operator&(ProcessFlags a, ProcessFlags b) {
    return static_cast<ProcessFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline ProcessFlags& operator|=(ProcessFlags& a, ProcessFlags b) {
    a = a | b;
    return a;
}

inline ProcessFlags& operator&=(ProcessFlags& a, ProcessFlags b) {
    a = a & b;
    return a;
}

inline bool has_flag(ProcessFlags flags, ProcessFlags flag) {
    return (flags & flag) == flag;
}

// --- Shared Memory ---
constexpr size_t SHM_HASH_MAP_SIZE = 8192; // Should be a power of 2 for fast modulo

struct ShmEntry {
    std::atomic<uint32_t> uid;
    std::atomic<uint32_t> flags;
};

struct ZygiskSharedData {
    // This value is incremented before a batch update and after a batch update.
    // Readers should check if the version is even, and verify it hasn't changed during reads.
    std::atomic<uint32_t> version;

    // Global flags applied to all processes (e.g. root implementation type)
    std::atomic<uint32_t> global_root_flags;

    ShmEntry entries[SHM_HASH_MAP_SIZE];
};

} // namespace constants
