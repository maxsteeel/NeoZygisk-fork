#include "mount.hpp"

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "root_impl.hpp"
#include "socket_utils.hpp"
#include "misc.hpp"
#include "utils.hpp"

namespace zygisk_mount {

bool switch_mount_namespace(pid_t pid) {
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) return false;

    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", pid);

    UniqueFd fd(open(ns_path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    if (setns(fd, CLONE_NEWNS) != 0) return false;

    if (chdir(cwd) != 0) return false;

    return true;
}

MountNamespaceManager::MountNamespaceManager() : clean_mnt_ns_fd_(-1), root_mnt_ns_fd_(-1) {}

int MountNamespaceManager::get_namespace_fd(zygiskd::MountNamespace namespace_type) const {
    mutex_guard lock(mtx_);
    return (namespace_type == zygiskd::MountNamespace::Clean) ? clean_mnt_ns_fd_ : root_mnt_ns_fd_;
}

int MountNamespaceManager::save_mount_namespace(pid_t pid, zygiskd::MountNamespace namespace_type) {
    mutex_guard lock(mtx_);

    int& fd_ref = (namespace_type == zygiskd::MountNamespace::Clean) ? clean_mnt_ns_fd_ : root_mnt_ns_fd_;
    if (fd_ref >= 0) return fd_ref;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return -1;

    UniqueFd pipe_read(pipefd[0]);
    UniqueFd pipe_write(pipefd[1]);

    pid_t child_pid = fork();
    if (child_pid < 0) return -1;

    if (child_pid == 0) {
        // --- Child Process ---
        pipe_read = UniqueFd();

        if (!switch_mount_namespace(pid)) _exit(1);

        if (namespace_type == zygiskd::MountNamespace::Clean) {
            if (unshare(CLONE_NEWNS) != 0) _exit(1);
            if (!clean_mount_namespace()) LOGE("clean_mount_namespace failed");
        }

        uint8_t sig = 0;
        socket_utils::xwrite(pipe_write, &sig, sizeof(sig));

        char dummy;
        read(0, &dummy, 1); 
        _exit(0);
    }

    // --- Parent Process ---
    pipe_write = UniqueFd();

    uint8_t buf = 0;
    if (socket_utils::xread(pipe_read, &buf, sizeof(buf)) != sizeof(buf)) {
        kill(child_pid, SIGKILL);
        waitpid(child_pid, nullptr, 0);
        return -1;
    }

    pipe_read = UniqueFd();

    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", child_pid);

    UniqueFd ns_fd(open(ns_path, O_RDONLY | O_CLOEXEC));
    kill(child_pid, SIGKILL);
    waitpid(child_pid, nullptr, 0);

    if (ns_fd < 0) return -1;

    fd_ref = ns_fd.release();
    return fd_ref;
}

struct MountInfo {
    int mnt_id;
    char path[256];
};

struct MountTargetList : public UniqueList<MountInfo> {
    void push_back(int id, const char* p) {
        MountInfo info;
        info.mnt_id = id;
        strlcpy(info.path, p, sizeof(info.path));
        UniqueList<MountInfo>::push_back(info);
    }
};

static inline char* tokenize_word(char* str, char** next_word) {
    char* word_start = str;
    // Move forward to the end of the word
    while (*str > ' ') ++str;

    // If a delimiter is found, it is destroyed and set to Null
    if (*str != '\0') {
        *str = '\0';
        ++str;
        // Excess spaces are cleared for the next word
        while (*str > '\0' && *str <= ' ') ++str;
    }
    *next_word = str; // It saves where the next starts
    return word_start;
}

bool MountNamespaceManager::clean_mount_namespace() {
    UniqueFd fd(open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
    if (fd < 0) [[unlikely]] {
        PLOGE("open /proc/self/mountinfo");
        return false;
    }

    MountTargetList unmount_targets;

    const char* root_source = nullptr;
    auto root = root_impl::get();
    if (root == root_impl::RootImpl::APatch) root_source = "APatch";
    else if (root == root_impl::RootImpl::KernelSU) root_source = "KSU";
    else if (root == root_impl::RootImpl::Magisk) root_source = "magisk";

    bool is_ksu = (root == root_impl::RootImpl::KernelSU);
    char ksu_module_source[256] = {0};

    char buf[4096];
    size_t current_pos = 0;
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buf + current_pos, sizeof(buf) - current_pos - 1)) > 0) {
        size_t total_bytes = current_pos + bytes_read;
        buf[total_bytes] = '\0';

        char *line_start = buf;
        char *line_end;

        while ((line_end = static_cast<char*>(__builtin_memchr(line_start, '\n', total_bytes - (line_start - buf)))) != nullptr) {
            *line_end = '\0';
                
            if (line_start < line_end) {
                char* ptr = line_start;
                char* next;

                // extract mnt_id
                int mnt_id = fast_atoi(ptr);
                if (mnt_id != 0) {
                    ptr = tokenize_word(ptr, &next); // skip mnt_id
                    ptr = tokenize_word(next, &next); // skip parent_id
                    ptr = tokenize_word(next, &next); // skip major:minor
                    char* root_path = tokenize_word(next, &next);
                    char* mount_point = tokenize_word(next, &next);
                    ptr = tokenize_word(next, &next); // skip mount options
                    ptr = tokenize_word(next, &next); // skip optional fields
                    if (*ptr == '-') ptr = tokenize_word(next, &next); // skip separator
                    ptr = tokenize_word(next, &next); // skip filesystem type
                    char* mount_source = tokenize_word(next, &next);

                    if (is_ksu && __builtin_strncmp(mount_point, "/data/adb/modules", 17) == 0) {
                        if (__builtin_strncmp(mount_source, "/dev/block/loop", 15) == 0) {
                            strlcpy(ksu_module_source, mount_source, sizeof(ksu_module_source));
                        }
                    }

                    bool should_unmount = false;
                    if (__builtin_strncmp(root_path, "/adb/modules", 12) == 0) should_unmount = true;
                    else if (__builtin_strncmp(mount_point, "/data/adb/modules", 17) == 0) should_unmount = true;
                    else if (root_source && __builtin_strcmp(mount_source, root_source) == 0) should_unmount = true;
                    else if (ksu_module_source[0] != '\0' && __builtin_strcmp(mount_source, ksu_module_source) == 0) should_unmount = true;

                    if (should_unmount) {
                        unmount_targets.push_back(mnt_id, mount_point);
                    }
                }
            }
            line_start = line_end + 1;
        }

        size_t remaining = total_bytes - (line_start - buf);
        if (remaining > 0 && remaining < sizeof(buf)) {
            __builtin_memmove(buf, line_start, remaining);
            current_pos = remaining;
        } else {
            current_pos = 0;
        }
    }

    if (unmount_targets.size > 1) {
        ::sort(unmount_targets.data, unmount_targets.data + unmount_targets.size, 
            [](const MountInfo& a, const MountInfo& b) {
                return a.mnt_id > b.mnt_id; // Deepest first
            });
    }

    for (size_t i = 0; i < unmount_targets.size; i++) {
        if (umount2(unmount_targets.data[i].path, MNT_DETACH) == -1) {
            PLOGE("umount2 %s", unmount_targets.data[i].path);
        }
    }

    return true;
}

} // namespace zygisk_mount

