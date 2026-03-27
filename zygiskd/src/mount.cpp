#include "mount.hpp"

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <cstring>
#include <vector>
#include <string_view>
#include <algorithm>

#include "daemon.hpp"
#include "logging.hpp"
#include "root_impl.hpp"
#include "socket_utils.hpp"
#include "misc.hpp"
#include "utils.hpp"

namespace zygisk_mount {

bool switch_mount_namespace(pid_t pid) {
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        PLOGE("switch_mount_namespace: getcwd");
        return false;
    }

    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", pid);

    UniqueFd fd(open(ns_path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        PLOGE("switch_mount_namespace: open %s", ns_path);
        return false;
    }

    if (setns(fd, CLONE_NEWNS) != 0) {
        PLOGE("switch_mount_namespace: setns");
        return false;
    }

    if (chdir(cwd) != 0) {
        PLOGE("switch_mount_namespace: chdir");
        return false;
    }

    return true;
}

MountNamespaceManager::MountNamespaceManager() : clean_mnt_ns_fd_(-1), root_mnt_ns_fd_(-1) {}

int MountNamespaceManager::get_namespace_fd(zygiskd::MountNamespace namespace_type) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return (namespace_type == zygiskd::MountNamespace::Clean) ? clean_mnt_ns_fd_ : root_mnt_ns_fd_;
}

int MountNamespaceManager::save_mount_namespace(pid_t pid, zygiskd::MountNamespace namespace_type) {
    std::lock_guard<std::mutex> lock(mtx_);

    int& fd_ref = (namespace_type == zygiskd::MountNamespace::Clean) ? clean_mnt_ns_fd_ : root_mnt_ns_fd_;
    if (fd_ref >= 0) {
        return fd_ref;
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        PLOGE("pipe2");
        return -1;
    }

    UniqueFd pipe_read(pipefd[0]);
    UniqueFd pipe_write(pipefd[1]);

    pid_t child_pid = fork();
    if (child_pid < 0) {
        PLOGE("fork");
        return -1;
    }

    if (child_pid == 0) {
        // --- Child Process ---
        pipe_read = UniqueFd();

        if (!switch_mount_namespace(pid)) {
            _exit(1);
        }

        if (namespace_type == zygiskd::MountNamespace::Clean) {
            if (unshare(CLONE_NEWNS) != 0) {
                PLOGE("unshare");
                _exit(1);
            }
            if (!clean_mount_namespace()) {
                LOGE("clean_mount_namespace failed");
            }
        }

        uint8_t sig = 0;
        if (socket_utils::xwrite(pipe_write, &sig, sizeof(sig)) != sizeof(sig)) {
            PLOGE("child: write pipe");
        }
        pipe_write = UniqueFd();

        while (true) {
            sleep(60);
        }
        _exit(0);
    }

    // --- Parent Process ---
    pipe_write = UniqueFd();

    uint8_t buf = 0;
    if (socket_utils::xread(pipe_read, &buf, sizeof(buf)) != sizeof(buf)) {
        PLOGE("parent: read pipe");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, nullptr, 0);
        return -1;
    }

    pipe_read = UniqueFd();

    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", child_pid);

    UniqueFd ns_fd(open(ns_path, O_RDONLY | O_CLOEXEC));
    if (ns_fd < 0) {
        PLOGE("open %s", ns_path);
        kill(child_pid, SIGKILL);
        waitpid(child_pid, nullptr, 0);
        return -1;
    }

    kill(child_pid, SIGKILL);
    waitpid(child_pid, nullptr, 0);

    fd_ref = ns_fd.release();
    return fd_ref;
}

struct MountInfo {
    int mnt_id;
    char path[256];
};

bool MountNamespaceManager::clean_mount_namespace() {
    UniqueFile file(fopen("/proc/self/mountinfo",  "re"));
    if (!file) [[unlikely]] {
        PLOGE("fopen /proc/self/mountinfo");
        return false;
    }

    std::vector<MountInfo> unmount_targets;
    unmount_targets.reserve(256);

    const char* root_source = nullptr;
    auto root = root_impl::get();
    if (root == root_impl::RootImpl::APatch) root_source = "APatch";
    else if (root == root_impl::RootImpl::KernelSU) root_source = "KSU";
    else if (root == root_impl::RootImpl::Magisk) root_source = "magisk";

    const bool is_ksu = (root == root_impl::RootImpl::KernelSU);
    char ksu_module_source[256] = {0};

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        int mnt_id;
        char root_path[256] = {0};
        char mount_point[256] = {0};
        char fstype[256] = {0};
        char mount_source[256] = {0};

        int ret = sscanf(line, "%d %*d %*s %255s %255s %*s %*s - %255s %255s",
                         &mnt_id, root_path, mount_point, fstype, mount_source);

        if (ret < 5) continue;

        bool should_unmount = false;
        std::string_view root_view(root_path);
        std::string_view mp_view(mount_point);
        std::string_view src_view(mount_source);
        std::string_view line_view(line);

        if (is_ksu && mp_view == "/data/adb/modules" && src_view.starts_with("/dev/block/loop")) {
            strlcpy(ksu_module_source, mount_source, sizeof(ksu_module_source));
        }

        if (root_source && src_view.find(root_source) != std::string_view::npos) should_unmount = true;
        else if (root == root_impl::RootImpl::Magisk && src_view == "worker") should_unmount = true;
        else if (root_view.find("/adb/") != std::string_view::npos) should_unmount = true;
        else if (mp_view.find("/adb/") != std::string_view::npos) should_unmount = true;
        else if (line_view.find("/adb/") != std::string_view::npos) should_unmount = true;
        else if (root_view.find("zygisk") != std::string_view::npos) should_unmount = true;
        else if (src_view.find("zygisk") != std::string_view::npos) should_unmount = true;
        else if (line_view.find("zygisk") != std::string_view::npos) should_unmount = true;
        else if (is_ksu && ksu_module_source[0] != '\0' && src_view == ksu_module_source) should_unmount = true;

        if (should_unmount) {
            MountInfo info;
            info.mnt_id = mnt_id;
            strlcpy(info.path, mount_point, sizeof(info.path));
            unmount_targets.push_back(info);
        }
    }

    qsort(unmount_targets.data(), unmount_targets.size(), sizeof(MountInfo), [](const void* a, const void* b) {
        const auto* m1 = (const MountInfo*)a;
        const auto* m2 = (const MountInfo*)b;
        return (m2->mnt_id - m1->mnt_id); // Descending order
    });

    for (const auto& target : unmount_targets) {
        if (umount2(target.path, MNT_DETACH) == -1) {
            PLOGE("umount2 %s", target.path);
        }
    }

    return true;
}

} // namespace zygisk_mount
