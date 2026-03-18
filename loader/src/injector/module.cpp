#include "module.hpp"

#include <android/dlext.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_close_range
#define __NR_close_range 436
#endif

#include <lsplt.hpp>

#include "daemon.hpp"
#include "dl.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "misc.hpp"
#include "zygisk.hpp"

// Structure for the getdents64 syscall
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// Extremely fast inline string-to-int parser (avoids atoi overhead)
static inline int fast_atoi(const char *str) {
    int val = 0;
    while (*str >= '0' && *str <= '9') {
        val = val * 10 + (*str++ - '0');
    }
    return val;
}

using namespace std;

ZygiskModule::ZygiskModule(int id, void *handle, void *entry)
    : id(id), handle(handle), entry{entry}, api{}, mod{nullptr} {
    // Make sure all pointers are null
    memzero(&api, sizeof(api));
    api.base.impl = this;
    api.base.registerModule = &ZygiskModule::RegisterModuleImpl;
}

bool ZygiskModule::RegisterModuleImpl(ApiTable *api, long *module) {
    if (api == nullptr || module == nullptr) return false;

    long api_version = *module;
    // Unsupported version
    if (api_version > ZYGISK_API_VERSION) return false;

    // Set the actual module_abi*
    api->base.impl->mod = {module};

    // Fill in API accordingly with module API version
    if (api_version >= 1) {
        api->v1.hookJniNativeMethods = hookJniNativeMethods;
        api->v1.pltHookRegister = [](auto a, auto b, auto c, auto d) {
            if (g_ctx) g_ctx->plt_hook_register(a, b, c, d);
        };
        api->v1.pltHookExclude = [](auto a, auto b) {
            if (g_ctx) g_ctx->plt_hook_exclude(a, b);
        };
        api->v1.pltHookCommit = []() { return g_ctx && g_ctx->plt_hook_commit(); };
        api->v1.connectCompanion = [](ZygiskModule *m) { return m->connectCompanion(); };
        api->v1.setOption = [](ZygiskModule *m, auto opt) { m->setOption(opt); };
    }
    if (api_version >= 2) {
        api->v2.getModuleDir = [](ZygiskModule *m) { return m->getModuleDir(); };
        api->v2.getFlags = [](auto) { return ZygiskModule::getFlags(); };
    }
    if (api_version >= 4) {
        api->v4.pltHookCommit = []() { return lsplt::CommitHook(g_hook->cached_map_infos); };
        api->v4.pltHookRegister = [](dev_t dev, ino_t inode, const char *symbol, void *fn,
                                     void **backup) {
            if (dev == 0 || inode == 0 || symbol == nullptr || fn == nullptr) return;
            lsplt::RegisterHook(dev, inode, symbol, fn, backup);
        };
        api->v4.exemptFd = [](int fd) { return g_ctx && g_ctx->exempt_fd(fd); };
    }

    return true;
}

bool ZygiskModule::valid() const {
    if (mod.api_version == nullptr) return false;
    switch (*mod.api_version) {
    case 5:
    case 4:
    case 3:
    case 2:
    case 1:
        return mod.v1->impl && mod.v1->preAppSpecialize && mod.v1->postAppSpecialize &&
               mod.v1->preServerSpecialize && mod.v1->postServerSpecialize;
    default:
        return false;
    }
}

/* Zygisksu changed: Use own zygiskd */
int ZygiskModule::connectCompanion() const { return zygiskd::ConnectCompanion(id); }

/* Zygisksu changed: Use own zygiskd */
int ZygiskModule::getModuleDir() const { return zygiskd::GetModuleDir(id); }

void ZygiskModule::setOption(zygisk::Option opt) {
    if (g_ctx == nullptr) return;
    switch (opt) {
    case zygisk::FORCE_DENYLIST_UNMOUNT:
        g_ctx->flags |= DO_REVERT_UNMOUNT;
        break;
    case zygisk::DLCLOSE_MODULE_LIBRARY:
        unload = true;
        break;
    }
}

uint32_t ZygiskModule::getFlags() { return g_ctx ? (g_ctx->info_flags & ~PRIVATE_MASK) : 0; }

bool ZygiskModule::tryUnload() const { return unload && dlclose(handle) == 0; }

// -----------------------------------------------------------------

#define call_app(method)                                                                           \
    switch (*mod.api_version) {                                                                    \
    case 1:                                                                                        \
    case 2: {                                                                                      \
        AppSpecializeArgs_v1 a(args);                                                              \
        mod.v1->method(mod.v1->impl, &a);                                                          \
        break;                                                                                     \
    }                                                                                              \
    case 3:                                                                                        \
    case 4:                                                                                        \
    case 5:                                                                                        \
        mod.v1->method(mod.v1->impl, args);                                                        \
        break;                                                                                     \
    }

void ZygiskModule::preAppSpecialize(AppSpecializeArgs_v5 *args) const { call_app(preAppSpecialize) }

void ZygiskModule::postAppSpecialize(const AppSpecializeArgs_v5 *args) const {
    call_app(postAppSpecialize)
}

void ZygiskModule::preServerSpecialize(ServerSpecializeArgs_v1 *args) const {
    mod.v1->preServerSpecialize(mod.v1->impl, args);
}

void ZygiskModule::postServerSpecialize(const ServerSpecializeArgs_v1 *args) const {
    mod.v1->postServerSpecialize(mod.v1->impl, args);
}

// -----------------------------------------------------------------

// Helper to determine if a string is a simple literal or a complex regex
static inline bool is_simple_literal(const char *str) {
    return strpbrk(str, ".*+?^$[]|()\\") == nullptr;
}

void ZygiskContext::plt_hook_register(const char *regex, const char *symbol, void *fn,
                                      void **backup) {
    if (regex == nullptr || symbol == nullptr || fn == nullptr) return;

    RegisterInfo info;
    strlcpy(info.symbol, symbol ? symbol : "", sizeof(info.symbol));
    info.callback = fn;
    info.backup = backup;

    if (is_simple_literal(regex)) {
        info.is_regex = false;
        strlcpy(info.literal, regex ? regex : "", sizeof(info.literal));
    } else {
        info.is_regex = true;
        if (regcomp(&info.regex, regex, REG_NOSUB) != 0) return;
    }

    mutex_guard lock(hook_info_lock);
    register_info.emplace_back(std::move(info));
}

void ZygiskContext::plt_hook_exclude(const char *regex, const char *symbol) {
    if (!regex) return;

    IgnoreInfo ign;
    strlcpy(ign.symbol, symbol ? symbol : "", sizeof(ign.symbol));

    if (is_simple_literal(regex)) {
        ign.is_regex = false;
        strlcpy(ign.literal, regex ? regex : "", sizeof(ign.literal));
    } else {
        ign.is_regex = true;
        if (regcomp(&ign.regex, regex, REG_NOSUB) != 0) return;
    }

    mutex_guard lock(hook_info_lock);
    ignore_info.push_back(ign);
}

void ZygiskContext::plt_hook_process_regex() {
    if (register_info.empty()) return;
    for (auto &map : g_hook->cached_map_infos) {
        if (map.offset != 0 || !map.is_private || !(map.perms & PROT_READ)) continue;

        // Pre-evaluate ignore rules that only depend on map.path
        std::vector<bool> ign_matches(ignore_info.size());
        for (size_t i = 0; i < ignore_info.size(); ++i) {
            auto &ign = ignore_info[i];
            if (!ign.is_regex) {
                ign_matches[i] = (strstr(map.path, ign.literal) != nullptr);
            } else {
                ign_matches[i] = (regexec(&ign.regex, map.path, 0, nullptr, 0) == 0);
            }
        }

        for (auto &reg : register_info) {
            // Execute fast sub-string search or fallback to heavy regex
            if (!reg.is_regex) {
                if (!strstr(map.path, reg.literal)) continue;
            } else {
                if (regexec(&reg.regex, map.path, 0, nullptr, 0) != 0) continue;
            }
            bool ignored = false;
            for (size_t i = 0; i < ignore_info.size(); ++i) {
                auto &ign = ignore_info[i];
                if (ign.symbol[0] != '\0' && strcmp(ign.symbol, reg.symbol) != 0) continue;
                if (ign_matches[i]) {
                    ignored = true;
                    break;
                }
            }
            if (!ignored) {
                lsplt::RegisterHook(map.dev, map.inode, reg.symbol, reg.callback, reg.backup);
            }
        }
    }
}

bool ZygiskContext::plt_hook_commit() {
    {
        mutex_guard lock(hook_info_lock);
        plt_hook_process_regex();

        // Manually destroy sensitive string data in the heap before clearing
        for (auto &reg : register_info) {
            memzero(reg.symbol, sizeof(reg.symbol));
        }
        for (auto &ign : ignore_info) {
            memzero(ign.symbol, sizeof(ign.symbol));
        }

        register_info.clear();
        ignore_info.clear();
        register_info.shrink_to_fit();
        ignore_info.shrink_to_fit();
    }
    return lsplt::CommitHook(g_hook->cached_map_infos);
}

// -----------------------------------------------------------------

void ZygiskContext::sanitize_fds() {
    if (unlikely(!is_child())) {
        return;
    }

    if (can_exempt_fd() && !exempted_fds.empty()) {
        auto update_fd_array = [&](int old_len) -> jintArray {
            jintArray array = env->NewIntArray(static_cast<int>(old_len + exempted_fds.size()));
            if (array == nullptr) return nullptr;

            env->SetIntArrayRegion(array, old_len, static_cast<int>(exempted_fds.size()),
                                   exempted_fds.data());
            for (int fd : exempted_fds) {
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                    allowed_fds[fd] = true;
                }
            }
            *args.app->fds_to_ignore = array;
            return array;
        };

        if (jintArray fdsToIgnore = *args.app->fds_to_ignore) {
            int *arr = env->GetIntArrayElements(fdsToIgnore, nullptr);
            int len = env->GetArrayLength(fdsToIgnore);
            for (int i = 0; i < len; ++i) {
                int fd = arr[i];
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                    allowed_fds[fd] = true;
                }
            }
            if (jintArray newFdList = update_fd_array(len)) {
                env->SetIntArrayRegion(newFdList, 0, len, arr);
            }
            env->ReleaseIntArrayElements(fdsToIgnore, arr, JNI_ABORT);
        } else {
            update_fd_array(0);
        }
    }

    // Close all forbidden fds using direct syscall
    if (is_kernel_5_9_or_newer()) {
        unsigned int start_fd = 0;
        bool in_range = false;
        size_t n = allowed_fds.size();
        for (size_t i = 0; i < n; ++i) {
            if (!allowed_fds[i]) {
                if (!in_range) {
                    start_fd = static_cast<unsigned int>(i);
                    in_range = true;
                }
            } else {
                if (in_range) {
                    syscall(__NR_close_range, start_fd, static_cast<unsigned int>(i - 1), 0);
                    in_range = false;
                }
            }
        }
        if (in_range) {
            syscall(__NR_close_range, start_fd, ~0U, 0);
        } else {
            syscall(__NR_close_range, static_cast<unsigned int>(n), ~0U, 0);
        }
    } else {
        UniqueFd fd_dir(open("/proc/self/fd", O_RDONLY | O_DIRECTORY));
        if (likely(fd_dir >= 0)) {
            char buf[4096];
            int nread;
            while ((nread = syscall(__NR_getdents64, (int)fd_dir, buf, sizeof(buf))) > 0) {
                for (int bpos = 0; bpos < nread;) {
                    auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);
                    if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                        int fd = fast_atoi(d->d_name);
                        if (unlikely((fd < 0 || static_cast<size_t>(fd) >= allowed_fds.size() ||
                                      !allowed_fds[fd]) &&
                                     fd != (int)fd_dir)) {
                            close(fd);
                        }
                    }
                    bpos += d->d_reclen;
                }
            }
        }
    }

    // Clear exempted fds to free memory
    exempted_fds.clear();
    exempted_fds.shrink_to_fit();
    allowed_fds.clear();
    allowed_fds.shrink_to_fit();
}

bool ZygiskContext::exempt_fd(int fd) {
    if ((flags & POST_SPECIALIZE) || (flags & SKIP_CLOSE_LOG_PIPE)) return true;
    if (!can_exempt_fd()) return false;
    exempted_fds.push_back(fd);
    LOGV("exempt fd %d", fd);
    return true;
}

bool ZygiskContext::can_exempt_fd() const {
    return (flags & APP_FORK_AND_SPECIALIZE) && args.app->fds_to_ignore;
}

static int sigmask(int how, int signum) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return sigprocmask(how, &set, nullptr);
}

void ZygiskContext::fork_pre() {
    // Do our own fork before loading any 3rd party code
    // First block SIGCHLD, unblock after original fork is done
    sigmask(SIG_BLOCK, SIGCHLD);
    pid = old_fork();

    if (unlikely(!is_child())) return;

    // Record all open fds using direct syscall to avoid heap allocations
    UniqueFd fd_dir(open("/proc/self/fd", O_RDONLY | O_DIRECTORY));
    if (likely(fd_dir >= 0)) {
        char buf[4096];
        int nread;
        while ((nread = syscall(__NR_getdents64, (int)fd_dir, buf, sizeof(buf))) > 0) {
            for (int bpos = 0; bpos < nread;) {
                auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);

                // Only parse if it starts with a number (valid FD)
                if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                    int fd = fast_atoi(d->d_name);
                    if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                        allowed_fds[fd] = true;
                    }
                }
                bpos += d->d_reclen;
            }
        }
        allowed_fds[fd_dir] = false;
    }
}

void ZygiskContext::fork_post() {
    // Unblock SIGCHLD in case the original method didn't
    sigmask(SIG_UNBLOCK, SIGCHLD);

    // Clear exempted fds to free memory
    exempted_fds.clear();
    exempted_fds.shrink_to_fit();
    allowed_fds.clear();
    allowed_fds.shrink_to_fit();
}

/* Zygisksu changed: Load module fds */
void ZygiskContext::run_modules_pre() {
    auto ms = zygiskd::ReadModules();
    auto size = ms.size();
    for (size_t i = 0; i < size; i++) {
        auto &m = ms[i];
        if (void *handle = DlopenMem(m.memfd, RTLD_NOW);
            void *entry = handle ? dlsym(handle, "zygisk_module_entry") : nullptr) {
            modules.emplace_back(i, handle, entry);
        }

        close(m.memfd);
        memzero(m.name, sizeof(m.name));
    }

    for (auto &m : modules) {
        m.onLoad(env);
        if (flags & APP_SPECIALIZE) {
            m.preAppSpecialize(args.app);
        } else if (flags & SERVER_FORK_AND_SPECIALIZE) {
            m.preServerSpecialize(args.server);
        }
    }
}

void ZygiskContext::run_modules_post() {
    flags |= POST_SPECIALIZE;

    size_t modules_unloaded = 0;
    for (const auto &m : modules) {
        if (flags & APP_SPECIALIZE) {
            m.postAppSpecialize(args.app);
        } else if (flags & SERVER_FORK_AND_SPECIALIZE) {
            m.postServerSpecialize(args.server);
        }
        if (m.tryUnload()) modules_unloaded++;
    }

    if (modules.size() > 0) {
        LOGV("modules unloaded: %zu/%zu", modules_unloaded, modules.size());
    }
}

void ZygiskContext::app_specialize_pre() {
    uid_t uid = args.app->uid;
    uid_t app_id = uid % 100000;  // Support for Work Profiles / Multi-User

    // Total range: Standard Isolated Services (99000-99999) and AppZygote (90000-98999)
    if (app_id >= 90000 && app_id <= 99999) {
        bool found_parent = false;

        // 1. Try to get the parent's UID using app_data_dir (If Android sends it)
        if (args.app->app_data_dir) {
            const char *data_dir = env->GetStringUTFChars(args.app->app_data_dir, nullptr);
            if (data_dir != nullptr) {
                struct stat st;
                if (stat(data_dir, &st) == 0) {
                    uid = st.st_uid;
                    found_parent = true;
                    LOGV("identify isolated service via app_data_dir [uid:%d, data_dir:%s]", uid,
                         data_dir);
                }
                env->ReleaseStringUTFChars(args.app->app_data_dir, data_dir);
            }
        }

        // 2. If failed or null, extract directory from pkg_data_info_list (Android 10+)
        if (!found_parent && args.app->pkg_data_info_list && *args.app->pkg_data_info_list) {
            jobjectArray pkg_array = *args.app->pkg_data_info_list;  // Dereference pointer
            jint count = env->GetArrayLength(pkg_array);
            if (count > 0) {
                jstring pkg_data_info = (jstring) env->GetObjectArrayElement(pkg_array, 0);
                if (pkg_data_info) {
                    const char *info_str = env->GetStringUTFChars(pkg_data_info, nullptr);
                    if (info_str) {
                        // string format is: "packageName,volumeUuid,inode,dataDir"
                        const char *comma1 = strchr(info_str, ',');
                        const char *comma2 = comma1 ? strchr(comma1 + 1, ',') : nullptr;
                        const char *comma3 = comma2 ? strchr(comma2 + 1, ',') : nullptr;
                        if (comma3 && *(comma3 + 1) != '\0') {
                            const char *data_dir = comma3 + 1;
                            struct stat st;
                            if (stat(data_dir, &st) == 0) {
                                uid = st.st_uid;
                                LOGV(
                                    "identify isolated service via pkg_data_info [uid:%d, data_dir:%s]",
                                    uid, data_dir);
                            }
                        }
                        env->ReleaseStringUTFChars(pkg_data_info, info_str);
                    }
                    env->DeleteLocalRef(pkg_data_info);
                }
            }
        }
    }

    if (info_flags == 0) info_flags = zygiskd::GetProcessFlags(uid);

    if ((info_flags & UNMOUNT_MASK) == UNMOUNT_MASK) {
        LOGI("[%s] is on the denylist", process);
        flags |= DO_REVERT_UNMOUNT;
    }

    flags |= APP_SPECIALIZE;
    run_modules_pre();
}

void ZygiskContext::app_specialize_post() {
    run_modules_post();

    if ((info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
        LOGI("current uid %d is manager!", args.app->uid);
        setenv("ZYGISK_ENABLED", "1", 1);
    }

    // Cleanups
    env->ReleaseStringUTFChars(args.app->nice_name, process);
}

void ZygiskContext::server_specialize_pre() {
    run_modules_pre();
    zygiskd::SystemServerStarted();
}

void ZygiskContext::server_specialize_post() { run_modules_post(); }

// -----------------------------------------------------------------

void ZygiskContext::nativeForkSystemServer_pre() {
    LOGV("pre forkSystemServer");
    flags |= SERVER_FORK_AND_SPECIALIZE;

    fork_pre();
    if (is_child()) {
        server_specialize_pre();
        zygiskd::CacheMountNamespace(getpid());
    }
    sanitize_fds();
}

void ZygiskContext::nativeForkSystemServer_post() {
    if (is_child()) {
        LOGV("post forkSystemServer");
        zygiskd::UnmapSharedMemory();
        server_specialize_post();
    }
    fork_post();
}

bool abort_zygote_unmount(const std::vector<mount_info> &traces, uint32_t info_flags) {
    if (traces.size() == 0) {
        LOGV("abort unmounting zygote with an empty trace list");
        return true;
    }
    bool is_magisk = info_flags & PROCESS_ROOT_IS_MAGISK;
    for (const auto &trace : traces) {
        if (trace.target.starts_with("/product")) {
            if (trace.target.starts_with("/product/bin")) continue;
            if (!is_magisk && trace.target != "/product") continue;
            // workaround for zygote resource overlay (JingMatrix/NeoZygisk#26)
            LOGV("abort unmounting zygote due to prohibited target: [%s]", trace.raw_info.c_str());
            return true;
        }
    }
    return false;
}

void ZygiskContext::nativeSpecializeAppProcess_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre specialize [%s]", process);
    // App specialize does not check FD
    flags |= SKIP_CLOSE_LOG_PIPE;
    app_specialize_pre();

    // If parent Zygote has not yet been cleaned up, this App Zygote inherits the dirty namespace.
    // The unshare() hook by default depends on a 'Clean' namespace in cache that is
    // actually dirty (SystemServer cache). We must manually unmount here.
    if (!g_hook->zygote_unmounted && (flags & DO_REVERT_UNMOUNT)) {
        LOGI("AppZygote [%s] is on denylist, performing manual unmount", process);
        auto traces = check_zygote_traces(info_flags);

        if (!abort_zygote_unmount(traces, info_flags)) {
            for (const auto &trace : traces) {
                // Fix Magisk root loss: we omitted elements of "magisk"
                if (trace.source == "magisk") continue;

                LOGV("AppZygote unmounting %s", trace.target.c_str());
                umount2(trace.target.c_str(), MNT_DETACH);
            }
            // After unmounting, we can clear the traces to prevent the SystemServer
            // from inheriting them, which may cause issues with the SystemServer's
            // resource overlay (JingMatrix/NeoZygisk#26)
            g_hook->zygote_unmounted = true;
            g_hook->zygote_traces.clear();
        }
    }
}

void ZygiskContext::nativeSpecializeAppProcess_post() {
    LOGV("post specialize [%s]", process);
    zygiskd::UnmapSharedMemory();
    app_specialize_post();
}

void ZygiskContext::nativeForkAndSpecialize_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre forkAndSpecialize [%s]", process);
    flags |= APP_FORK_AND_SPECIALIZE;

    if (!g_hook->zygote_unmounted && g_hook->zygote_traces.size() == 0) {
        info_flags = zygiskd::GetProcessFlags(args.app->uid);

        g_hook->zygote_traces = check_zygote_traces(info_flags);

        if (!abort_zygote_unmount(g_hook->zygote_traces, info_flags)) {
            auto removal_predicate = [](const mount_info &trace) {
                // Fix Magisk root loss: skip unmounting items tagged as "magisk"
                if (trace.source == "magisk") {
                    LOGV("skip magisk specific mounts for compatibility: %s",
                         trace.raw_info.c_str());
                    return false;  // Return false to keep this trace in the vector/mount list
                }
                LOGV("unmounting %s (mnt_id: %u)", trace.target.c_str(), trace.id);
                if (umount2(trace.target.c_str(), MNT_DETACH) == 0) {
                    return true;  // Success: Mark for removal.
                } else {
                    LOGE("failed to unmount %s: %s", trace.target.c_str(), strerror(errno));
                    return false;  // Failure: Keep this trace in the vector.
                }
            };

            auto new_end = std::remove_if(g_hook->zygote_traces.begin(),
                                          g_hook->zygote_traces.end(), removal_predicate);

            g_hook->zygote_traces.erase(new_end, g_hook->zygote_traces.end());
            g_hook->zygote_unmounted = true;
        }
    }

    fork_pre();
    if (is_child()) {
        app_specialize_pre();
    }

    sanitize_fds();
}

void ZygiskContext::nativeForkAndSpecialize_post() {
    if (is_child()) {
        LOGV("post forkAndSpecialize [%s]", process);
        zygiskd::UnmapSharedMemory();
        app_specialize_post();
    }
    fork_post();
}

// -----------------------------------------------------------------

bool ZygiskContext::update_mount_namespace(zygiskd::MountNamespace namespace_type) {
    const char *type_str = (namespace_type == zygiskd::MountNamespace::Clean ? "Clean" : "Root");
    LOGV("updating mount namespace to type %s", type_str);

    UniqueFd ns_fd(zygiskd::UpdateMountNamespace(namespace_type));

    // Check for failure (Not cached or error)
    if (ns_fd < 0) {
        LOGW("mount namespace [%s] not available/cached", type_str);
        return false;
    }

    // Apply the namespace
    // setns works directly with the FD received from the socket.
    int ret = setns(ns_fd, CLONE_NEWNS);
    if (ret != 0) {
        PLOGE("setns failed for type %s", type_str);
        return false;
    }

    return true;
}
