#include "module.hpp"

#include <android/dlext.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

#ifndef __NR_close_range
#define __NR_close_range 436
#endif

#include <lsplt.hpp>

#include "daemon.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "misc.hpp"
#include "zygisk.hpp"
#include "custom_linker.hpp"
#include "utils.hpp"

ZygiskModule::ZygiskModule(int id, void *handle, void *entry)
    : id(id), handle(handle), entry{entry}, api{}, mod{nullptr} {
    memzero(&api, sizeof(api));
    api.base.impl = this;
    api.base.registerModule = &ZygiskModule::RegisterModuleImpl;
}

bool ZygiskModule::RegisterModuleImpl(ApiTable *api, long *module) {
    if (api == nullptr || module == nullptr) return false;

    long api_version = *module;
    if (api_version > ZYGISK_API_VERSION) return false;

    api->base.impl->mod = {module};

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

int ZygiskModule::connectCompanion() const { return zygiskd::ConnectCompanion(id); }
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

bool ZygiskModule::tryUnload() const {
    if (!unload) return false;
    if (is_custom_linker_address(handle)) {
        custom_linker_unload(handle);
        return true;
    }
    return false;
}

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
void ZygiskModule::postAppSpecialize(const AppSpecializeArgs_v5 *args) const { call_app(postAppSpecialize) }
void ZygiskModule::preServerSpecialize(ServerSpecializeArgs_v1 *args) const { mod.v1->preServerSpecialize(mod.v1->impl, args); }
void ZygiskModule::postServerSpecialize(const ServerSpecializeArgs_v1 *args) const { mod.v1->postServerSpecialize(mod.v1->impl, args); }

void ZygiskContext::plt_hook_register(const char *regex, const char *symbol, void *fn, void **backup) {
    if (!regex || !symbol || !fn) return;
    RegisterInfo info;
    strlcpy(info.symbol, symbol, sizeof(info.symbol));
    strlcpy(info.literal, regex, sizeof(info.literal)); // Ignoramos si es regex, lo tratamos como literal
    info.callback = fn;
    info.backup = backup;
    register_info.push_back(info);
}

void ZygiskContext::plt_hook_exclude(const char *regex, const char *symbol) {
    if (!regex) return;
    IgnoreInfo ign;
    strlcpy(ign.symbol, symbol ? symbol : "", sizeof(ign.symbol));
    strlcpy(ign.literal, regex, sizeof(ign.literal));
    ignore_info.push_back(ign);
}

void ZygiskContext::plt_hook_process_regex() {
    if (register_info.size == 0) return;

    for (size_t i = 0; i < g_hook->cached_map_infos.size; i++) {
        auto& map = g_hook->cached_map_infos.data[i];
        if (map.offset != 0 || !map.is_private || !(map.perms & PROT_READ)) continue;

        for (size_t k = 0; k < register_info.size; k++) {
            auto& reg = register_info.data[k];
            if (!__builtin_strstr(map.path, reg.literal)) continue;

            bool ignored = false;
            for (size_t j = 0; j < ignore_info.size; ++j) {
                auto &ign = ignore_info.data[j];
                if (ign.symbol[0] != '\0' && __builtin_strcmp(ign.symbol, reg.symbol) != 0) continue;
                if (__builtin_strstr(map.path, ign.literal)) {
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
    plt_hook_process_regex();

    // When clear() is called, the RegexUniqueList structure will iterate
    // on all its elements and will call regfree() on those 
    // where is_regex == true. Then it will set the size = 0.
    // This avoids Memory Leak and is a thousand times cleaner.
    register_info.clear();
    ignore_info.clear();
    return lsplt::CommitHook(g_hook->cached_map_infos);
}

void ZygiskContext::sanitize_fds() {
    if (unlikely(!is_child())) return;

    if (can_exempt_fd() && exempted_fds.size > 0) {
        jintArray old_arr = *args.app->fds_to_ignore;
        int old_len = old_arr ? env->GetArrayLength(old_arr) : 0;
        int new_len = old_len + exempted_fds.size;

        if (jintArray new_arr = env->NewIntArray(new_len)) {
            if (old_len > 0) {
                void* old_data = env->GetPrimitiveArrayCritical(old_arr, nullptr);
                if (old_data) {
                    env->SetIntArrayRegion(new_arr, 0, old_len, static_cast<jint*>(old_data));
                    for (int i = 0; i < old_len; ++i) {
                        int fd = static_cast<jint*>(old_data)[i];
                        if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size) {
                            allowed_fds.data[fd] = true;
                        }
                    }
                    env->ReleasePrimitiveArrayCritical(old_arr, old_data, JNI_ABORT);
                }
            }
            env->SetIntArrayRegion(new_arr, old_len, exempted_fds.size, exempted_fds.data);
            for (size_t i = 0; i < exempted_fds.size; i++) {
                int fd = exempted_fds.data[i];
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size) {
                    allowed_fds.data[fd] = true;
                }
            }
            *args.app->fds_to_ignore = new_arr;
        }
    }

    static int supports_close_range = -1;
    if (unlikely(supports_close_range == -1)) {
        supports_close_range = is_kernel_version_at_least(5, 9) ? 1 : 0;
    }

    if (supports_close_range == 1) {
        unsigned int start_fd = 0;
        bool in_range = false;
        for (size_t i = 0; i < allowed_fds.size; ++i) {
            if (!allowed_fds.data[i]) {
                if (!in_range) {
                    start_fd = static_cast<unsigned int>(i);
                    in_range = true;
                }
            } else if (in_range) {
                syscall(__NR_close_range, start_fd, static_cast<unsigned int>(i - 1), 0);
                in_range = false;
            }
        }
        if (in_range) {
            syscall(__NR_close_range, start_fd, ~0U, 0);
        } else {
            syscall(__NR_close_range, static_cast<unsigned int>(allowed_fds.size), ~0U, 0);
        }
    } else {
        int fd_dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (likely(fd_dir >= 0)) {
            char buf[32768];
            int nread;
            while ((nread = syscall(__NR_getdents64, fd_dir, buf, sizeof(buf))) > 0) {
                for (int bpos = 0; bpos < nread;) {
                    auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);
                    if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                        int fd = fast_atoi(d->d_name);
                        if (fd >= 0 && fd != fd_dir && 
                            (static_cast<size_t>(fd) >= allowed_fds.size || !allowed_fds.data[fd])) {
                            close(fd);
                        }
                    }
                    bpos += d->d_reclen;
                }
            }
            close(fd_dir);
        }
    }

    exempted_fds.size = 0;
    allowed_fds.size = 0;
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
    sigmask(SIG_BLOCK, SIGCHLD);
    pid = old_fork();

    if (unlikely(!is_child())) return;

    int fd_dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (likely(fd_dir >= 0)) {
        char buf[32768]; 
        int nread;
        while ((nread = syscall(__NR_getdents64, fd_dir, buf, sizeof(buf))) > 0) {
            for (int bpos = 0; bpos < nread;) {
                auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);
                if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                    int fd = fast_atoi(d->d_name);
                    if (fd >= 0) allowed_fds.data[fd] = true;
                }
                bpos += d->d_reclen;
            }
        }
        allowed_fds.data[fd_dir] = false;
        close(fd_dir);
    } else {
        LOGW("Failed to open /proc/self/fd. All fds allowed.");
        __builtin_memset(allowed_fds.data, 1, allowed_fds.size);
    }
}

void ZygiskContext::fork_post() {
    sigmask(SIG_UNBLOCK, SIGCHLD);
    exempted_fds.size = 0;
    allowed_fds.size = 0;
}

void ZygiskContext::run_modules_pre() {
    constexpr size_t MAX_MODULES = 256;
    zygiskd::Module ms[MAX_MODULES];

    size_t size = zygiskd::ReadModules(ms, MAX_MODULES);

    for (size_t i = 0; i < size; i++) {
        auto &m = ms[i];
        uintptr_t base, entry_addr;
        size_t size_mod, init_array, init_count;
        
        if (custom_linker_load(m.memfd, &base, &size_mod, &entry_addr, &init_array, &init_count)) {
            modules.push_back(new ZygiskModule(static_cast<int>(i), (void*)base, (void*)entry_addr));
            LOGV("Module `%s` loaded at %p", m.name, (void*)base);
        }
        close(m.memfd);
    }

    for (size_t i = 0; i < modules.size; i++) {
        auto *m = modules.data[i];
        m->onLoad(env);
        if (flags & APP_SPECIALIZE) m->preAppSpecialize(args.app);
        else if (flags & SERVER_FORK_AND_SPECIALIZE) m->preServerSpecialize(args.server);
    }
}

void ZygiskContext::run_modules_post() {
    flags |= POST_SPECIALIZE;
    size_t modules_unloaded = 0;
    for (size_t i = 0; i < modules.size; i++) {
        const auto *m = modules.data[i];
        if (flags & APP_SPECIALIZE) m->postAppSpecialize(args.app);
        else if (flags & SERVER_FORK_AND_SPECIALIZE) m->postServerSpecialize(args.server);
        if (m->tryUnload()) modules_unloaded++;
    }
    if (modules.size > 0) LOGV("modules unloaded: %zu/%zu", modules_unloaded, modules.size);
}

void ZygiskContext::app_specialize_pre() {
    uid_t uid = args.app->uid;
    bool is_isolated = uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END;

    if (is_isolated) {
        bool found_parent = false;
        if (args.app->app_data_dir) {
            if (const char *dir = env->GetStringUTFChars(args.app->app_data_dir, nullptr)) {
                struct stat st;
                if (stat(dir, &st) == 0) {
                    uid = st.st_uid;
                    found_parent = true;
                }
                env->ReleaseStringUTFChars(args.app->app_data_dir, dir);
            }
        }

        if (!found_parent && args.app->pkg_data_info_list && *args.app->pkg_data_info_list) {
            jobjectArray arr = *args.app->pkg_data_info_list;
            if (env->GetArrayLength(arr) > 0) {
                if (jstring info = static_cast<jstring>(env->GetObjectArrayElement(arr, 0))) {
                    if (const char *str = env->GetStringUTFChars(info, nullptr)) {
                        const char *p = str;
                        if ((p = __builtin_strchr(p, ',')) && (p = __builtin_strchr(p + 1, ',')) &&
                            (p = __builtin_strchr(p + 1, ',')) && *(++p) != '\0') {
                            struct stat st;
                            if (stat(p, &st) == 0) uid = st.st_uid;
                        }
                        env->ReleaseStringUTFChars(info, str);
                    }
                    env->DeleteLocalRef(info);
                }
            }
        }
    }

    bool skip_zygiskd = is_isolated && zygiskd::Connect(1) == -1;
    if (!skip_zygiskd && info_flags == 0) info_flags = zygiskd::GetProcessFlags(uid);

    if ((info_flags & UNMOUNT_MASK) == UNMOUNT_MASK) {
        flags |= DO_REVERT_UNMOUNT;
    }

    flags |= APP_SPECIALIZE;
    if (!skip_zygiskd) run_modules_pre();
}

void ZygiskContext::app_specialize_post() {
    run_modules_post();
    if ((info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
        LOGI("current uid %d is manager!", args.app->uid);
        setenv("ZYGISK_ENABLED", "1", 1);
    }
    env->ReleaseStringUTFChars(args.app->nice_name, process);
}

void ZygiskContext::server_specialize_pre() {
    run_modules_pre();
    zygiskd::SystemServerStarted();
}

void ZygiskContext::server_specialize_post() { run_modules_post(); }

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

void ZygiskContext::nativeSpecializeAppProcess_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre specialize [%s]", process);
    flags |= SKIP_CLOSE_LOG_PIPE;
    app_specialize_pre();

    if (!g_hook->zygote_unmounted && (flags & DO_REVERT_UNMOUNT)) {
        LOGI("AppZygote [%s] is on denylist, performing manual unmount", process);
        
        bool abort = false;
        MountInfoList new_traces = check_zygote_traces(info_flags, &abort);
        g_hook->zygote_traces = static_cast<MountInfoList&&>(new_traces);

        if (!abort) {
            for (size_t i = 0; i < g_hook->zygote_traces.size; i++) {
                const auto& trace = g_hook->zygote_traces.data[i];
                if (trace.skip_unmount) continue;
                LOGV("AppZygote unmounting %s", trace.target);
                umount2(trace.target, MNT_DETACH);
            }
            g_hook->zygote_unmounted = true;
            g_hook->zygote_traces.size = 0;
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
    flags |= APP_FORK_AND_SPECIALIZE;

    if (!g_hook->zygote_unmounted && g_hook->zygote_traces.size == 0) {
        info_flags = zygiskd::GetProcessFlags(args.app->uid);

        bool abort = false;
        g_hook->zygote_traces = check_zygote_traces(info_flags, &abort);

        if (!abort) {
            for (size_t i = 0; i < g_hook->zygote_traces.size; i++) {
                umount2(g_hook->zygote_traces.data[i].target, MNT_DETACH);
            }
            g_hook->zygote_traces.size = 0;
            g_hook->zygote_unmounted = true;
        }
    }

    fork_pre();
    
    if (is_child()) {
        app_specialize_pre();
        if (flags & DO_REVERT_UNMOUNT) {
            if (g_hook->zygote_traces.size == 0) {
                g_hook->zygote_traces = check_zygote_traces(info_flags);
            }

            for (size_t i = 0; i < g_hook->zygote_traces.size; i++) {
                umount2(g_hook->zygote_traces.data[i].target, MNT_DETACH);
            }
            g_hook->zygote_traces.size = 0;
        }
    }
    sanitize_fds();
}

void ZygiskContext::nativeForkAndSpecialize_post() {
    if (is_child()) {
        LOGV("post forkAndSpecialize [%s]", process);
        zygiskd::UnmapSharedMemory();
        app_specialize_post();
    } else {
        if (process) env->ReleaseStringUTFChars(args.app->nice_name, process);
    }
    fork_post();
}

bool ZygiskContext::update_mount_namespace(zygiskd::MountNamespace namespace_type) {
    UniqueFd ns_fd(zygiskd::UpdateMountNamespace(namespace_type));
    if (ns_fd < 0) return false;
    return setns(ns_fd, CLONE_NEWNS) == 0;
}
