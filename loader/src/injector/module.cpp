#include "module.hpp"

#include <android/dlext.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
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
#include "dl.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "misc.hpp"
#include "zygisk.hpp"
#include "custom_linker.hpp"
#include "utils.hpp"

static __thread sigjmp_buf g_segv_jmp_buf;
static __thread volatile sig_atomic_t g_in_module_load = 0;
static struct sigaction old_segv, old_bus;

static void module_segv_handler(int sig, siginfo_t *info, void *context) {
    if (g_in_module_load) {
        siglongjmp(g_segv_jmp_buf, 1);
    }

    // Chain to previous handler if not caught by us
    struct sigaction *old_sa = (sig == SIGSEGV) ? &old_segv : &old_bus;
    if (old_sa->sa_flags & SA_SIGINFO) {
        if (old_sa->sa_sigaction) {
            old_sa->sa_sigaction(sig, info, context);
        }
    } else {
        if (old_sa->sa_handler == SIG_DFL || old_sa->sa_handler == SIG_IGN) {
            signal(sig, SIG_DFL);
            raise(sig);
        } else if (old_sa->sa_handler) {
            old_sa->sa_handler(sig);
        }
    }
}

class ModuleSecurityGuard {
    void* altstack_mem;
    struct sigaction old_segv, old_bus;
    stack_t old_ss;

public:
    ModuleSecurityGuard() {
        altstack_mem = malloc(SIGSTKSZ);
        stack_t ss = {}; 
        ss.ss_sp = altstack_mem;
        ss.ss_flags = 0;
        ss.ss_size = SIGSTKSZ;
        sigaltstack(&ss, &old_ss);
        struct sigaction sa = {};
        sa.sa_sigaction = module_segv_handler;
        sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, &old_segv);
        sigaction(SIGBUS, &sa, &old_bus);
    }

    ~ModuleSecurityGuard() {
        sigaction(SIGSEGV, &old_segv, nullptr);
        sigaction(SIGBUS, &old_bus, nullptr);

        stack_t disable_ss = {};
        disable_ss.ss_flags = SS_DISABLE;
        sigaltstack(&disable_ss, nullptr);
        free(altstack_mem);
    }
};

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
    return dlclose(handle) == 0;
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

static inline bool is_simple_literal(const char *str) {
    return strpbrk(str, ".*+?^$[]|()\\") == nullptr;
}

void ZygiskContext::plt_hook_register(const char *regex, const char *symbol, void *fn, void **backup) {
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
    register_info.push_back(info);
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
    if (register_info.size == 0) return;
    const size_t ignore_count = ignore_info.size;
    
    // Fast-stack allocation for matches
    uint8_t* ign_matches = static_cast<uint8_t*>(__builtin_alloca(ignore_count));

    for (size_t i = 0; i < g_hook->cached_map_infos.size; i++) {
        auto& map = g_hook->cached_map_infos.data[i];
        if (map.offset != 0 || !map.is_private || !(map.perms & PROT_READ)) continue;

        for (size_t j = 0; j < ignore_count; ++j) {
            auto &ign = ignore_info.data[j];
            if (!ign.is_regex) {
                ign_matches[j] = (__builtin_strstr(map.path, ign.literal) != nullptr);
            } else {
                ign_matches[j] = (regexec(&ign.regex, map.path, 0, nullptr, 0) == 0);
            }
        }

        for (size_t k = 0; k < register_info.size; k++) {
            auto& reg = register_info.data[k];
            if (!reg.is_regex) {
                if (!__builtin_strstr(map.path, reg.literal)) continue;
            } else {
                if (regexec(&reg.regex, map.path, 0, nullptr, 0) != 0) continue;
            }
            bool ignored = false;
            for (size_t j = 0; j < ignore_count; ++j) {
                auto &ign = ignore_info.data[j];
                if (ign.symbol[0] != '\0' && __builtin_strcmp(ign.symbol, reg.symbol) != 0) continue;
                if (ign_matches[j]) {
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

        for (size_t i = 0; i < register_info.size; i++) memzero(register_info.data[i].symbol, sizeof(register_info.data[i].symbol));
        for (size_t i = 0; i < ignore_info.size; i++) memzero(ignore_info.data[i].symbol, sizeof(ignore_info.data[i].symbol));

        register_info.size = 0;
        ignore_info.size = 0;
    }
    return lsplt::CommitHook(g_hook->cached_map_infos);
}

void ZygiskContext::sanitize_fds() {
    if (unlikely(!is_child())) return;

    if (can_exempt_fd() && exempted_fds.size > 0) {
        auto update_fd_array = [&](int old_len) -> jintArray {
            jintArray array = env->NewIntArray(static_cast<int>(old_len + exempted_fds.size));
            if (array == nullptr) return nullptr;

            env->SetIntArrayRegion(array, old_len, static_cast<int>(exempted_fds.size), exempted_fds.data);
            for (size_t i = 0; i < exempted_fds.size; i++) {
                int fd = exempted_fds.data[i];
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size) {
                    allowed_fds.data[fd] = true;
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
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size) {
                    allowed_fds.data[fd] = true;
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

    if (is_kernel_5_9_or_newer()) {
        unsigned int start_fd = 0;
        bool in_range = false;
        size_t n = allowed_fds.size;
        for (size_t i = 0; i < n; ++i) {
            if (!allowed_fds.data[i]) {
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
        int fd_dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
        if (likely(fd_dir >= 0)) {
            char buf[4096];
            int nread;
            while ((nread = syscall(__NR_getdents64, fd_dir, buf, sizeof(buf))) > 0) {
                for (int bpos = 0; bpos < nread;) {
                    auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);
                    if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                        int fd = fast_atoi(d->d_name);
                        if (unlikely((fd < 0 || static_cast<size_t>(fd) >= allowed_fds.size ||
                                      !allowed_fds.data[fd]) && fd != fd_dir)) {
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

    int fd_dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (likely(fd_dir >= 0)) {
        char buf[4096];
        int nread;
        while ((nread = syscall(__NR_getdents64, fd_dir, buf, sizeof(buf))) > 0) {
            for (int bpos = 0; bpos < nread;) {
                auto d = reinterpret_cast<struct linux_dirent64 *>(buf + bpos);
                if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                    int fd = fast_atoi(d->d_name);
                    // Ensure the list is big enough dynamically
                    while (static_cast<size_t>(fd) >= allowed_fds.capacity) {
                        allowed_fds.push_back(false);
                    }
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
    ModuleSecurityGuard guard;

    size_t size = zygiskd::ReadModules(ms, MAX_MODULES);

    for (size_t i = 0; i < size; i++) {
        auto &m = ms[i];
        g_in_module_load = 1;
        if (sigsetjmp(g_segv_jmp_buf, 1) == 0) {
            uintptr_t base, entry_addr;
            size_t size_mod, init_array, init_count;
            if (custom_linker_load(m.memfd, &base, &size_mod, &entry_addr, &init_array, &init_count)) {
                void* handle = reinterpret_cast<void*>(base); 
                void* entry = reinterpret_cast<void*>(entry_addr);
                modules.push_back(new ZygiskModule(static_cast<int>(i), handle, entry));
                LOGV("Module `%s` loaded with custom linker at %p (size: 0x%zx)", m.name, handle, size_mod);
            } else {
                LOGW("Custom linker failed for module `%s`. Falling back to dlopen.", m.name);
                void *handle = DlopenMem(m.memfd, RTLD_NOW);
                void *entry = handle ? dlsym(handle, "zygisk_module_entry") : nullptr;
                if (handle && entry) {
                    modules.push_back(new ZygiskModule(static_cast<int>(i), handle, entry));
                }
            }
        } else {
            LOGE("Module `%s` crashed during dlopen/dlsym. Disabling.", m.name);
            if (m.memfd >= 0) { close(m.memfd); m.memfd = -1; }
            if (!custom_linker_cleanup()) LOGE("Failed to clean up after module `%s` crash.", m.name);
            if (zygiskd::ReportModuleCrash(i) != 0) PLOGE("Failed to report module crash for module `%s`", m.name);
        }
        g_in_module_load = 0;
        close(m.memfd);
    }

    size_t valid_modules = 0;
    for (size_t i = 0; i < modules.size; i++) {
        auto *m = modules.data[i];
        auto &mod = ms[m->id];
        bool crashed = false;

        g_in_module_load = 1;
        if (sigsetjmp(g_segv_jmp_buf, 1) == 0) {
            m->onLoad(env);
            if (flags & APP_SPECIALIZE) m->preAppSpecialize(args.app);
            else if (flags & SERVER_FORK_AND_SPECIALIZE) m->preServerSpecialize(args.server);
        } else {
            crashed = true;
            LOGE("Module `%s` crashed during onLoad/preSpecialize.", mod.name);
        }
        g_in_module_load = 0;

        if (!crashed) {
            // Keep valid modules packed at the front
            if (valid_modules != i) modules.data[valid_modules] = modules.data[i];
            valid_modules++;
        } else {
            delete m;
        }
    }
    modules.size = valid_modules; // Drop crashed modules efficiently

    for (size_t i = 0; i < size; i++) memzero(ms[i].name, sizeof(ms[i].name));
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
    bool is_isolated_aid = uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END;

    if (is_isolated_aid && args.app->app_data_dir) {
        bool found_parent = false;
        if (args.app->app_data_dir) {
            const char *data_dir = env->GetStringUTFChars(args.app->app_data_dir, nullptr);
            if (data_dir != nullptr) {
                struct stat st;
                if (stat(data_dir, &st) == 0) {
                    uid = st.st_uid;
                    found_parent = true;
                    LOGV("identify isolated service via app_data_dir [uid:%d, data_dir:%s]", uid, data_dir);
                }
                env->ReleaseStringUTFChars(args.app->app_data_dir, data_dir);
            }
        }

        if (!found_parent && args.app->pkg_data_info_list && *args.app->pkg_data_info_list) {
            jobjectArray pkg_array = *args.app->pkg_data_info_list; 
            jint count = env->GetArrayLength(pkg_array);
            if (count > 0) {
                jstring pkg_data_info = (jstring) env->GetObjectArrayElement(pkg_array, 0);
                if (pkg_data_info) {
                    const char *info_str = env->GetStringUTFChars(pkg_data_info, nullptr);
                    if (info_str) {
                        const char *p = info_str;
                        if ((p = __builtin_strchr(p, ',')) && (p = __builtin_strchr(p + 1, ',')) &&
                            (p = __builtin_strchr(p + 1, ',')) && *(++p) != '\0') {
                            const char *data_dir = p;
                            struct stat st;
                            if (stat(data_dir, &st) == 0) {
                                uid = st.st_uid;
                                LOGV("identify isolated service via pkg_data_info [uid:%d, data_dir:%s]", uid, data_dir);
                            }
                        }
                        env->ReleaseStringUTFChars(pkg_data_info, info_str);
                    }
                    env->DeleteLocalRef(pkg_data_info);
                }
            }
        }
    }

    bool skip_zygiskd = is_isolated_aid && zygiskd::Connect(1) == -1;
    if (!skip_zygiskd && info_flags == 0) info_flags = zygiskd::GetProcessFlags(uid);

    if ((info_flags & UNMOUNT_MASK) == UNMOUNT_MASK) {
        LOGI("[%s] is on the denylist", process);
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

bool abort_zygote_unmount(const MountInfoList &traces, uint32_t info_flags) {
    if (traces.size == 0) {
        LOGV("abort unmounting zygote with an empty trace list");
        return true;
    }
    bool is_magisk = info_flags & PROCESS_ROOT_IS_MAGISK;
    for (size_t i = 0; i < traces.size; i++) {
        const auto& trace = traces.data[i];
        if (__builtin_strncmp(trace.target, "/product", 8) == 0) {
            if (__builtin_strncmp(trace.target, "/product/bin", 12) == 0) continue;
            if (!is_magisk && __builtin_strcmp(trace.target, "/product") != 0) continue;
            LOGV("abort unmounting zygote due to prohibited target: [%s]", trace.target);
            return true;
        }
    }
    return false;
}

void ZygiskContext::nativeSpecializeAppProcess_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre specialize [%s]", process);
    flags |= SKIP_CLOSE_LOG_PIPE;
    app_specialize_pre();

    if (!g_hook->zygote_unmounted && (flags & DO_REVERT_UNMOUNT)) {
        LOGI("AppZygote [%s] is on denylist, performing manual unmount", process);
        
        MountInfoList new_traces = check_zygote_traces(info_flags);
        
        // Copiamos datos al context global manualmente
        g_hook->zygote_traces.size = 0;
        for(size_t i=0; i<new_traces.size; i++) g_hook->zygote_traces.push_back(new_traces.data[i]);

        if (!abort_zygote_unmount(g_hook->zygote_traces, info_flags)) {
            for (size_t i = 0; i < g_hook->zygote_traces.size; i++) {
                const auto& trace = g_hook->zygote_traces.data[i];
                if (__builtin_strcmp(trace.source, "magisk") == 0) continue;
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
    LOGV("pre forkAndSpecialize [%s]", process);
    flags |= APP_FORK_AND_SPECIALIZE;

    if (!g_hook->zygote_unmounted && g_hook->zygote_traces.size == 0) {
        info_flags = zygiskd::GetProcessFlags(args.app->uid);

        MountInfoList new_traces = check_zygote_traces(info_flags);
        g_hook->zygote_traces.size = 0;
        for(size_t i=0; i<new_traces.size; i++) g_hook->zygote_traces.push_back(new_traces.data[i]);

        if (!abort_zygote_unmount(g_hook->zygote_traces, info_flags)) {
            size_t valid = 0;
            for (size_t i = 0; i < g_hook->zygote_traces.size; i++) {
                const auto& trace = g_hook->zygote_traces.data[i];
                if (__builtin_strcmp(trace.source, "magisk") == 0) {
                    LOGV("skip magisk specific mounts for compatibility: %s", trace.source);
                    g_hook->zygote_traces.data[valid++] = trace; 
                } else {
                    LOGV("unmounting %s (mnt_id: %u)", trace.target, trace.id);
                    if (umount2(trace.target, MNT_DETACH) != 0) {
                        LOGE("failed to unmount %s: %s", trace.target, strerror(errno));
                        g_hook->zygote_traces.data[valid++] = trace; 
                    }
                }
            }
            g_hook->zygote_traces.size = valid;
            g_hook->zygote_unmounted = true;
        }
    }

    fork_pre();
    if (is_child()) {
        app_specialize_pre();
        if (flags & DO_REVERT_UNMOUNT) {
            LOGI("Reverting mounts for denylisted app: %s", process);
            MountInfoList traces = check_zygote_traces(info_flags);
            for (size_t i = 0; i < traces.size; i++) {
                LOGV("Child unmounting %s", traces.data[i].target);
                umount2(traces.data[i].target, MNT_DETACH);
            }
        }
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

bool ZygiskContext::update_mount_namespace(zygiskd::MountNamespace namespace_type) {
    const char *type_str = (namespace_type == zygiskd::MountNamespace::Clean ? "Clean" : "Root");
    LOGV("updating mount namespace to type %s", type_str);

    int ns_fd = zygiskd::UpdateMountNamespace(namespace_type);

    if (ns_fd < 0) {
        LOGW("mount namespace [%s] not available/cached", type_str);
        return false;
    }

    int ret = setns(ns_fd, CLONE_NEWNS);
    if (ret != 0) {
        PLOGE("setns failed for type %s", type_str);
        close(ns_fd);
        return false;
    }
    close(ns_fd);
    return true;
}
