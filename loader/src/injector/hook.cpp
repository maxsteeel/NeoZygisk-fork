#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <stdint.h>
#include <stdlib.h>

#include <lsplt.hpp>

#include "android_util.hpp"
#include "elf_utils.hpp"
#include "daemon.hpp"
#include "misc.hpp"
#include "module.hpp"
#include "zygisk.hpp"
#include "constants.hpp"

extern constants::ZygiskSharedData* g_shared_data;
const char *moduleId = "zygisksu";

// *********************
// Zygisk Bootstrapping
// *********************
//
// Zygisk's lifecycle is driven by several PLT function hooks in libandroid_runtime, libart, and
// libnative_bridge. As Zygote is starting up, these carefully selected functions will call into
// the respective lifecycle callbacks in Zygisk to drive the progress forward.
//
// The entire bootstrap process is shown in the graph below.
// Arrows represent control flow, and the blocks are sorted chronologically from top to bottom.
//
//       libandroid_runtime                zygisk                 libart
//
//           ┌───────┐                 ┌─────────────┐
//           │ start │                 │ remote_call │
//           └───┬───┘                 └──────┬──────┘
//               │                            │
//               │                            ▼
//               │                        ┌────────┐
//               │                        │hook_plt│
//               │                        └────────┘
//               ▼
//   ┌──────────────────────┐
//   │ strdup("ZygoteInit") │
//   └───────────┬────┬─────┘
//               │    │                ┌───────────────┐
//               │    └───────────────►│hook_zygote_jni│
//               │                     └───────────────┘       ┌─────────┐
//               │                                             │         │
//               └────────────────────────────────────────────►│   JVM   │
//                                                             │         │
//                                                             └──┬─┬────┘
//     ┌───────────────────┐                                      │ │
//     │nativeXXXSpecialize│◄─────────────────────────────────────┘ │
//     └─────────────┬─────┘                                        │
//                   │                 ┌─────────────┐              │
//                   └────────────────►│ZygiskContext│              │
//                                     └─────────────┘              ▼
//                                                       ┌─────────────────────────┐
//                                                       │pthread_attr_setstacksize│
//                                                       └──────────┬──────────────┘
//                                    ┌────────────────┐            │
//                                    │restore_plt_hook│◄───────────┘
//                                    └────────────────┘
//
// Some notes regarding the important functions/symbols during bootstrap:
//
// * HookContext::hook_plt(): hook functions like |unshare| and |strdup|
// * strdup: called in AndroidRuntime::start before calling ZygoteInit#main(...)
// * HookContext::hook_zygote_jni(): replace the process specialization functions registered
//   with register_jni_procs. This marks the final step of the code injection bootstrap process.
// * pthread_attr_setstacksize: called whenever the JVM tries to setup threads for itself. We use
//   this method to cleanup and unmap Zygisk from the process.

constexpr const char *kZygoteInit = "com.android.internal.os.ZygoteInit";
constexpr const char *kZygote = "com/android/internal/os/Zygote";

// Global contexts:
//
// HookContext lives as long as Zygisk is loaded in memory. It tracks the process's function
// hooking state and bootstraps code injection until we replace the process specialization methods.
//
// ZygiskContext lives during the process specialization process. It implements Zygisk
// features, such as loading modules and customizing process fork/specialization.

ZygiskContext *g_ctx;
HookContext *g_hook;
JniHookDefinitions *get_defs() { return g_hook; }

static ino_t g_art_inode = 0;
static dev_t g_art_dev = 0;
// -----------------------------------------------------------------

#define DCL_HOOK_FUNC(ret, func, ...)                                                  \
    ret (*old_##func)(__VA_ARGS__);                                                    \
    ret new_##func(__VA_ARGS__)

DCL_HOOK_FUNC(static char *, strdup, const char *str) {

    static bool zygote_hooked = false;

    if (unlikely(!zygote_hooked && str != nullptr)) {
        if (*str == 'c' && __builtin_strcmp(kZygoteInit, str) == 0) {
            g_hook->hook_zygote_jni();

            // Wipe the old map paths populated by hook_plt() before overwriting them.
            // The new scan will repopulate the map info with the same paths, but they 
            // will be wiped again in hook_zygote_jni() after we are done with hooking.
            g_hook->clear_map_paths();
            g_hook->refresh_map_infos();
            zygote_hooked = true;
        }
    }
    return old_strdup(str);
}

// Skip actual fork and return cached result if applicable
DCL_HOOK_FUNC(int, fork) { 
    // It is unlikely that we are providing a cached PID
    if (unlikely(g_ctx && g_ctx->pid >= 0)) {
        return g_ctx->pid;
    }
    return old_fork(); 
}

// Unmount stuffs in the process's private mount namespace
DCL_HOOK_FUNC(static int, unshare, int flags) {
    if (unlikely(g_ctx && (flags & CLONE_NEWNS) && !(g_ctx->flags & SERVER_FORK_AND_SPECIALIZE))) {
        bool should_unmount = !(g_ctx->info_flags & (PROCESS_IS_MANAGER | PROCESS_GRANTED_ROOT)) &&
                              g_ctx->flags & DO_REVERT_UNMOUNT;
        if (!should_unmount && g_hook->zygote_unmounted) {
            ZygiskContext::update_mount_namespace(zygiskd::MountNamespace::Root);
        }
        bool is_zygote_clean = g_hook->zygote_unmounted && g_hook->zygote_traces.size == 0;
        if (should_unmount && !is_zygote_clean) {
            ZygiskContext::update_mount_namespace(zygiskd::MountNamespace::Clean);
        }
    }
    return old_unshare(flags);
}

DCL_HOOK_FUNC(int, property_get, const char *key, char *value, const char *default_value) {

    static bool unloader_triggered = false;

    if (unlikely(!unloader_triggered)) {
        unloader_triggered = true;

        if (!g_hook->skip_hooking_unloader) {
            g_hook->hook_unloader();
            g_hook->skip_hooking_unloader = true;

            for (size_t i = g_hook->plt_backup.size; i > 0; ) {
                i--;
                const auto& bkp = g_hook->plt_backup.data[i];

                if (bkp.backup_ptr == reinterpret_cast<void*>(old_property_get)) {
                    if (!lsplt::RegisterHook(bkp.dev, bkp.inode, bkp.sym, *bkp.backup_ptr, nullptr) ||
                        !lsplt::CommitHook(g_hook->cached_map_infos, true)) {
                        PLOGE("unhook %s", bkp.sym);
                    } else {
                        if (i < g_hook->plt_backup.size - 1) {
                            __builtin_memmove(&g_hook->plt_backup.data[i], &g_hook->plt_backup.data[i + 1], 
                                              (g_hook->plt_backup.size - i - 1) * sizeof(PltBackupEntry));
                        }
                        g_hook->plt_backup.size--;
                    }
                }
            }
            g_hook->clear_map_paths();
        }
    }
    return old_property_get(key, value, default_value);
}

// We cannot directly call `munmap` to unload ourselves, otherwise when `munmap` returns,
// it will return to our code which has been unmapped, causing segmentation fault.
// Instead, we hook `pthread_attr_setstacksize` which will be called when VM daemon threads start.
DCL_HOOK_FUNC(static int, pthread_attr_setstacksize, void *target, size_t size) {
    int res = old_pthread_attr_setstacksize((pthread_attr_t *) target, size);

    if (unlikely(g_hook != nullptr && g_hook->should_unmap)) {
        // Only perform unloading on the main thread
        HookContext* tmp = g_hook;
        g_hook = nullptr; // Safety null-pointer assignment
        tmp->restore_plt_hook();
        void *addr = tmp->start_addr;
        size_t size = tmp->block_size;
        delete tmp;

        // Because both `pthread_attr_setstacksize` and `munmap` have the same function
        // signature, we can use `musttail` to let the compiler reuse our stack frame and thus
        // `munmap` will directly return to the caller of `pthread_attr_setstacksize`.
        LOGV("unmap libzygisk.so loaded at %p with size %zu", addr, size);
        [[clang::musttail]] return munmap(addr, size);
    }

    return res;
}

#undef DCL_HOOK_FUNC

// -----------------------------------------------------------------
static size_t get_fd_max() {
    rlimit r{32768, 32768};
    getrlimit(RLIMIT_NOFILE, &r);
    return r.rlim_max;
}

ZygiskContext::ZygiskContext(JNIEnv *env, void *args)
    : env(env),
      args{args},
      process(nullptr),
      pid(-1),
      flags(0),
      info_flags(0),
      hook_info_lock(PTHREAD_MUTEX_INITIALIZER) {

    size_t fd_max = get_fd_max();
    allowed_fds.capacity = fd_max;
    allowed_fds.size = fd_max;
    allowed_fds.data = (bool*)malloc(fd_max * sizeof(bool));
    __builtin_memset(allowed_fds.data, 0, fd_max * sizeof(bool));
    g_ctx = this;
}

ZygiskContext::~ZygiskContext() {
    // This global pointer points to a variable on the stack.
    // Set this to nullptr to prevent leaking local variable.
    // This also disables most plt hooked functions.
    g_ctx = nullptr;
    if (!is_child()) return;
    for (size_t i = 0; i < modules.size; i++) modules.data[i]->clearApi();
    g_hook->should_unmap = true;
    g_hook->restore_zygote_hook(env);
}

// -----------------------------------------------------------------

HookContext::HookContext(void *start_addr, size_t block_size)
    : start_addr{start_addr}, block_size{block_size} {};

void HookContext::register_hook(dev_t dev, ino_t inode, const char *symbol, void *new_func, void **old_func) {
    if (!lsplt::RegisterHook(dev, inode, symbol, new_func, old_func)) {
        LOGE("failed to register plt_hook \"%s\"\n", symbol);
        return;
    }
    plt_backup.push_back({dev, inode, symbol, old_func});
}

#define PLT_HOOK_REGISTER_SYM(DEV, INODE, SYM, NAME)                                       \
    register_hook(DEV, INODE, SYM, reinterpret_cast<void *>(new_##NAME),                           \
                  reinterpret_cast<void **>(&old_##NAME))

#define PLT_HOOK_REGISTER(DEV, INODE, NAME) PLT_HOOK_REGISTER_SYM(DEV, INODE, #NAME, NAME)

void HookContext::refresh_map_infos() {
    map_info_cache.size = 0;
    cached_map_infos = lsplt::Scan();
    
    for (size_t i = 0; i < cached_map_infos.size; i++) {
        const auto& map = cached_map_infos.data[i];
        if (map.path[0] != '\0') {
            const char* filename = __builtin_strrchr(map.path, '/');
            filename = filename ? filename + 1 : map.path;
            CachedMapEntry entry;
            entry.name = filename;
            entry.name_hash = calc_gnu_hash(filename);
            entry.info = &map;
            map_info_cache.push_back(entry);
        }
    }

    if (map_info_cache.size > 0) {
        ::sort(map_info_cache.data, map_info_cache.data + map_info_cache.size,
               [](const CachedMapEntry& a, const CachedMapEntry& b) {
                   return a.name_hash < b.name_hash;
               });
    }
}

void HookContext::hook_plt() {
    ino_t android_runtime_inode = 0;
    dev_t android_runtime_dev = 0;

    refresh_map_infos();

    if (const auto* info = find_in_cache(map_info_cache, "libandroid_runtime.so")) {
        android_runtime_inode = info->inode;
        android_runtime_dev = info->dev;
    }

    if (const auto* info = find_in_cache(map_info_cache, "libart.so")) {
        g_art_inode = info->inode;
        g_art_dev = info->dev;
    }

    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, fork);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, unshare);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, strdup);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, property_get);

    if (!lsplt::CommitHook(cached_map_infos)) LOGE("HookContext::hook_plt failed");

    size_t new_size = 0;
    for (size_t i = 0; i < plt_backup.size; i++) {
        if (*plt_backup.data[i].backup_ptr != nullptr) {
            plt_backup.data[new_size++] = plt_backup.data[i];
        }
    }
    plt_backup.size = new_size;
}

void HookContext::hook_unloader() {
    clear_map_paths();
    refresh_map_infos();
    if (g_art_inode == 0 || g_art_dev == 0) {
        if (const auto* info = find_in_cache(map_info_cache, "libart.so")) {
            g_art_inode = info->inode;
            g_art_dev = info->dev;
        }
    }

    PLT_HOOK_REGISTER(g_art_dev, g_art_inode, pthread_attr_setstacksize);
    if (!lsplt::CommitHook(cached_map_infos)) {
        LOGE("HookContext::hook_unloader failed");
    }
}

void HookContext::clear_map_paths() {
    static atomic_flag clearing = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set_explicit(&clearing, memory_order_acquire)) return;

    for (size_t i = 0; i < cached_map_infos.size; i++) {
        auto& map = cached_map_infos.data[i];
        size_t len = strnlen(map.path, sizeof(map.path));
        if (len > 0) memzero(map.path, len);
    }

    atomic_flag_clear_explicit(&clearing, memory_order_release); 
}

void HookContext::restore_plt_hook() {
    for (size_t i = 0; i < plt_backup.size; i++) {
        const auto& bkp = plt_backup.data[i];
        if (!lsplt::RegisterHook(bkp.dev, bkp.inode, bkp.sym, *bkp.backup_ptr, nullptr)) {
            LOGE("failed to register plt_hook [%s]", bkp.sym);
            should_unmap = false;
        }
    }
    if (!lsplt::CommitHook(cached_map_infos, true)) {
        LOGE("failed to restore plt_hook");
        should_unmap = false;
    }

    // Clear cached map info
    clear_map_paths();
    cached_map_infos.size = 0;
}

// -----------------------------------------------------------------

void HookContext::hook_jni_methods(JNIEnv *env, const char *clz, JNIMethods methods) {
    auto clazz = env->FindClass(clz);
    if (clazz == nullptr) {
        env->ExceptionClear();
        for (auto &method : methods) method.fnPtr = nullptr;
        return;
    }

    JNINativeMethod* hooks = new JNINativeMethod[methods.size()];
    size_t hooks_count = 0;

    for (auto &native_method : methods) {
        if (!native_method.fnPtr) continue;

        auto method_id = env->GetMethodID(clazz, native_method.name, native_method.signature);
        bool is_static = false;
        if (method_id == nullptr) {
            env->ExceptionClear();
            method_id = env->GetStaticMethodID(clazz, native_method.name, native_method.signature);
            is_static = true;
        }
        if (method_id == nullptr) {
            env->ExceptionClear();
            native_method.fnPtr = nullptr;
            continue;
        }
        auto method = util::jni::ToReflectedMethod(env, clazz, method_id, is_static);
        auto modifier = util::jni::CallIntMethod(env, method, member_getModifiers);
        if ((modifier & MODIFIER_NATIVE) == 0) {
            native_method.fnPtr = nullptr;
            continue;
        }
        auto artMethod = util::art::ArtMethod::FromReflectedMethod(env, method);
        hooks[hooks_count++] = native_method;
        auto original_method = artMethod->GetData();
        LOGV("replaced %s!%s @%p", clz, native_method.name, original_method);
        native_method.fnPtr = original_method;
    }

    if (hooks_count > 0) env->RegisterNatives(clazz, hooks, hooks_count);
    delete[] hooks;
}

void HookContext::hook_zygote_jni() {
    auto get_created_java_vms = reinterpret_cast<jint (*)(JavaVM **, jsize, jsize *)>(
        dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    if (!get_created_java_vms) {
        void* sym = resolve_symbol("libnativehelper.so", "JNI_GetCreatedJavaVMs");
        if (sym) {
            get_created_java_vms = reinterpret_cast<decltype(get_created_java_vms)>(sym);
        } else {
            LOGW("JNI_GetCreatedJavaVMs not found in memory");
            return;
        }
    }
    JavaVM *vm = nullptr;
    jsize num = 0;
    jint res = get_created_java_vms(&vm, 1, &num);
    if (res != JNI_OK || vm == nullptr) return;
    JNIEnv *env = nullptr;
    res = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (res != JNI_OK || env == nullptr) return;

    auto classMember = util::jni::FindClass(env, "java/lang/reflect/Member");
    if (classMember != nullptr)
        member_getModifiers = util::jni::GetMethodID(env, classMember, "getModifiers", "()I");
    auto classModifier = util::jni::FindClass(env, "java/lang/reflect/Modifier");
    if (classModifier != nullptr) {
        auto fieldId = util::jni::GetStaticFieldID(env, classModifier, "NATIVE", "I");
        if (fieldId != nullptr)
            MODIFIER_NATIVE = util::jni::GetStaticIntField(env, classModifier, fieldId);
    }
    if (member_getModifiers == nullptr || MODIFIER_NATIVE == 0) return;
    if (!util::art::ArtMethod::Init(env)) {
        LOGE("failed to init ArtMethod");
        return;
    }
    hook_jni_methods(env, kZygote, JNIMethods(zygote_methods, sizeof(zygote_methods) / sizeof(zygote_methods[0])));
}

void HookContext::restore_zygote_hook(JNIEnv *env) {
    hook_jni_methods(env, kZygote, JNIMethods(zygote_methods, sizeof(zygote_methods) / sizeof(zygote_methods[0])));
}

// -----------------------------------------------------------------

void hook_entry(void *start_addr, size_t block_size) {
    UniqueFd shm_fd(zygiskd::GetZygiskSharedData());
    if (shm_fd >= 0) {
        void* map_res = mmap(nullptr, sizeof(constants::ZygiskSharedData), PROT_READ, MAP_SHARED, shm_fd, 0);
        if (map_res != MAP_FAILED) {
            g_shared_data = static_cast<constants::ZygiskSharedData*>(map_res);
            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, g_shared_data, sizeof(constants::ZygiskSharedData), "jit-cache");
            LOGI("Successfully mapped shared data!");
        } else {
            PLOGE("Failed to mmap zygisk-shm");
        }
    } else {
        LOGE("Failed to get zygisk shared data fd");
    }

    g_hook = new HookContext(start_addr, block_size);
    g_hook->hook_plt();
}

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods) {
    g_hook->hook_jni_methods(env, clz, {methods, (size_t) numMethods});
}
