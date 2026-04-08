#include "magisk.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <dlfcn.h>

#include "constants.hpp"
#include "logging.hpp"
#include "daemon.hpp" // UniqueFd
#include "utils.hpp" // UniquePipe, StringList, IntList

namespace magisk {

// --- High-Performance Cache Structures ---
struct Cache {
    struct timespec db_mtime = {0, -1};
    struct timespec pkg_mtime = {0, -1};
    IntList granted_uids;
    IntList denylist_uids;
    StringList denylist_pkgs;
    IntList all_known_uids;
    bool manager_resolved = false;
    int32_t manager_uid = -1;
};

static Cache g_cache;
static std::shared_mutex g_cache_mutex;

static const char* MAGISK_OFFICIAL_PKG = "com.topjohnwu.magisk";
static const std::pair<const char*, const char*> MAGISK_THIRD_PARTIES[] = {
    {"alpha", "io.github.vvb2060.magisk"},
    {"kitsune", "io.github.huskydg.magisk"},
};

static std::once_flag variant_flag;
static char magisk_variant_pkg[128] = {0};

// --- Native SQLite Implementation ---

// Function pointer types for dynamically loading SQLite
typedef int (*sqlite3_open_t)(const char*, void**);
typedef int (*sqlite3_prepare_v2_t)(void*, const char*, int, void**, const char**);
typedef int (*sqlite3_bind_text_t)(void*, int, const char*, int, void (*)(void*));
typedef int (*sqlite3_bind_int_t)(void*, int, int);
typedef int (*sqlite3_step_t)(void*);
typedef int (*sqlite3_finalize_t)(void*);
typedef int (*sqlite3_close_t)(void*);
typedef const unsigned char* (*sqlite3_column_text_t)(void*, int);

#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_TRANSIENT ((void (*)(void*)) - 1)

// Caches the loaded library handle and resolved function pointers
struct SQLiteLibrary {
    void* handle = nullptr;
    sqlite3_open_t fn_open = nullptr;
    sqlite3_prepare_v2_t fn_prepare = nullptr;
    sqlite3_bind_text_t fn_bind_text = nullptr;
    sqlite3_bind_int_t fn_bind_int = nullptr;
    sqlite3_step_t fn_step = nullptr;
    sqlite3_finalize_t fn_finalize = nullptr;
    sqlite3_close_t fn_close = nullptr;
    sqlite3_column_text_t fn_column_text = nullptr;

    SQLiteLibrary() {
        // Load Android's native SQLite library dynamically to avoid bloating the binary
        handle = dlopen("libsqlite.so", RTLD_NOW);
        if (!handle) {
            LOGW("Failed to dlopen libsqlite.so");
            return;
        }
        fn_open = (sqlite3_open_t)dlsym(handle, "sqlite3_open");
        fn_prepare = (sqlite3_prepare_v2_t)dlsym(handle, "sqlite3_prepare_v2");
        fn_bind_text = (sqlite3_bind_text_t)dlsym(handle, "sqlite3_bind_text");
        fn_bind_int = (sqlite3_bind_int_t)dlsym(handle, "sqlite3_bind_int");
        fn_step = (sqlite3_step_t)dlsym(handle, "sqlite3_step");
        fn_finalize = (sqlite3_finalize_t)dlsym(handle, "sqlite3_finalize");
        fn_close = (sqlite3_close_t)dlsym(handle, "sqlite3_close");
        fn_column_text = (sqlite3_column_text_t)dlsym(handle, "sqlite3_column_text");
    }

    static const SQLiteLibrary& get() {
        static SQLiteLibrary instance;
        return instance;
    }
};

// Lightweight wrapper to interact with Android's native libsqlite.so
class MagiskDB {
private:
    void* db = nullptr;

    sqlite3_open_t fn_open = nullptr;
    sqlite3_prepare_v2_t fn_prepare = nullptr;
    sqlite3_bind_text_t fn_bind_text = nullptr;
    sqlite3_bind_int_t fn_bind_int = nullptr;
    sqlite3_step_t fn_step = nullptr;
    sqlite3_finalize_t fn_finalize = nullptr;
    sqlite3_close_t fn_close = nullptr;
    sqlite3_column_text_t fn_column_text = nullptr;

public:
    MagiskDB() {
        const auto& lib = SQLiteLibrary::get();
        if (!lib.handle) return;

        fn_open = lib.fn_open;
        fn_prepare = lib.fn_prepare;
        fn_bind_text = lib.fn_bind_text;
        fn_bind_int = lib.fn_bind_int;
        fn_step = lib.fn_step;
        fn_finalize = lib.fn_finalize;
        fn_close = lib.fn_close;
        fn_column_text = lib.fn_column_text;

        if (fn_open && fn_close) {
            // Open the Magisk database in read-only mode if possible
            if (fn_open("/data/adb/magisk.db", &db) != SQLITE_OK) {
                LOGW("Failed to open /data/adb/magisk.db natively");
                db = nullptr;
            }
        }
    }

    ~MagiskDB() {
        if (db && fn_close) fn_close(db);
    }

    bool is_valid() const { return db != nullptr; }

    // Executes a query and returns true if at least one row is found
    bool check_exists(const char* query) {
        if (!is_valid() || !fn_prepare || !fn_step || !fn_finalize) return false;
        void* stmt = nullptr;
        bool result = false;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            if (fn_step(stmt) == SQLITE_ROW) {
                result = true;
            }
            fn_finalize(stmt);
        }
        return result;
    }

    bool check_exists(const char* query, int arg) {
        if (!is_valid() || !fn_prepare || !fn_bind_int || !fn_step || !fn_finalize) return false;
        void* stmt = nullptr;
        bool result = false;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            if (fn_bind_int(stmt, 1, arg) == SQLITE_OK) {
                if (fn_step(stmt) == SQLITE_ROW) {
                    result = true;
                }
            }
            fn_finalize(stmt);
        }
        return result;
    }

    bool check_exists(const char* query, const char* arg) {
        if (!is_valid() || !fn_prepare || !fn_bind_text || !fn_step || !fn_finalize) return false;
        void* stmt = nullptr;
        bool result = false;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            fn_bind_text(stmt, 1, arg, -1, SQLITE_TRANSIENT);
            if (fn_step(stmt) == SQLITE_ROW) {
                result = true;
            }
            fn_finalize(stmt);
        }
        return result;
    }

    // Executes a query and copies the first column of the first row into out_buf
    bool get_string(const char* query, char* out_buf, size_t max_len) {
        if (!is_valid() || !fn_prepare || !fn_step || !fn_column_text || !fn_finalize) return false;
        void* stmt = nullptr;
        bool result = false;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            if (fn_step(stmt) == SQLITE_ROW) {
                const unsigned char* text = fn_column_text(stmt, 0);
                if (text) {
                    strlcpy(out_buf, (const char*)text, max_len);
                    result = true;
                }
            }
            fn_finalize(stmt);
        }
        return result;
    }

    IntList get_int_list(const char* query) {
        IntList result;
        if (!is_valid() || !fn_prepare || !fn_step || !fn_column_text || !fn_finalize) return result;
        void* stmt = nullptr;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            while (fn_step(stmt) == SQLITE_ROW) {
                const char* text = (const char*)fn_column_text(stmt, 0);
                if (text) {
                    result.push_back(fast_atoi(text));
                }
            }
            fn_finalize(stmt);
        }
        return result;
    }

    StringList get_string_list(const char* query) {
        StringList result;
        if (!is_valid() || !fn_prepare || !fn_step || !fn_column_text || !fn_finalize) return result;
        void* stmt = nullptr;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            while (fn_step(stmt) == SQLITE_ROW) {
                const char* text = (const char*)fn_column_text(stmt, 0);
                if (text) {
                    result.push_back(text);
                }
            }
            fn_finalize(stmt);
        }
        return result;
    }
};

static inline int cmp_int(const void* a, const void* b) {
    return (*(int32_t*)a - *(int32_t*)b);
}

static inline int cmp_str(const void* a, const void* b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

static void sort_pkgs(StringList& list) {
    if (list.size == 0) return;
    qsort(list.data, list.size, sizeof(char*), cmp_str);

    size_t unique_count = 1;
    for (size_t i = 1; i < list.size; ++i) {
        if (strcmp(list.data[i], list.data[unique_count - 1]) != 0) {
            list.data[unique_count++] = list.data[i];
        } else {
            free(list.data[i]); 
        }
    }
    list.size = unique_count;
}

static void sort_uids(IntList& list) {
    if (list.size == 0) return;
    qsort(list.data, list.size, sizeof(int32_t), cmp_int);

    size_t unique_count = 1;
    for (size_t i = 1; i < list.size; ++i) {
        if (list.data[i] != list.data[unique_count - 1]) {
            list.data[unique_count++] = list.data[i];
        }
    }
    list.size = unique_count;
}

static bool list_contains_uid(auto& list, int32_t value) {
    if (list.size == 0) return false;
    return bsearch(&value, list.data, list.size, sizeof(int32_t), cmp_int) != nullptr;
}

static bool list_contains_pkg(auto& list, auto value) {
    if (list.size == 0) return false;
    return bsearch(&value, list.data, list.size, sizeof(char*), cmp_str) != nullptr;
}

// --- General Magisk Detection ---

static void detect_variant() {
    std::call_once(variant_flag, []() {
        char buf[256];
        if (utils::exec_command({"magisk", "-v"}, buf, sizeof(buf))) {
            for (const auto& pair : MAGISK_THIRD_PARTIES) {
                if (strstr(buf, pair.first) != nullptr) {
                    LOGI("Detected Magisk variant: %s", pair.first);
                    strlcpy(magisk_variant_pkg, pair.second, sizeof(magisk_variant_pkg));
                    return;
                }
            }
        }
        LOGI("Detected official Magisk variant.");
        strlcpy(magisk_variant_pkg, MAGISK_OFFICIAL_PKG, sizeof(magisk_variant_pkg));
    });
}

std::optional<Version> detect_version() {
    char buf[256];
    if (!utils::exec_command({"magisk", "-V"}, buf, sizeof(buf))) {
        return std::nullopt;
    }

    int version = fast_atoi(buf);
    detect_variant();

    if (version >= MIN_MAGISK_VERSION) {
        return Version::Supported;
    } else {
        return Version::TooOld;
    }
}

// --- High-Performance Database Queries ---

static bool cache_update_required(struct stat* db_st, struct stat* pkg_st) {
    bool db_ok = (stat("/data/adb/magisk.db", db_st) == 0);
    bool pkg_ok = (stat("/data/system/packages.list", pkg_st) == 0);

    if (!db_ok) db_st->st_mtim = {0, -1};
    if (!pkg_ok) pkg_st->st_mtim = {0, -1};

    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    return g_cache.db_mtime.tv_sec != db_st->st_mtim.tv_sec ||
           g_cache.db_mtime.tv_nsec != db_st->st_mtim.tv_nsec ||
           g_cache.pkg_mtime.tv_sec != pkg_st->st_mtim.tv_sec ||
           g_cache.pkg_mtime.tv_nsec != pkg_st->st_mtim.tv_nsec ||
           (db_ok && g_cache.db_mtime.tv_nsec == -1) ||
           (pkg_ok && g_cache.pkg_mtime.tv_nsec == -1) ||
           !g_cache.manager_resolved; // We will set this to true after attempting to resolve once
}

static void fetch_from_magisk_db(MagiskDB& db, StringList& denylist_pkgs) {
    g_cache.granted_uids = db.get_int_list("SELECT uid FROM policies WHERE policy=2");
    sort_uids(g_cache.granted_uids);

    denylist_pkgs = db.get_string_list("SELECT package_name FROM denylist");

    char val[128];
    if (db.get_string("SELECT value FROM strings WHERE key='requester' LIMIT 1", val, sizeof(val))) {
        char path[256];
        snprintf(path, sizeof(path), "/data/user_de/0/%s", val);
        struct stat st;
        if (stat(path, &st) == 0) {
            g_cache.manager_uid = st.st_uid;
        }
    }
}

static void fetch_from_magisk_sqlite_fallback(StringList& denylist_pkgs) {
    char buf[256];
    if (utils::exec_command({"magisk", "--sqlite", "SELECT uid FROM policies WHERE policy=2"}, buf, sizeof(buf))) {
        const char* out = buf;
        while ((out = strstr(out, "uid=")) != nullptr) {
            out += 4;
            int32_t parsed_uid = fast_atoi(out);
            if (parsed_uid > 0) g_cache.granted_uids.push_back(parsed_uid);
            const char* next_line = strchr(out, '\n');
            if (!next_line) break;
            out = next_line + 1;
        }
        sort_uids(g_cache.granted_uids);
    }

    if (utils::exec_command({"magisk", "--sqlite", "SELECT package_name FROM denylist"}, buf, sizeof(buf))) {
        char* line = buf;
        while (line && *line) {
            char* name_start = strstr(line, "package_name=");
            if (name_start) {
                name_start += 13;
                char* name_end = strchr(name_start, '\n');
                if (name_end) {
                    *name_end = '\0';
                    denylist_pkgs.push_back(name_start);
                    line = name_end + 1;
                } else {
                    denylist_pkgs.push_back(name_start);
                    break;
                }
            } else {
                break;
            }
        }
    }

    if (utils::exec_command({"magisk", "--sqlite", "SELECT value FROM strings WHERE key='requester' LIMIT 1"}, buf, sizeof(buf))) {
        char* val_start = strstr(buf, "value=");
        if (val_start) {
            val_start += 6;
            char* val_end = strchr(val_start, '\n');
            if (val_end) {
                *val_end = '\0';
            }
            if (*val_start != '\0') {
                char path[256];
                snprintf(path, sizeof(path), "/data/user_de/0/%s", val_start);
                struct stat st;
                if (stat(path, &st) == 0) {
                    g_cache.manager_uid = st.st_uid;
                }
            }
        }
    }
}

static void resolve_manager_uid() {
    if (g_cache.manager_uid == -1 && magisk_variant_pkg[0] != '\0') {
        char path[256];
        snprintf(path, sizeof(path), "/data/user_de/0/%s", magisk_variant_pkg);
        struct stat st;
        if (stat(path, &st) == 0) {
            g_cache.manager_uid = st.st_uid;
        }
    }
}

static void parse_packages_list() {
    UniqueFile fp(fopen("/data/system/packages.list", "re"));
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            char* space1 = strchr(line, ' ');
            if (!space1) continue;

            std::string_view pkg_name(line, space1 - line);

            char* uid_str = space1 + 1;
            char* space2 = strchr(uid_str, ' ');
            if (space2) *space2 = '\0';

            int32_t parsed_uid = fast_atoi(uid_str);
            g_cache.all_known_uids.push_back(parsed_uid);

            if (bsearch(&pkg_name, g_cache.denylist_pkgs.data, g_cache.denylist_pkgs.size, sizeof(char*), cmp_str) != nullptr) {
                g_cache.denylist_uids.push_back(parsed_uid);
            }
        }
        sort_uids(g_cache.all_known_uids); 
        sort_uids(g_cache.denylist_uids);
    }
}

void refresh_cache() {
    struct stat db_st, pkg_st;
    if (!cache_update_required(&db_st, &pkg_st)) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(g_cache_mutex);
    // Double-check after acquiring write lock
    if (g_cache.db_mtime.tv_sec == db_st.st_mtim.tv_sec &&
        g_cache.db_mtime.tv_nsec == db_st.st_mtim.tv_nsec &&
        g_cache.pkg_mtime.tv_sec == pkg_st.st_mtim.tv_sec &&
        g_cache.pkg_mtime.tv_nsec == pkg_st.st_mtim.tv_nsec &&
        g_cache.manager_resolved) {
        return;
    }

    g_cache.granted_uids.clear();
    g_cache.denylist_uids.clear();
    g_cache.denylist_pkgs.clear();
    g_cache.all_known_uids.clear();
    g_cache.manager_uid = -1;
    g_cache.manager_resolved = false;

    MagiskDB db;
    StringList denylist_pkgs;

    if (db.is_valid()) {
        fetch_from_magisk_db(db, denylist_pkgs);
    } else {
        // Fallback for libsqlite.so failure using magisk --sqlite
        fetch_from_magisk_sqlite_fallback(denylist_pkgs);
    }

    resolve_manager_uid();

    // Mark manager resolution as attempted to prevent infinite cache thrashing
    g_cache.manager_resolved = true;

    // Resolve denylist packages to UIDs via packages.list once
    // and track all known UIDs to prevent fallback N+1 executions
    sort_pkgs(denylist_pkgs);
    g_cache.denylist_pkgs = std::move(denylist_pkgs);

    parse_packages_list();

    g_cache.db_mtime = db_st.st_mtim;
    g_cache.pkg_mtime = pkg_st.st_mtim;
}

static bool is_valid_pkg_name(const std::string_view& pkg_name) {
    if (pkg_name.empty() || pkg_name.length() > 255) return false;
    for (char c : pkg_name) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}


static bool get_package_by_uid_from_xml(int32_t uid, auto& pkg_name) {
    UniqueFd fd(open("/data/system/packages.xml", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) return false;

    const char* map = (const char*)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (map == MAP_FAILED) return false;

    int32_t app_id = uid % 100000;

    char uid_str[32];
    int len = snprintf(uid_str, sizeof(uid_str), "userId=\"%d\"", app_id);

    char shared_uid_str[32];
    int shared_len = snprintf(shared_uid_str, sizeof(shared_uid_str), "sharedUserId=\"%d\"", app_id);

    const char* pos = (const char*)memmem(map, st.st_size, uid_str, len);
    if (!pos) {
        pos = (const char*)memmem(map, st.st_size, shared_uid_str, shared_len);
    }

    bool found = false;
    if (pos) {
        const char* cur = pos;
        while (cur > map && *cur != '<') cur--;

        const char* name_attr = "name=\"";
        const char* name_pos = (const char*)memmem(cur, pos - cur, name_attr, 6);
        if (name_pos) {
            name_pos += 6;
            const char* end_pos = (const char*)memchr(name_pos, '\"', pos - name_pos);
            if (end_pos) {
                pkg_name = std::string_view(name_pos, end_pos - name_pos);
                found = true;
            }
        }
    }

    munmap((void*)map, st.st_size);
    return found;
}

bool uid_granted_root(int32_t uid) {
    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    return list_contains_uid(g_cache.granted_uids, uid);
}

bool uid_should_umount(int32_t uid) {
    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    if (list_contains_uid(g_cache.denylist_uids, uid)) return true;
    if (list_contains_uid(g_cache.all_known_uids, uid)) return false;
    lock.unlock(); // Release lock before executing external command

    // Fallback for missing packages in packages.list (e.g. freshly installed or system apps)
    std::string_view pkg_name;
    if (!get_package_by_uid_from_xml(uid, pkg_name)) {
        return false;
    }

    if (pkg_name.empty() || !is_valid_pkg_name(pkg_name)) return false;

    lock.lock();
    return list_contains_pkg(g_cache.denylist_pkgs, pkg_name);
}

bool uid_is_manager(int32_t uid) {
    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    return g_cache.manager_uid == uid;
}

} // namespace magisk
