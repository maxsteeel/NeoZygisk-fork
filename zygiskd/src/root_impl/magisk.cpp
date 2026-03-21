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
#include <unordered_set>
#include <unordered_map>
#include <dlfcn.h>

#include "constants.hpp"
#include "logging.hpp"
#include "utils.hpp" // For UniquePipe

namespace magisk {

// --- High-Performance Cache Structures ---
struct Cache {
    struct timespec db_mtime = {0, -1};
    struct timespec pkg_mtime = {0, -1};
    std::unordered_set<int32_t> granted_uids;
    std::unordered_set<int32_t> denylist_uids;
    std::unordered_set<int32_t> all_known_uids;
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
static std::string magisk_variant_pkg;

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

    std::vector<int32_t> get_int_list(const char* query) {
        std::vector<int32_t> result;
        if (!is_valid() || !fn_prepare || !fn_step || !fn_column_text || !fn_finalize) return result;
        void* stmt = nullptr;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            while (fn_step(stmt) == SQLITE_ROW) {
                const unsigned char* text = fn_column_text(stmt, 0);
                if (text) {
                    result.push_back(atoi((const char*)text));
                }
            }
            fn_finalize(stmt);
        }
        return result;
    }

    std::vector<std::string> get_string_list(const char* query) {
        std::vector<std::string> result;
        if (!is_valid() || !fn_prepare || !fn_step || !fn_column_text || !fn_finalize) return result;
        void* stmt = nullptr;

        if (fn_prepare(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
            while (fn_step(stmt) == SQLITE_ROW) {
                const unsigned char* text = fn_column_text(stmt, 0);
                if (text) {
                    result.push_back((const char*)text);
                }
            }
            fn_finalize(stmt);
        }
        return result;
    }
};

// --- General Magisk Detection ---

static void detect_variant() {
    std::call_once(variant_flag, []() {
        if (auto version_str = utils::exec_command({"magisk", "-v"})) {
            for (const auto& pair : MAGISK_THIRD_PARTIES) {
                if (version_str.value().find(pair.first) != std::string::npos) {
                    LOGI("Detected Magisk variant: %s", pair.first);
                    magisk_variant_pkg = pair.second;
                    return;
                }
            }
        }
        LOGI("Detected official Magisk variant.");
        magisk_variant_pkg = MAGISK_OFFICIAL_PKG;
    });
}

std::optional<Version> detect_version() {
    auto version_str = utils::exec_command({"magisk", "-V"});
    if (!version_str) return std::nullopt;

    int version = std::stoi(version_str.value());
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

static void update_cache() {
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
    g_cache.all_known_uids.clear();
    g_cache.manager_uid = -1;
    g_cache.manager_resolved = false;

    MagiskDB db;
    std::vector<std::string> denylist_pkgs;

    if (db.is_valid()) {
        auto uids = db.get_int_list("SELECT uid FROM policies WHERE policy=2");
        g_cache.granted_uids.insert(uids.begin(), uids.end());

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
    } else {
        // Fallback for libsqlite.so failure using magisk --sqlite
        if (auto output = utils::exec_command({"magisk", "--sqlite", "SELECT uid FROM policies WHERE policy=2"})) {
            std::string out = output.value();
            size_t pos = 0;
            while ((pos = out.find("uid=", pos)) != std::string::npos) {
                pos += 4;
                size_t end = out.find('\n', pos);
                if (end == std::string::npos) end = out.length();
                std::string uid_str = out.substr(pos, end - pos);
                int32_t parsed_uid = fast_atoi(uid_str.c_str());
                if (parsed_uid > 0) {
                    g_cache.granted_uids.insert(parsed_uid);
                }
            }
        }

        if (auto output = utils::exec_command({"magisk", "--sqlite", "SELECT package_name FROM denylist"})) {
            std::string out = output.value();
            size_t pos = 0;
            while ((pos = out.find("package_name=", pos)) != std::string::npos) {
                pos += 13;
                size_t end = out.find('\n', pos);
                if (end == std::string::npos) end = out.length();
                denylist_pkgs.push_back(out.substr(pos, end - pos));
            }
        }

        if (auto output = utils::exec_command({"magisk", "--sqlite", "SELECT value FROM strings WHERE key='requester' LIMIT 1"})) {
            std::string val = output.value();
            if (val.find("value=") == 0) {
                std::string manager_pkg = val.substr(6);
                size_t end = manager_pkg.find('\n');
                if (end != std::string::npos) manager_pkg = manager_pkg.substr(0, end);
                char path[256];
                snprintf(path, sizeof(path), "/data/user_de/0/%s", manager_pkg.c_str());
                struct stat st;
                if (stat(path, &st) == 0) {
                    g_cache.manager_uid = st.st_uid;
                }
            }
        }
    }

    if (g_cache.manager_uid == -1 && !magisk_variant_pkg.empty()) {
        char path[256];
        snprintf(path, sizeof(path), "/data/user_de/0/%s", magisk_variant_pkg.c_str());
        struct stat st;
        if (stat(path, &st) == 0) {
            g_cache.manager_uid = st.st_uid;
        }
    }

    // Mark manager resolution as attempted to prevent infinite cache thrashing
    g_cache.manager_resolved = true;

    // Resolve denylist packages to UIDs via packages.list once
    // and track all known UIDs to prevent fallback N+1 executions
    std::unordered_set<std::string_view> target_pkgs;
    for (const auto& pkg : denylist_pkgs) {
        target_pkgs.insert(pkg);
    }

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

            int32_t parsed_uid = atoi(uid_str);
            g_cache.all_known_uids.insert(parsed_uid);

            if (target_pkgs.find(pkg_name) != target_pkgs.end()) {
                g_cache.denylist_uids.insert(parsed_uid);
            }
        }
    }

    g_cache.db_mtime = db_st.st_mtim;
    g_cache.pkg_mtime = pkg_st.st_mtim;
}

static bool is_valid_pkg_name(const std::string& pkg_name) {
    if (pkg_name.empty() || pkg_name.length() > 255) return false;
    for (char c : pkg_name) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

static std::string to_hex(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        out += hex[c >> 4];
        out += hex[c & 0xf];
    }
    return out;
}

static bool get_package_by_uid_from_xml(int32_t uid, std::string& pkg_name) {
    int fd = open("/data/system/packages.xml", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    const char* map = (const char*)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

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
                pkg_name.assign(name_pos, end_pos - name_pos);
                found = true;
            }
        }
    }

    munmap((void*)map, st.st_size);
    return found;
}

bool uid_granted_root(int32_t uid) {
    update_cache();
    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    return g_cache.granted_uids.find(uid) != g_cache.granted_uids.end();
}

bool uid_should_umount(int32_t uid) {
    update_cache();
    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    if (g_cache.denylist_uids.find(uid) != g_cache.denylist_uids.end()) {
        return true;
    }
    if (g_cache.all_known_uids.find(uid) != g_cache.all_known_uids.end()) {
        return false;
    }
    lock.unlock(); // Release lock before executing external command

    // Fallback for missing packages in packages.list (e.g. freshly installed or system apps)
    std::string pkg_name;
    if (!get_package_by_uid_from_xml(uid, pkg_name)) {
        return false;
    }

    if (pkg_name.empty() || !is_valid_pkg_name(pkg_name)) return false;

    MagiskDB db;
    if (db.is_valid()) {
        return db.check_exists("SELECT 1 FROM denylist WHERE package_name=? LIMIT 1", pkg_name.c_str());
    }

    std::string query = "SELECT 1 FROM denylist WHERE package_name=CAST(X'" + to_hex(pkg_name) + "' AS TEXT) LIMIT 1";
    return utils::exec_command({"magisk", "--sqlite", query}).has_value();
}

bool uid_is_manager(int32_t uid) {
    update_cache();
    std::shared_lock<std::shared_mutex> lock(g_cache_mutex);
    return g_cache.manager_uid == uid;
}

} // namespace magisk
