#include "magisk.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <mutex>
#include <dlfcn.h>

#include "constants.hpp"
#include "logging.hpp"
#include "utils.hpp" // For UniquePipe

namespace magisk {

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

// Escapes single quotes for SQL string literals (e.g. ' -> '')
static std::string quote_sql_str(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

bool uid_granted_root(int32_t uid) {
    MagiskDB db;
    if (db.is_valid()) {
        return db.check_exists("SELECT 1 FROM policies WHERE uid=? AND policy=2 LIMIT 1", uid);
    }

    // Fallback just in case libsqlite.so fails to load
    char query[128];
    snprintf(query, sizeof(query), "SELECT 1 FROM policies WHERE uid=%d AND policy=2 LIMIT 1", uid);
    return utils::exec_command({"magisk", "--sqlite", query}).has_value();
}

bool uid_should_umount(int32_t uid) {
    std::string pkg_name;
    std::string uid_str = std::to_string(uid);
    size_t uid_len = uid_str.length();

    UniqueFile fp(fopen("/data/system/packages.list", "re"));
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            char* space1 = strchr(line, ' ');
            if (!space1) continue;

            char* uid_start = space1 + 1;
            if (strncmp(uid_start, uid_str.c_str(), uid_len) == 0 && uid_start[uid_len] == ' ') {
                pkg_name.assign(line, space1 - line);
                break;
            }
        }
    }

    if (pkg_name.empty()) {
        auto list = utils::exec_command({"pm", "list", "packages", "--uid", std::to_string(uid)});
        if (!list) return false;

        // Output is typically "package:com.example.app uid:10000"
        std::string list_str = list.value();
        size_t pos = list_str.find("package:");
        if (pos == std::string::npos) return false;

        pos += 8; // "package:"
        size_t space_pos = list_str.find(' ', pos);
        pkg_name = list_str.substr(pos, space_pos == std::string::npos ? std::string::npos : space_pos - pos);
    }

    if (pkg_name.empty()) return false;

    MagiskDB db;
    if (db.is_valid()) {
        return db.check_exists("SELECT 1 FROM denylist WHERE package_name=? LIMIT 1", pkg_name.c_str());
    }

    // Fallback
    if (!is_valid_pkg_name(pkg_name)) {
        LOGW("Invalid package name for fallback: %s", pkg_name.c_str());
        return false;
    }
    std::string query = "SELECT 1 FROM denylist WHERE package_name='" + quote_sql_str(pkg_name) + "' LIMIT 1";
    return utils::exec_command({"magisk", "--sqlite", query}).has_value();
}

bool uid_is_manager(int32_t uid) {
    MagiskDB db;
    if (db.is_valid()) {
        char val[128];
        if (db.get_string("SELECT value FROM strings WHERE key='requester' LIMIT 1", val, sizeof(val))) {
            char path[256];
            snprintf(path, sizeof(path), "/data/user_de/0/%s", val);
            struct stat st;
            if (stat(path, &st) == 0) {
                return st.st_uid == static_cast<uid_t>(uid);
            }
        }
    } else {
        // Fallback
        const char* query = "SELECT value FROM strings WHERE key='requester' LIMIT 1";
        if (auto output = utils::exec_command({"magisk", "--sqlite", query})) {
            std::string val = output.value();
            if (val.find("value=") == 0) {
                std::string manager_pkg = val.substr(6);
                if (is_valid_pkg_name(manager_pkg)) {
                    char path[256];
                    snprintf(path, sizeof(path), "/data/user_de/0/%s", manager_pkg.c_str());
                    struct stat st;
                    if (stat(path, &st) == 0) {
                        return st.st_uid == static_cast<uid_t>(uid);
                    }
                }
            }
        }
    }

    if (!magisk_variant_pkg.empty()) {
        char path[256];
        snprintf(path, sizeof(path), "/data/user_de/0/%s", magisk_variant_pkg.c_str());
        struct stat st;
        if (stat(path, &st) == 0) {
            return st.st_uid == static_cast<uid_t>(uid);
        }
    }

    LOGD("Could not determine Magisk manager UID.");
    return false;
}

} // namespace magisk
