#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

#include "root_impl.hpp"
#include "constants.hpp"
#include "logging.hpp"
#include "daemon.hpp" 
#include "utils.hpp" 

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
static RWLock g_cache_mutex;

static const char* MAGISK_OFFICIAL_PKG = "com.topjohnwu.magisk";
struct StringPair { const char* first; const char* second; };
static const StringPair MAGISK_THIRD_PARTIES[] = {
    {"alpha", "io.github.vvb2060.magisk"},
    {"kitsune", "io.github.huskydg.magisk"},
};

static ::once_flag variant_flag = 0;
static char magisk_variant_pkg[128] = {0};

// --- Native SQLite Implementation ---
typedef int (*sqlite3_open_t)(const char*, void**);
typedef int (*sqlite3_prepare_v2_t)(void*, const char*, int, void**, const char**);
typedef int (*sqlite3_step_t)(void*);
typedef int (*sqlite3_finalize_t)(void*);
typedef int (*sqlite3_close_t)(void*);
typedef const unsigned char* (*sqlite3_column_text_t)(void*, int);

#define SQLITE_OK 0
#define SQLITE_ROW 100

struct SQLiteLibrary {
    void* handle = nullptr;
    sqlite3_open_t fn_open = nullptr;
    sqlite3_prepare_v2_t fn_prepare = nullptr;
    sqlite3_step_t fn_step = nullptr;
    sqlite3_finalize_t fn_finalize = nullptr;
    sqlite3_close_t fn_close = nullptr;
    sqlite3_column_text_t fn_column_text = nullptr;

    SQLiteLibrary() {
        handle = dlopen("libsqlite.so", RTLD_NOW);
        if (!handle) return;
        
        fn_open = (sqlite3_open_t)dlsym(handle, "sqlite3_open");
        fn_prepare = (sqlite3_prepare_v2_t)dlsym(handle, "sqlite3_prepare_v2");
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

class MagiskDB {
private:
    void* db = nullptr;
    const SQLiteLibrary& lib;

public:
    MagiskDB() : lib(SQLiteLibrary::get()) {
        if (lib.fn_open && lib.fn_close) {
            if (lib.fn_open("/data/adb/magisk.db", &db) != SQLITE_OK) db = nullptr;
        }
    }

    ~MagiskDB() {
        if (db && lib.fn_close) lib.fn_close(db);
    }

    bool is_valid() const { return db != nullptr; }

    void load_policies(IntList& uids) {
        if (!is_valid() || !lib.fn_prepare || !lib.fn_step || !lib.fn_column_text || !lib.fn_finalize) return;
        void* stmt = nullptr;
        if (lib.fn_prepare(db, "SELECT uid FROM policies WHERE policy=2", -1, &stmt, nullptr) == SQLITE_OK) {
            while (lib.fn_step(stmt) == SQLITE_ROW) {
                const char* text = (const char*)lib.fn_column_text(stmt, 0);
                if (text) uids.push_back(fast_atoi(text));
            }
            lib.fn_finalize(stmt);
        }
    }

    void load_denylist(StringList& pkgs) {
        if (!is_valid() || !lib.fn_prepare || !lib.fn_step || !lib.fn_column_text || !lib.fn_finalize) return;
        void* stmt = nullptr;
        if (lib.fn_prepare(db, "SELECT package_name FROM denylist", -1, &stmt, nullptr) == SQLITE_OK) {
            while (lib.fn_step(stmt) == SQLITE_ROW) {
                const char* text = (const char*)lib.fn_column_text(stmt, 0);
                if (text) pkgs.push_back(text); 
            }
            lib.fn_finalize(stmt);
        }
    }

    bool get_requester(char* out_buf, size_t max_len) {
        if (!is_valid() || !lib.fn_prepare || !lib.fn_step || !lib.fn_column_text || !lib.fn_finalize) return false;
        void* stmt = nullptr;
        bool result = false;
        if (lib.fn_prepare(db, "SELECT value FROM strings WHERE key='requester' LIMIT 1", -1, &stmt, nullptr) == SQLITE_OK) {
            if (lib.fn_step(stmt) == SQLITE_ROW) {
                const char* text = (const char*)lib.fn_column_text(stmt, 0);
                if (text) {
                    strlcpy(out_buf, text, max_len);
                    result = true;
                }
            }
            lib.fn_finalize(stmt);
        }
        return result;
    }
};

// --- Lightweight Sorting & Deduplication ---

static void sort_pkgs(StringList& list) {
    if (list.size <= 1) return;
    ::sort(list.data, list.data + list.size, [](const char* a, const char* b) {
        return strcmp(a, b) < 0;
    });

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
    if (list.size <= 1) return;
    ::sort(list.data, list.data + list.size, [](int32_t a, int32_t b) {
        return a < b;
    });

    size_t unique_count = 1;
    for (size_t i = 1; i < list.size; ++i) {
        if (list.data[i] != list.data[unique_count - 1]) {
            list.data[unique_count++] = list.data[i];
        }
    }
    list.size = unique_count;
}

static inline int cmp_int(const void* a, const void* b) {
    return (*(int32_t*)a - *(int32_t*)b);
}

static inline int cmp_str(const void* a, const void* b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

static bool list_contains_uid(const IntList& list, int32_t value) {
    if (list.size == 0) return false;
    return bsearch(&value, list.data, list.size, sizeof(int32_t), cmp_int) != nullptr;
}

static bool list_contains_pkg(const StringList& list, const char* value) {
    if (list.size == 0) return false;
    return bsearch(&value, list.data, list.size, sizeof(char*), cmp_str) != nullptr;
}

// --- General Magisk Detection ---
static void detect_variant() {
    ::call_once(variant_flag, []() {
        char buf[256];
        const char* args[] = {"magisk", "-v", nullptr};
        if (utils::exec_command(args, buf, sizeof(buf))) {
            for (const auto& pair : MAGISK_THIRD_PARTIES) {
                if (strstr(buf, pair.first) != nullptr) {
                    LOGI("Detected Magisk variant: %s", pair.first);
                    strlcpy(magisk_variant_pkg, pair.second, sizeof(magisk_variant_pkg));
                    return;
                }
            }
        }
        strlcpy(magisk_variant_pkg, MAGISK_OFFICIAL_PKG, sizeof(magisk_variant_pkg));
    });
}

Version detect_version() {
    char buf[256];
    const char* args[] = {"magisk", "-V", nullptr};
    if (!utils::exec_command(args, buf, sizeof(buf))) return Version::Null;

    int version = fast_atoi(buf);
    detect_variant();

    return (version >= MIN_MAGISK_VERSION) ? Version::Supported : Version::TooOld;
}

// --- Hyper-Fast Path Builder ---
static void build_manager_path(char* out_buf, const char* pkg_name) {
    // "/data/user_de/0/" is exactly 16 bytes
    __builtin_memcpy(out_buf, "/data/user_de/0/", 16);
    char* ptr = out_buf + 16;
    while (*pkg_name) *ptr++ = *pkg_name++;
    *ptr = '\0';
}

// --- Zero-Copy Fast Parser (Replaces fgets) ---
static void parse_packages_list() {
    UniqueFd fd(open("/data/system/packages.list", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return;

    char buf[4096];
    size_t current_pos = 0;
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buf + current_pos, sizeof(buf) - current_pos - 1)) > 0) {
        size_t total_bytes = current_pos + bytes_read;
        buf[total_bytes] = '\0';
        char *line_start = buf;
        char *line_end;

        while ((line_end = static_cast<char*>(memchr(line_start, '\n', total_bytes - (line_start - buf)))) != nullptr) {
            *line_end = '\0';

            if (line_start < line_end) {
                char* ptr = line_start;
                while (*ptr > ' ' && ptr < line_end) ++ptr;

                if (ptr < line_end) {
                    *ptr = '\0'; ++ptr;
                    while (*ptr == ' ' && ptr < line_end) ++ptr; // Find end of package name
                    if (*ptr != '\0') {
                        *ptr = '\0'; // Null-terminate pkg name natively
                        ++ptr;
                        while (*ptr == ' ' && ptr < line_end) ++ptr; // Skip spaces to UID

                        if (ptr < line_end) {
                            int32_t parsed_uid = fast_atoi(ptr);
                            if (parsed_uid > 0) {
                                g_cache.all_known_uids.push_back(parsed_uid);
                                if (list_contains_pkg(g_cache.denylist_pkgs, line_start)) {
                                    g_cache.denylist_uids.push_back(parsed_uid);
                                }
                            }
                        }
                    }
                }
                line_start = line_end + 1;
            }
        }

        size_t remaining = total_bytes - (line_start - buf);
        if (remaining > 0 && remaining < sizeof(buf)) {
            memmove(buf, line_start, remaining);
            current_pos = remaining;
        } else {
            current_pos = 0;
        }
    }
    sort_uids(g_cache.all_known_uids);
    sort_uids(g_cache.denylist_uids);
}

// --- High-Performance Database Queries ---
void refresh_cache() {
    struct stat db_st, pkg_st;
    bool db_ok = (stat("/data/adb/magisk.db", &db_st) == 0);
    bool pkg_ok = (stat("/data/system/packages.list", &pkg_st) == 0);

    if (!db_ok) db_st.st_mtim = {0, -1};
    if (!pkg_ok) pkg_st.st_mtim = {0, -1};

    // Fast check (Shared lock)
    {
        SharedMutexGuard read_lock(g_cache_mutex);
        if (g_cache.db_mtime.tv_sec == db_st.st_mtim.tv_sec &&
            g_cache.db_mtime.tv_nsec == db_st.st_mtim.tv_nsec &&
            g_cache.pkg_mtime.tv_sec == pkg_st.st_mtim.tv_sec &&
            g_cache.pkg_mtime.tv_nsec == pkg_st.st_mtim.tv_nsec &&
            g_cache.manager_resolved) {
            return;
        }
    }

    // Heavy update (Unique lock)
    UniqueMutexGuard write_lock(g_cache_mutex);
    
    if (g_cache.db_mtime.tv_sec == db_st.st_mtim.tv_sec &&
        g_cache.db_mtime.tv_nsec == db_st.st_mtim.tv_nsec &&
        g_cache.pkg_mtime.tv_sec == pkg_st.st_mtim.tv_sec &&
        g_cache.pkg_mtime.tv_nsec == pkg_st.st_mtim.tv_nsec &&
        g_cache.manager_resolved) {
        return;
    }

    g_cache.granted_uids.clear();
    g_cache.denylist_uids.clear();
    g_cache.denylist_pkgs.clear(); // StringList destructor calls free on elements
    g_cache.all_known_uids.clear();
    g_cache.manager_uid = -1;

    MagiskDB db;
    if (db.is_valid()) {
        db.load_policies(g_cache.granted_uids);
        db.load_denylist(g_cache.denylist_pkgs);

        char requester[128];
        if (db.get_requester(requester, sizeof(requester))) {
            char path[256];
            build_manager_path(path, requester);
            struct stat st;
            if (stat(path, &st) == 0) g_cache.manager_uid = st.st_uid;
        }
    } else {
        LOGE("NATIVE SQLITE FAILED. Fallback disabled for stability.");
    }

    sort_uids(g_cache.granted_uids);
    sort_pkgs(g_cache.denylist_pkgs);

    if (g_cache.manager_uid == -1 && magisk_variant_pkg[0] != '\0') {
        char path[256];
        build_manager_path(path, magisk_variant_pkg);
        struct stat st;
        if (stat(path, &st) == 0) g_cache.manager_uid = st.st_uid;
    }
    g_cache.manager_resolved = true;

    parse_packages_list();

    g_cache.db_mtime = db_st.st_mtim;
    g_cache.pkg_mtime = pkg_st.st_mtim;
}

// Fixed fast XML parser
static bool get_package_by_uid_from_xml(int32_t uid, char* out_pkg_name, size_t max_len) {
    UniqueFd fd(open("/data/system/packages.xml", O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    char target_uid[32];
    int32_t app_id = uid % 100000;
    
    // Reverse integer build for extreme speed
    char* ptr = target_uid + sizeof(target_uid) - 1;
    *ptr = '\0';
    *(--ptr) = '"';
    do {
        *(--ptr) = '0' + (app_id % 10);
        app_id /= 10;
    } while (app_id > 0);
    const char* prefix = "userId=\"";
    ptr -= 8;
    __builtin_memcpy(ptr, prefix, 8);
    size_t target_len = (target_uid + sizeof(target_uid) - 1) - ptr;

    // Buffer read to avoid SIGBUS from mmap
    char buf[8192];
    ssize_t bytes_read;
    bool found = false;

    while (!found && (bytes_read = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0'; 
        
        const char* pos = (const char*)memmem(buf, bytes_read, ptr, target_len);
        if (pos) {
            const char* cur = pos;
            while (cur > buf && *cur != '<') cur--;

            const char* name_pos = (const char*)memmem(cur, pos - cur, "name=\"", 6);
            if (name_pos) {
                name_pos += 6;
                const char* end_pos = (const char*)memchr(name_pos, '\"', pos - name_pos);
                if (end_pos) {
                    size_t name_len = end_pos - name_pos;
                    if (name_len < max_len) {
                        __builtin_memcpy(out_pkg_name, name_pos, name_len);
                        out_pkg_name[name_len] = '\0';
                        found = true;
                    }
                }
            }
        }
        // If not found in this chunk, rewind slightly to prevent cutting words in half
        if (!found && bytes_read == sizeof(buf) - 1) {
            lseek(fd, -256, SEEK_CUR); 
        }
    }
    return found;
}

static bool is_valid_pkg_name(const char* pkg_name) {
    if (!pkg_name || pkg_name[0] == '\0') return false;
    for (int i = 0; pkg_name[i]; i++) {
        char c = pkg_name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

bool uid_granted_root(int32_t uid) {
    SharedMutexGuard lock(g_cache_mutex);
    return list_contains_uid(g_cache.granted_uids, uid);
}

bool uid_should_umount(int32_t uid) {
    {
        SharedMutexGuard read_lock(g_cache_mutex);
        if (list_contains_uid(g_cache.denylist_uids, uid)) return true;
        if (list_contains_uid(g_cache.all_known_uids, uid)) return false;
    }

    char pkg_name[128];
    if (!get_package_by_uid_from_xml(uid, pkg_name, sizeof(pkg_name))) return false;
    if (!is_valid_pkg_name(pkg_name)) return false;

    SharedMutexGuard read_lock(g_cache_mutex);
    return list_contains_pkg(g_cache.denylist_pkgs, pkg_name);
}

bool uid_is_manager(int32_t uid) {
    SharedMutexGuard lock(g_cache_mutex);
    return g_cache.manager_uid == uid;
}

} // namespace magisk

