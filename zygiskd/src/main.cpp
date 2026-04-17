#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "logging.hpp"
#include "constants.hpp"
#include "zygiskd_main.hpp"
#include "companion.hpp"
#include "root_impl.hpp"
#include "mount.hpp"
#include "utils.hpp"

// We are providing our own Android logger equivalent if building daemon directly or linking common logging.
// common logging uses Android __android_log_print and PLOGE/LOGE macros.

int main(int argc, char** argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "companion") == 0) {
            if (argc >= 3) {
                int fd = fast_atoi(argv[2]);
                companion::entry(fd);
            } else {
                LOGE("Companion: Missing file descriptor argument.");
            }
            return 0;
        } else if (strcmp(argv[1], "version") == 0) {
            printf("NeoZygisk daemon %s\n", ZKSU_VERSION);
            return 0;
        } else if (strcmp(argv[1], "root") == 0) {
            root_impl::setup();
            printf("Detected root implementation: %d\n", static_cast<int>(root_impl::get()));
            return 0;
        }
    }

    // Default to starting the main daemon.

    // We must be in the root mount namespace to function correctly.
    if (!zygisk_mount::switch_mount_namespace(1)) {
        LOGE("Zygiskd daemon failed to switch mount namespace");
        return 1;
    }

    // Detect and globally set the root implementation.
    root_impl::setup();
    LOGI("Current root implementation: %d", static_cast<int>(root_impl::get()));

    return zygiskd_main::main();
}
