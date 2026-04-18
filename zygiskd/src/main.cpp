#include "main.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "logging.hpp"
#include "constants.hpp"
#include "root_impl.hpp"
#include "mount.hpp"
#include "utils.hpp"

int main(int argc, char** argv) {
    if (argc >= 2 && argv[1]) {
        switch (argv[1][0]) {
            case 'c':
                if (strcmp(argv[1], "companion") == 0) {
                    if (argc >= 3 && argv[2]) {
                        companion::entry(fast_atoi(argv[2]));
                        return 0;
                    } else {
                        LOGE("Companion: Missing file descriptor argument.");
                        return 1; // Devolver error, no éxito
                    }
                }
                break;
            case 'v':
                if (strcmp(argv[1], "version") == 0) {
                    printf("NeoZygisk daemon %s\n", ZKSU_VERSION);
                    return 0;
                }
                break;
            case 'r':
                if (strcmp(argv[1], "root") == 0) {
                    root_impl::setup();
                    printf("Detected root implementation: %d\n", static_cast<int>(root_impl::get()));
                    return 0;
                }
                break;
            default:
                break;
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
