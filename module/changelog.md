# NeoZygisk-fork v2.3-308 Update Released

I created this fork because I'm tired of all the detections in the original NeoZygisk, which persist despite NkBe's changes. For now, this fork will only prioritize hiding Zygisk (aside from this, there won't be any other advantages over the original NeoZygisk at the moment).

## Changes since latest version:

* **Bleeding-Edge Toolchain**: Completely migrated to Gradle 9.4.0, Android Gradle Plugin (AGP) 9.0.1, and Kotlin 2.3.10. Also migrated the build script to Gradle's Lazy Configuration API to support Configuration Cache, and relocated Cargo's target cache for cleaner workspace management.

* **Raw NDK Integration**: Eradicated the deprecated rust-android-gradle plugin. Implemented a custom, raw NDK integration linking Android C++ toolchains directly with Cargo. Module .zip size heavily reduced by ~32% due to strict build environment control and stripped unneeded artifacts.

* **Aggressive Memory Sterilization**: Implemented custom memzero and wipe_string routines utilizing volatile pointers to successfully bypass compiler Dead Store Elimination (DSE) caused by -O3/LTO. Also i've optimized plt_hook regex evaluation to save CPU cycles, alongside global optimizations to C/C++ CFLAGS and Rust compilation flags.

* **Remote Memory Leak Fix**: Resolved a critical remote leak in remote_csoloader.cpp by aggressively zeroing and unmapping the injected library path immediately after the open syscall.

* **ELF String Stripping**: Set NO_SONAME in CMake to strip libzygisk.so from the dynamic string table.

* **Zero-Allocation Zygote Forking**: Replaced standard opendir/readdir calls with direct getdents64 syscalls and implemented inline fast_atoi to drastically reduce CPU overhead during process creation. Also injected branch prediction hints (likely/unlikely) into hot paths to reduce CPU pipeline stalls.

* **Aggressive RAM Reclamation**: Forced OS physical RAM reclamation using shrink_to_fit() before forks, and aggressively cleared file descriptors (FDs) across Zygote to eliminate memory bloat.


### Latest detailed changes of my fork:

* **Abandons dlopen, introducing a native CSO Loader**: The injection core of zygisk has been completely restructured, replacing it with a Custom Shared Object (CSO) Loader written natively in C++. Through manual mapping and ELF relocation, "zero linker traces" are achieved, making the injected module completely invisible in the system's soinfo tracking list.
*Credits to **@ThePedroo** for C implementation of CSOLoader, base for this implementation*

* **Deep Memory Disguise (memfd_create)**: Targeting high-strength root detectors scans such as Native Detector, the originally easily detectable anonymous executable memory ([anon]) is replaced with a memfd-based virtual file descriptor. The injected payload will now perfectly disguise itself as a legitimate JIT-compiled cache (/memfd:jit-cache).

* **Implement Abstract Unix Domain Sockets**: The communication mechanism of the daemon process has been completely upgraded to abstract namespace sockets (abandoning the traditional physical .sock files), ensuring that no physical communication node traces are left in the physical file system.

* **Smart IFUNC Resolver**: To address the crash issue of Android Bionic indirect functions (such as memcpy) encountered when bypassing dlopen, a new local symbol resolution and offset mapping algorithm has been added to ensure stable operation of the C++ virtual machine without the assistance of the official Linker.

* **Bionic Crash Interception**: Intercepts and takes over the destruction and registration process of global variables in C++. This successfully prevents the Bionic system from triggering the ABRT(6) security self-destruct mechanism due to the detection of registration requests from unknown memory sources.

* **Remote execution of native constructors**: CSOLoader can now precisely locate and safely execute DT_INIT_ARRAY within the target process, ensuring that C++ standard library components such as std::string and std::vector are correctly initialized without triggering a segmentation fault.

* **Removal of redundant attexit memory scanner**: Thanks to the new CSOLoader hiding architecture, modules no longer need to brute-force scan and modify the internal structure of libc.so (g_array) at runtime to erase traces. This significantly reduces unnecessary memory operation noise, lowers the risk of being detected by heuristic scanning, and also removes the old clean_linker_trace.

* **Massive Codebase Debloat & Future-Proofing**: Completely eradicated the highly unstable and fragile `solist` (linker soinfo parser) and `fossil` (memory scanner/spoofer) implementations. By relying purely on the new CSOLoader architecture, thousands of lines of obsolete code were purged. This guarantees extreme stability and makes the fork completely immune to future Android OS updates (e.g., Android 17 linker changes) that typically break traditional memory list parsers.

* **Zero-Allocation I/O & Extreme Boot Performance**: Rewrote critical early-boot components (`seccomp` handling, file reading, and unmount parsing) to utilize pure C raw syscalls (`read()`) and fixed stack buffers. By completely eliminating dynamic heap allocations (`malloc`, `std::string`, `std::ifstream`) during Zygote's initialization, this prevents memory fragmentation, avoids allocator deadlocks, and drastically reduces the injection overhead, ensuring lightning-fast boot times.

* **App Zygote Root Detection Bypass**: Addressed a critical vulnerability where `Isolated Services` (such as Chromium sandboxed renderers and banking app secure environments) inherited a dirty mount namespace. By enforcing a manual and surgical `umount` during `nativeSpecializeAppProcess`, the fork now successfully bypasses root detection in highly secure isolated processes and prevents kernel panics associated with leaked file descriptors.

* **Improvements in Unmount**: Introduced a highly optimized, pure C parser for mount points, allowing the injector to clean up Magisk/KernelSU traces at maximum speed without relying on heavy C++ standard library wrappers.
