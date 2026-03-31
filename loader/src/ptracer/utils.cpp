#include "utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <link.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <memory>

#include "logging.hpp"
#include "elf_utils.hpp"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PAGE_START(x) ((x) & ~(PAGE_SIZE - 1))
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE - 1))

/**
 * @brief Writes data to another process's memory using process_vm_writev.
 * @return The number of bytes written, or -1 on error.
 */
ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len) {
    // The iovec struct's iov_base is a non-const void*, so we must cast away constness.
    // This is safe as process_vm_writev treats the local iovec as a source.
    struct iovec local {
        .iov_base = const_cast<void *>(buf), .iov_len = len
    };
    struct iovec remote {
        .iov_base = (void *) remote_addr, .iov_len = len
    };

    ssize_t bytes_written = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    if (bytes_written == -1) {
        PLOGE("process_vm_writev to addr 0x%" PRIxPTR, remote_addr);
    } else if (static_cast<size_t>(bytes_written) != len) {
        LOGW("not fully written to 0x%" PRIxPTR ": wrote %zd, expected %zu", remote_addr,
             bytes_written, len);
    }
    return bytes_written;
}

/**
 * @brief Reads data from another process's memory using process_vm_readv.
 * @return The number of bytes read, or -1 on error.
 */
ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    struct iovec local {
        .iov_base = buf, .iov_len = len
    };
    struct iovec remote {
        .iov_base = (void *) remote_addr, .iov_len = len
    };

    ssize_t bytes_read = process_vm_readv(pid, &local, 1, &remote, 1, 0);

    if (bytes_read == -1) {
        PLOGE("process_vm_readv from addr 0x%" PRIxPTR, remote_addr);
    } else if (static_cast<size_t>(bytes_read) != len) {
        LOGW("not fully read from 0x%" PRIxPTR ": read %zd, expected %zu", remote_addr, bytes_read,
             len);
    }
    return bytes_read;
}

// --- Register Manipulation (Architecture Specific) ---

bool get_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("ptrace(PTRACE_GETREGS)");
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec iov = {.iov_base = &regs, .iov_len = sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        PLOGE("ptrace(PTRACE_GETREGSET)");
#if defined(__arm__)
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            PLOGE("fallback to PTRACE_GETREGS");
            return false;
        }
#else
        return false;
#endif
    }
#endif
    return true;
}

bool set_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("ptrace(PTRACE_SETREGS)");
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec iov = {.iov_base = &regs, .iov_len = sizeof(regs)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        PLOGE("ptrace(PTRACE_SETREGSET)");
#if defined(__arm__)
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            PLOGE("fallback to PTRACE_SETREGS");
            return false;
        }
#else
        return false;
#endif
    }
#endif
    return true;
}

/**
 * @brief Finds the base address of a loaded module (the first mapping with zero offset).
 */
void *find_module_base(int pid, std::string_view suffix) {
    void* result = nullptr;
    MapInfo::Scan(pid, [&](const MapInfo& map) {
        if (map.offset == 0 && std::string_view(map.path).ends_with(suffix)) {
            result = (void*)map.start;
            return true; // We find the module, stop scanning
        }
        return false; // Continue scanning
    });
    return result;
}

/**
 * @brief Calculates the address of a function in a remote process.
 *
 * This works by finding the function's address in our own process (`dlopen`/`dlsym`),
 * then finding the base address of its containing library in both our process and the
 * remote process. The remote address is then calculated using the offset from the base.
 * remote_sym = remote_base + (local_sym - local_base)
 */
void *find_func_addr(int local_pid, int remote_pid, std::string_view module, std::string_view func) {
    auto lib = dlopen(module.data(), RTLD_NOW);
    if (lib == nullptr) {
        LOGE("failed to open lib %s: %s", module.data(), dlerror());
        return nullptr;
    }
    void *local_sym = dlsym(lib, func.data());
    dlclose(lib);  // Close the library handle immediately to avoid resource leaks.
    if (local_sym == nullptr) {
        LOGE("failed to find sym %s in %s: %s", func.data(), module.data(), dlerror());
        return nullptr;
    }

    void *local_base = find_module_base(local_pid, module);
    if (local_base == nullptr) {
        LOGE("failed to find local base for module %s", module.data());
        return nullptr;
    }

    void *remote_base = find_module_base(remote_pid, module);
    if (remote_base == nullptr) {
        LOGE("failed to find remote base for module %s", module.data());
        return nullptr;
    }

    uintptr_t remote_addr = (uintptr_t)remote_base + ((uintptr_t) local_sym - (uintptr_t) local_base);
    LOGV("found remote %s!%s at 0x%" PRIxPTR " (local base 0x%" PRIxPTR ", remote base 0x%" PRIxPTR ")",
         module.data(), func.data(), (uintptr_t)remote_addr, (uintptr_t)local_base, (uintptr_t)remote_base);

    return (void *) remote_addr;
}

// --- Remote Call Implementation ---

// Most ABIs require the stack to be 16-byte aligned.
constexpr uintptr_t STACK_ALIGN_MASK = ~0xf;

void align_stack(struct user_regs_struct &regs, long preserve) {
    regs.REG_SP = (regs.REG_SP - preserve) & STACK_ALIGN_MASK;
}

/**
 * @brief Pushes a string onto the remote process's stack.
 * @return The address of the string in the remote process, or 0 on failure.
 */
uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    size_t len = strlen(str) + 1;
    regs.REG_SP -= len;
    align_stack(regs);  // Re-align after subtracting length.

    uintptr_t remote_addr = regs.REG_SP;
    if (write_proc(pid, remote_addr, str, len) != static_cast<ssize_t>(len)) {
        LOGE("failed to write string '%s' to remote process", str);
        return 0;  // Return 0 on failure.
    }
    LOGV("pushed string \"%s\" to 0x%" PRIxPTR, str, remote_addr);
    return remote_addr;
}

/**
 * @brief Executes a function in the remote process.
 *
 * This function is highly architecture-specific. It works by:
 * 1.  Setting up the remote process's registers according to the platform's C calling convention
 * (ABI).
 * 2.  Pushing arguments onto the remote stack if necessary.
 * 3.  Setting the return address register/stack to a specific `return_addr` (usually a
 * non-executable address).
 * 4.  Setting the instruction pointer to the `func_addr`.
 * 5.  Continuing the process, which executes the function.
 * 6.  Waiting for the process to trap (usually via SIGSEGV at our fake return address).
 * 7.  Reading the function's return value from the appropriate register.
 *
 * @return The return value of the remote function, or 0 on failure.
 */
uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                      uintptr_t return_addr, const long *args, size_t argc) {
    align_stack(regs);
    LOGV("calling remote function 0x%" PRIxPTR " with %zu args, return to 0x%" PRIxPTR, func_addr,
         argc, return_addr);

#if defined(__x86_64__)
    // ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
    if (argc > 0) regs.rdi = args[0];
    if (argc > 1) regs.rsi = args[1];
    if (argc > 2) regs.rdx = args[2];
    if (argc > 3) regs.rcx = args[3];
    if (argc > 4) regs.r8 = args[4];
    if (argc > 5) regs.r9 = args[5];
    if (argc > 6) {
        size_t stack_args_size = (argc - 6) * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, regs.REG_SP, args + 6, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push stack arguments for x86_64 call");
            return 0;
        }
    }
    // Push return address
    regs.REG_SP -= sizeof(long);
    if (write_proc(pid, regs.REG_SP, &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("failed to push return address for x86_64 call");
        return 0;
    }
    regs.REG_IP = func_addr;

#elif defined(__i386__)
    // ABI: All arguments on stack, pushed in reverse order.
    // Our vector is already in the correct order to write in one block.
    if (argc > 0) {
        size_t stack_args_size = argc * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, regs.REG_SP, args, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push arguments for i386 call");
            return 0;
        }
    }
    // Push return address
    regs.REG_SP -= sizeof(long);
    if (write_proc(pid, regs.REG_SP, &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("failed to write return addr for i386 call");
        return 0;
    }
    regs.REG_IP = func_addr;

#elif defined(__aarch64__)
    // ABI: x0-x7, then stack
    for (size_t i = 0; i < argc && i < 8; i++) {
        regs.regs[i] = args[i];
    }
    if (argc > 8) {
        size_t stack_args_size = (argc - 8) * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, regs.REG_SP, args + 8, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push stack arguments for aarch64 call");
            return 0;
        }
    }
    regs.regs[30] = return_addr;  // Link Register (LR)
    regs.REG_IP = func_addr;

#elif defined(__arm__)
    // ABI: r0-r3, then stack
    for (size_t i = 0; i < argc && i < 4; i++) {
        regs.uregs[i] = args[i];
    }
    if (argc > 4) {
        size_t stack_args_size = (argc - 4) * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, (uintptr_t) regs.REG_SP, args + 4, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push stack arguments for arm call");
            return 0;
        }
    }
    regs.uregs[14] = return_addr;  // Link Register (LR)
    regs.REG_IP = func_addr;       // Program Counter (PC)

    // Handle Thumb vs ARM mode. The lowest bit of an address indicates Thumb mode.
    // The PC register itself must not have this bit set. It's stored in the CPSR.
    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        // Thumb mode: remove LSB from PC and set T-bit in CPSR
        regs.REG_IP &= ~1;
        regs.uregs[16] |= CPSR_T_MASK;
    } else {
        // ARM mode: clear T-bit in CPSR
        regs.uregs[16] &= ~CPSR_T_MASK;
    }

#else
#error "Unsupported architecture for remote_call"
#endif

    if (!set_regs(pid, regs)) {
        LOGE("remote_call: failed to set registers before call");
        return 0;
    }

    int sig = 0;
    while (true) {
        if (ptrace(PTRACE_CONT, pid, 0, sig) == -1) {
            LOGE("remote_call: ptrace cont failed");
            return 0;
        }

        int status;
        wait_for_trace(pid, &status, __WALL);

        if (!get_regs(pid, regs)) {
            LOGE("remote_call: failed to get registers after call");
            return 0;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            char status_str[256];
            parse_status(status, status_str, sizeof(status_str));
            LOGE("process died unexpectedly after remote call: %s", status_str);
            return 0;
        }

        if (WIFSTOPPED(status)) {
            if (static_cast<uintptr_t>(regs.REG_IP) == return_addr) {
                LOGV("remote call returned, result: 0x%" PRIXPTR, (uintptr_t) regs.REG_RET);
                return regs.REG_RET;
            }

            sig = WSTOPSIG(status);
            if (sig == SIGTRAP || sig == SIGSTOP) {
                sig = 0;
            } else {
                LOGV("remote_call: intercepted natural signal %d, passing to tracee", sig);
            }
        }
    }
}

// --- Process Management ---

/**
 * @brief Creates a fully detached daemon process using a double-fork.
 *
 * A double-fork ensures the final process is not a child of the original process,
 * but rather a child of init (PID 1). This prevents it from becoming a zombie
 * if the original parent exits without waiting for it.
 *
 * @return This function has different return values depending on which process is running:
 *         - In the **original parent process**, it returns the PID of the first child (> 0).
 *         - In the **final daemon (grandchild) process**, it returns 0.
 *         - On an initial fork error, it returns -1.
 */
int fork_dont_care() {
    pid_t pid = fork();
    if (pid < 0) {
        PLOGE("fork child");
        return -1;  // Return -1 on the first fork failure.
    }

    if (pid > 0) {
        // --- Original Parent Process ---
        // The parent waits for the *first* child to exit. This first child exits
        // almost immediately, allowing the parent to continue its work while the
        // second child (the daemon) continues in the background. It then returns
        // the PID of the child it forked, signaling to the caller that it is the parent.
        int status;
        waitpid(pid, &status, __WALL);
        return pid;
    }

    // --- First Child Process ---
    // This process exists only to spawn the final daemon process.
    pid_t grandchild_pid = fork();
    if (grandchild_pid < 0) {
        PLOGE("fork grandchild");
        exit(1);  // Exit with an error code if the second fork fails.
    }

    if (grandchild_pid > 0) {
        // The first child has successfully forked the grandchild, so its job is
        // done. It exits immediately. This orphans the grandchild, which is
        // then adopted by the 'init' process (PID 1). This is the key to detachment.
        exit(0);
    }

    // --- Second Child (Grandchild / Daemon) Process ---
    // The second fork() call returned 0 to this process. Now, we return 0 from
    // this function to let the new daemon's internal logic know that it is the
    // child process and should begin its work.
    return 0;
}

/**
 * @brief Skips the currently trapped syscall for a tracee.
 *
 * When a tracee is stopped due to a PTRACE_EVENT_SECCOMP, it is paused *before*
 * the syscall is executed. This function prevents the syscall from ever running
 * by modifying the tracee's registers.
 *
 * It sets the syscall number register to -1, which is an invalid syscall number.
 * The kernel recognizes this and skips the execution, causing the syscall to
 * immediately return with -ENOSYS, without any side effects.
 *
 * For ARM/ARM64, it also uses architecture-specific ptrace requests as a
 * fallback/alternative method to ensure the syscall is skipped. These might not
alway
s
 * work on all kernel versions, so their errors are ignored.
 *
 * @param pid The process ID of the tracee.
 */
void tracee_skip_syscall(int pid) {
    user_regs_struct regs;
    if (!get_regs(pid, regs)) {
        LOGE("tracee_skip_syscall: failed to get registers");
        exit(1);
    }

    // Set the syscall number to an invalid value (-1).
    // The kernel will see this and skip the syscall execution.
    regs.REG_SYSNR = -1;

    if (!set_regs(pid, regs)) {
        LOGE("tracee_skip_syscall: failed to set registers to skip syscall");
        exit(1);
    }

    // For ARM architectures, there are specific ptrace requests to modify the
    // syscall number. We attempt these as well, but don't check for errors
    // as they may not be supported on all kernels. The register modification
    // above is the primary method.
#if defined(__aarch64__)
    int sysnr = -1;
    struct iovec iov = {.iov_base = &sysnr, .iov_len = sizeof(sysnr)};
    ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
#elif defined(__arm__)
    ptrace(PTRACE_SET_SYSCALL, pid, 0, (void *) -1);
#endif
}

/**
 * @brief Waits for a ptrace event, handling seccomp events specifically.
 *
 * This is a wrapper around waitpid that handles EINTR and automatically
 * continues the process after a PTRACE_EVENT_SECCOMP.
 *
 * @param pid The PID to wait for.
 * @param status A pointer to an integer where the status will be stored.
 * @param flags Flags for waitpid.
 */
void wait_for_trace(int pid, int *status, int flags) {
    while (true) {
        if (waitpid(pid, status, flags) == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by a signal, just retry.
            }
            PLOGE("waitpid(%d)", pid);
            exit(1);
        }

        // Check if the stop was caused by a PTRACE_EVENT_SECCOMP.
        if (*status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            tracee_skip_syscall(pid);
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;  // Continue waiting for the next *real* stop event.
        }

        // If the process terminated or signaled instead of stopping, it's an error.
        if (!WIFSTOPPED(*status)) {
            char status_str[256];
            parse_status(*status, status_str, sizeof(status_str));
            LOGE("process %d did not stop as expected: %s", pid, status_str);
            exit(1);
        }

        // It's a valid stop event that we need to handle, so we return.
        return;
    }
}

void parse_status(int status, char* out_buf, size_t out_size) {
    if (WIFEXITED(status)) {
        snprintf(out_buf, out_size, "exited with %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(out_buf, out_size, "killed by signal %d (%s)", WTERMSIG(status), sigabbrev_np(WTERMSIG(status)));
    } else if (WIFSTOPPED(status)) {
        snprintf(out_buf, out_size, "stopped by signal %d (%s)", WSTOPSIG(status), sigabbrev_np(WSTOPSIG(status)));
    } else {
        snprintf(out_buf, out_size, "unknown status 0x%x", status);
    }
}

/**
 * @brief Gets the executable path of a process from /proc/[pid]/exe.
 * @return true on success, false on failure.
 */
bool get_program(int pid, char* buf, size_t buf_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    auto sz = readlink(path, buf, buf_size - 1);
    if (sz == -1) {
        PLOGE("readlink /proc/%d/exe", pid);
        return false;
    }
    buf[sz] = 0;
    return true;
}

uintptr_t find_syscall_gadget([[maybe_unused]] int local_pid, int remote_pid) {
    void* local_syscall = dlsym(RTLD_DEFAULT, "syscall");
    if (!local_syscall) {
        LOGE("Failed to find local syscall function");
        return 0;
    }

    // Clean the cryptographic signature before pointer arithmetic
    local_syscall = (void*)PAC_STRIP(local_syscall);
    uintptr_t gadget = 0;

    // Scan for a syscall execution instruction
    uint8_t* ptr = (uint8_t*)local_syscall;
    for (int i = 0; i < 1024; i += 4) {
#if defined(__aarch64__)
        if (*(uint32_t*)(ptr + i) == 0xd4000001) { // svc #0
            gadget = (uintptr_t)(ptr + i);
            break;
        }
#elif defined(__x86_64__)
        if (*(uint16_t*)(ptr + i) == 0x050f) { // syscall
            gadget = (uintptr_t)(ptr + i);
            break;
        }
#elif defined(__arm__)
        if (*(uint32_t*)(ptr + i) == 0xef000000 || *(uint32_t*)(ptr + i) == 0xdf00) { // swi 0 or svc 0
            gadget = (uintptr_t)(ptr + i);
            break;
        }
#elif defined(__i386__)
        if (*(uint16_t*)(ptr + i) == 0x80cd) { // int 0x80
            gadget = (uintptr_t)(ptr + i);
            break;
        }
#endif
    }

    if (!gadget) {
        LOGE("Failed to find syscall gadget in local memory");
        return 0;
    }

    uintptr_t local_base = (uintptr_t)find_module_base(local_pid, "libc.so");
    uintptr_t remote_base = (uintptr_t)find_module_base(remote_pid, "libc.so");

    if (!local_base || !remote_base) {
        LOGE("Failed to find libc.so base for syscall gadget translation");
        return 0;
    }

    return remote_base + (gadget - local_base);
}

#ifdef __aarch64__
// BTI compatibility mask
#define AARCH64_PSTATE_BTYPE_MASK (3ull << 10)
#endif

long remote_syscall(int pid, struct user_regs_struct &regs, uintptr_t syscall_gadget, long sysnr, const long *args, size_t args_size) {
    LOGV("remote syscall %ld args %zu at gadget 0x%" PRIxPTR, sysnr, args_size, syscall_gadget);

    // Save current registers to avoid state corruption
    struct user_regs_struct saved_regs = regs;

#if defined(__aarch64__)
    regs.regs[8] = sysnr;
    for (size_t i = 0; i < args_size && i < 6; i++) {
        regs.regs[i] = args[i];
    }
    regs.REG_IP = syscall_gadget;
    // Clear BTYPE so stepping the aarch64 vDSO svc will be accepted by the CPU
    regs.pstate &= ~AARCH64_PSTATE_BTYPE_MASK;
#elif defined(__arm__)
    regs.uregs[7] = sysnr;
    for (size_t i = 0; i < args_size && i < 6; i++) {
        regs.uregs[i] = args[i];
    }
    regs.REG_IP = syscall_gadget;
#elif defined(__x86_64__)
    regs.orig_rax = sysnr;
    regs.rax = sysnr;
    if (args_size > 0) regs.rdi = args[0];
    if (args_size > 1) regs.rsi = args[1];
    if (args_size > 2) regs.rdx = args[2];
    if (args_size > 3) regs.r10 = args[3]; // syscall instruction uses r10 instead of rcx
    if (args_size > 4) regs.r8 = args[4];
    if (args_size > 5) regs.r9 = args[5];
    regs.REG_IP = syscall_gadget;
#elif defined(__i386__)
    regs.orig_eax = sysnr;
    regs.eax = sysnr;
    if (args_size > 0) regs.ebx = args[0];
    if (args_size > 1) regs.ecx = args[1];
    if (args_size > 2) regs.edx = args[2];
    if (args_size > 3) regs.esi = args[3];
    if (args_size > 4) regs.edi = args[4];
    if (args_size > 5) regs.ebp = args[5];
    regs.REG_IP = syscall_gadget;
#endif

    if (!set_regs(pid, regs)) {
        LOGE("Failed to set registers for remote syscall");
        return -1;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
        PLOGE("PTRACE_SINGLESTEP syscall");
        set_regs(pid, saved_regs); // Safe restore
        return -1;
    }

    int status;
    wait_for_trace(pid, &status, __WALL);

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        char status_str[256];
        parse_status(status, status_str, sizeof(status_str));
        LOGE("remote syscall unexpected stop: %s", status_str);
        set_regs(pid, saved_regs);
        return -1;
    }

    if (!get_regs(pid, regs)) {
        LOGE("failed to get regs after syscall");
        set_regs(pid, saved_regs);
        return -1;
    }

    long ret = (long)regs.REG_RET;

    // Restore full original context so the target process logic isn't corrupted
    if (!set_regs(pid, saved_regs)) {
        LOGE("failed to restore regs after syscall");
        return -1;
    }

    return ret;
}
