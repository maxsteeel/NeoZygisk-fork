#pragma once
#include "../../../zygiskd/src/include/utils.hpp"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>
#include <cinttypes>
#include <signal.h>
#include <string.h>

#include <string>
#include <vector>

struct MapInfo {
    /// \brief The start address of the memory region.
    uintptr_t start;
    /// \brief The end address of the memory region.
    uintptr_t end;
    /// \brief The permissions of the memory region. This is a bit mask of the following values:
    /// - PROT_READ
    /// - PROT_WRITE
    /// - PROT_EXEC
    uint8_t perms;
    /// \brief Whether the memory region is private.
    bool is_private;
    /// \brief The offset of the memory region.
    uintptr_t offset;
    /// \brief The device number of the memory region.
    /// Major can be obtained by #major()
    /// Minor can be obtained by #minor()
    dev_t dev;
    /// \brief The inode number of the memory region.
    ino_t inode;
    /// \brief The path of the memory region.
    char path[256];

    /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
    /// This is useful to find out the inode of the library to hook.
    /// \return A list of \ref MapInfo entries.
    template <typename Callback>
    static void Scan(int pid, Callback cb) {
        char map_path[64];
        if (pid == -1 || pid == getpid()) {
            strcpy(map_path, "/proc/self/maps");
        } else {
            snprintf(map_path, sizeof(map_path), "/proc/%d/maps", pid);
        }

        UniqueFile fp(fopen(map_path, "re"));
        if (!fp) return;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            MapInfo info{};
            info.perms = 0;
            char perms_str[5] = {0};
            uint64_t temp_inode = 0; 
          
            // Standard proc maps format: 
            // 7f9c000000-7f9c001000 r-xp 00000000 103:04 123456 /system/lib64/libc.so
            int matched = sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %" PRIu64 " %255s",
                                 &info.start, &info.end, perms_str, &info.offset, &temp_inode, info.path);
            info.inode = static_cast<ino_t>(temp_inode);

            if (matched >= 4) {
                if (perms_str[0] == 'r') info.perms |= PROT_READ;
                if (perms_str[1] == 'w') info.perms |= PROT_WRITE;
                if (perms_str[2] == 'x') info.perms |= PROT_EXEC;
                info.is_private = (perms_str[3] == 'p');
                
                // If scanf did not read the path (because it was anonymous memory), path remains empty
                if (matched < 6) info.path[0] = '\0';

                // Execute the callback. If it returns true, we stop scanning.
                if (cb(info)) {
                    break; 
                }
            }
        }
    }
};

#if defined(__x86_64__)
#define REG_SP rsp
#define REG_IP rip
#define REG_RET rax
#define REG_SYSNR orig_rax
#elif defined(__i386__)
#define REG_SP esp
#define REG_IP eip
#define REG_RET eax
#define REG_SYSNR orig_eax
#elif defined(__aarch64__)
#define REG_SP sp
#define REG_IP pc
#define REG_RET regs[0]
#define REG_SYSNR regs[8]
#elif defined(__arm__)
#define REG_SP uregs[13]
#define REG_IP uregs[15]
#define REG_RET uregs[0]
#define REG_SYSNR uregs[7]
#define user_regs_struct user_regs
#endif

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len);

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len);

bool get_regs(int pid, struct user_regs_struct &regs);

bool set_regs(int pid, struct user_regs_struct &regs);

void *find_module_base(int pid, std::string_view suffix);

void *find_func_addr(int local_pid, int remote_pid, std::string_view module, std::string_view func);

void align_stack(struct user_regs_struct &regs, long preserve = 0);

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str);

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                      uintptr_t return_addr, const long *args, size_t argc);

int fork_dont_care();

void wait_for_trace(int pid, int *status, int flags);

std::string parse_status(int status);

#define WPTEVENT(x) (x >> 16)

#define CASE_CONST_RETURN(x)                                                                       \
    case x:                                                                                        \
        return #x;

inline const char *parse_ptrace_event(int status) {
    status = status >> 16;
    switch (status) {
        CASE_CONST_RETURN(PTRACE_EVENT_FORK)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK)
        CASE_CONST_RETURN(PTRACE_EVENT_CLONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXEC)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK_DONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXIT)
        CASE_CONST_RETURN(PTRACE_EVENT_SECCOMP)
        CASE_CONST_RETURN(PTRACE_EVENT_STOP)
    default:
        return "(no event)";
    }
}

inline const char *sigabbrev_np(int sig) {
    switch (sig) {
        case SIGHUP: return "SIGHUP";
        case SIGINT: return "SIGINT";
        case SIGQUIT: return "SIGQUIT";
        case SIGILL: return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        case SIGABRT: return "SIGABRT";
        case SIGBUS: return "SIGBUS";
        case SIGFPE: return "SIGFPE";
        case SIGKILL: return "SIGKILL";
        case SIGUSR1: return "SIGUSR1";
        case SIGSEGV: return "SIGSEGV";
        case SIGUSR2: return "SIGUSR2";
        case SIGPIPE: return "SIGPIPE";
        case SIGALRM: return "SIGALRM";
        case SIGTERM: return "SIGTERM";
#ifdef SIGSTKFLT
        case SIGSTKFLT: return "SIGSTKFLT";
#endif
        case SIGCHLD: return "SIGCHLD";
        case SIGCONT: return "SIGCONT";
        case SIGSTOP: return "SIGSTOP";
        case SIGTSTP: return "SIGTSTP";
        case SIGTTIN: return "SIGTTIN";
        case SIGTTOU: return "SIGTTOU";
        case SIGURG: return "SIGURG";
        case SIGXCPU: return "SIGXCPU";
        case SIGXFSZ: return "SIGXFSZ";
        case SIGVTALRM: return "SIGVTALRM";
        case SIGPROF: return "SIGPROF";
        case SIGWINCH: return "SIGWINCH";
        case SIGIO: return "SIGIO";
        case SIGPWR: return "SIGPWR";
        case SIGSYS: return "SIGSYS";
        default: return "(unknown)";
    }
}

bool get_program(int pid, char* buf, size_t buf_size);

// Finds a raw 'svc 0' or 'syscall' gadget in the remote libc.so
uintptr_t find_syscall_gadget(int local_pid, int remote_pid);

// Executes a raw kernel syscall in the remote process, bypassing BTI and libc wrappers.
long remote_syscall(int pid, struct user_regs_struct &regs, uintptr_t syscall_gadget, long sysnr, const long *args, size_t args_size);
