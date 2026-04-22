#pragma once
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include "daemon.hpp"
#include "misc.hpp"

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
            __builtin_memcpy(map_path, "/proc/self/maps\0", 16);
        } else {
            snprintf(map_path, sizeof(map_path), "/proc/%d/maps", pid);
        }

        UniqueFd fd(open(map_path, O_RDONLY | O_CLOEXEC));
        if (fd < 0) return;

        char buf[8192];
        size_t current_pos = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(fd, buf + current_pos, sizeof(buf) - current_pos - 1)) > 0) {
            size_t total_bytes = current_pos + bytes_read;
            buf[total_bytes] = '\0';

            char *line_start = buf;
            char *line_end;
            while ((line_end = static_cast<char*>(memchr(line_start, '\n', total_bytes - (line_start - buf)))) != nullptr) {
                *line_end = '\0'; // null termination

                if (line_start < line_end) {
                    MapInfo info{};
                    info.perms = 0;
                    char* ptr = line_start;
                    char* next;

                    info.start = fast_strtoull(ptr, &next, 16); // parse start address (hex)
                    if (ptr == next || *next != '-') goto skip_line;
                    ptr = next + 1;

                    info.end = fast_strtoull(ptr, &next, 16); // parse end address (hex)
                    if (ptr == next || *next != ' ') goto skip_line;
                    ptr = next + 1;

                    // parse perms (e.g., "r-xp")
                    if (line_end - ptr >= 4) {
                        if (ptr[0] == 'r') info.perms |= PROT_READ;
                        if (ptr[1] == 'w') info.perms |= PROT_WRITE;
                        if (ptr[2] == 'x') info.perms |= PROT_EXEC;
                        info.is_private = (ptr[3] == 'p');
                        ptr += 4;
                    } else {
                        goto skip_line;
                    }

                    while (*ptr == ' ' && ptr < line_end) ++ptr; // skip spaces
                    info.offset = fast_strtoull(ptr, &next, 16); // parse offset (hex)
                    if (ptr == next) goto skip_line;
                    ptr = next;
                    while (*ptr == ' ' && ptr < line_end) ++ptr;// skip spaces
                    while (*ptr != ' ' && ptr < line_end) ++ptr; // skip major:minor
                    while (*ptr == ' ' && ptr < line_end) ++ptr;
                    info.inode = fast_strtoull(ptr, &next, 10); // parse inode (decimal)
                    ptr = next;
                    while (*ptr == ' ' && ptr < line_end) ++ptr; // skip spaces

                    // extract path
                    size_t path_len = line_end - ptr;
                    if (path_len > 0) {
                        if (path_len >= sizeof(info.path)) path_len = sizeof(info.path) - 1;
                        __builtin_memcpy(info.path, ptr, path_len);
                        info.path[path_len] = '\0';
                    } else {
                        info.path[0] = '\0';
                    }

                    // execute callback. if it returns true, stop scanning.
                    if (cb(info)) {
                        return; // returns direct to exit the outer loop as well
                    }
                }

    skip_line:
                line_start = line_end + 1;
            }

            size_t remaining = total_bytes - (line_start - buf);
            if (remaining > 0 && remaining < sizeof(buf)) {
                __builtin_memmove(buf, line_start, remaining);
                current_pos = remaining;
            } else {
                current_pos = 0;
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

void align_stack(struct user_regs_struct &regs, long preserve = 0);

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str);

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                      uintptr_t return_addr, const long *args, size_t argc);

int fork_dont_care();

void wait_for_trace(int pid, int *status, int flags);

void parse_status(int status, char* out_buf, size_t out_size);

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
uintptr_t find_syscall_gadget(int remote_pid);

// Executes a raw kernel syscall in the remote process, bypassing BTI and libc wrappers.
long remote_syscall(int pid, struct user_regs_struct &regs, uintptr_t syscall_gadget, long sysnr, const long *args, size_t args_size);
