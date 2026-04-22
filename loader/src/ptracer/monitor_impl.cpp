#include <fcntl.h>
#include <linux/eventpoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h> 

#include "daemon.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

// --- Helper Functions  ---

static inline bool contains(const IntList& vec, int pid) {
    for (size_t i = 0; i < vec.size; i++) {
        if (unlikely(vec.data[i] == pid)) return true;
    }
    return false;
}

static inline void fast_erase(IntList& vec, int pid) {
    for (size_t i = 0; i < vec.size; i++) {
        if (vec.data[i] == pid) {
            vec.data[i] = vec.data[vec.size - 1];
            vec.size--;
            return;
        }
    }
}

// --- AppMonitor Method Implementations ---

AppMonitor::AppMonitor()
    : socket_handler_(*this),
      ptrace_handler_(*this),
#if defined(__LP64__)
      zygote_(*this, true),
#else
      zygote_(*this, false),
#endif
      tracing_state_(TRACING) {
}

ZygoteAbiManager &AppMonitor::get_abi_manager() { return zygote_; }

TracingState AppMonitor::get_tracing_state() const { return tracing_state_; }

void AppMonitor::write_abi_status_section(char *status_text, const Status &daemon_status) {
    if (!daemon_status.supported) return;

    size_t len = __builtin_strlen(status_text);
    char* p = status_text + len;
    size_t remaining = sizeof(final_output_) - len;

    p += snprintf(p, remaining, "\tzygote%s:\t%s\n\tdaemon%s:\t%s",
                  zygote_.abi_name_,
                  (tracing_state_ != TRACING) ? "❓ unknown" : 
                  (daemon_status.zygote_injected ? "😋 injected" : "❌ not injected"),
                  zygote_.abi_name_,
                  daemon_status.daemon_running ? "😋 running" : "❌ crashed");

    if (daemon_status.daemon_running && daemon_status.daemon_info[0]) {
        snprintf(p, remaining - (p - (status_text + len)), "\n%s", daemon_status.daemon_info);
    }
}

void AppMonitor::update_status() {
    if (prop_fd_ < 0) return;

    final_output_[0] = '\0';
    strlcat(final_output_, pre_section_, sizeof(final_output_));
    strlcat(final_output_, "\n\tmonitor: \t", sizeof(final_output_));

    switch (tracing_state_) {
    case TRACING:
        strlcat(final_output_, "😋 tracing", sizeof(final_output_));
        break;
    case STOPPING:
        [[fallthrough]];
    case STOPPED:
        strlcat(final_output_, "❌ stopped", sizeof(final_output_));
        break;
    case EXITING:
        strlcat(final_output_, "❌ exited", sizeof(final_output_));
        break;
    }
    if (tracing_state_ != TRACING && monitor_stop_reason_[0] != '\0') {
        strlcat(final_output_, "(", sizeof(final_output_));
        strlcat(final_output_, monitor_stop_reason_, sizeof(final_output_));
        strlcat(final_output_, ")", sizeof(final_output_));
    }

    strlcat(final_output_, "\n\n", sizeof(final_output_));
    write_abi_status_section(final_output_, zygote_.get_status());
    strlcat(final_output_, "\n\n", sizeof(final_output_));
    strlcat(final_output_, post_section_, sizeof(final_output_));

    ftruncate(prop_fd_, 0);
    pwrite(prop_fd_, final_output_, __builtin_strlen(final_output_), 0);
}

bool AppMonitor::prepare_environment() {
    __builtin_memset(pre_section_, 0, sizeof(pre_section_));
    __builtin_memset(post_section_, 0, sizeof(post_section_));
    __builtin_memset(this->prop_path_, 0, sizeof(this->prop_path_));
    snprintf(this->prop_path_, sizeof(this->prop_path_), "%s/status.prop", zygiskd::GetModDir());
    this->prop_fd_ = UniqueFd(open(this->prop_path_, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    if (this->prop_fd_ < 0) {
        PLOGE("failed to create/open prop_file at %s", this->prop_path_);
        return false;
    }
    UniqueFd orig_prop_fd(open("./module.prop", O_RDONLY | O_CLOEXEC));
    if (orig_prop_fd < 0) {
        PLOGE("open original prop");
        return false;
    }
    bool post = false;
    file_readline(false, orig_prop_fd, [&](const char* line) -> bool {
        if (__builtin_strncmp(line, "updateJson=", 11) == 0) return true;
        if (__builtin_strncmp(line, "description=", 12) == 0) {
            post = true;
            strncat(post_section_, line + 12, sizeof(post_section_) - __builtin_strlen(post_section_) - 1);
        } else {
            char* target = post ? post_section_ : pre_section_;
            strncat(target, "\t", sizeof(pre_section_) - __builtin_strlen(target) - 1);
            strncat(target, line, sizeof(pre_section_) - __builtin_strlen(target) - 1);
            strncat(target, "\n", sizeof(pre_section_) - __builtin_strlen(target) - 1);
        }
        return true;
    });

    update_status();
    return true;
}

void AppMonitor::run() {
    socket_handler_.Init();
    ptrace_handler_.Init();
    event_loop_.Init();
    event_loop_.RegisterHandler(&socket_handler_.epoll_evt, EPOLLIN | EPOLLET);
    event_loop_.RegisterHandler(&ptrace_handler_.epoll_evt, EPOLLIN | EPOLLET);
    event_loop_.Loop();
}

void AppMonitor::request_start() {
    if (tracing_state_ == STOPPING)
        tracing_state_ = TRACING;
    else if (tracing_state_ == STOPPED) {
        ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK);
        LOGI("start tracing init");
        tracing_state_ = TRACING;
    }
    update_status();
}

void AppMonitor::request_stop(const char* reason) {
    if (tracing_state_ == TRACING) {
        LOGI("stop tracing requested");
        tracing_state_ = STOPPING;
        size_t rlen = __builtin_strlen(reason);
        if (rlen >= sizeof(monitor_stop_reason_)) rlen = sizeof(monitor_stop_reason_) - 1;
        __builtin_memcpy(monitor_stop_reason_, reason, rlen);
        monitor_stop_reason_[rlen] = '\0';
        ptrace(PTRACE_INTERRUPT, 1, 0, 0);
        update_status();
    }
}

void AppMonitor::request_exit() {
    LOGI("prepare for exit ...");
    tracing_state_ = EXITING;
    const char* reason = "user requested";
    size_t rlen = __builtin_strlen(reason);
    __builtin_memcpy(monitor_stop_reason_, reason, rlen);
    monitor_stop_reason_[rlen] = '\0';
    update_status();
    event_loop_.Stop();
}

void AppMonitor::notify_init_detached() {
    tracing_state_ = STOPPED;
    LOGI("stop tracing init");
}

// --- SocketHandler Method Implementations ---

bool AppMonitor::SocketHandler::Init() {
    sock_fd_ = UniqueFd(socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (sock_fd_ == -1) {
        PLOGE("socket create");
        return false;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    size_t name_len = __builtin_strlen(AppMonitor::SOCKET_NAME);
    if (name_len >= sizeof(addr.sun_path) - 1) {
        PLOGE("UNIX domain socket path too long");
        return false;
    }
    __builtin_memcpy(addr.sun_path + 1, AppMonitor::SOCKET_NAME, name_len);
    socklen_t socklen = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
    if (bind(sock_fd_, (struct sockaddr *) &addr, socklen) == -1) {
        PLOGE("bind socket");
        return false;
    }

    epoll_evt.fd = sock_fd_; 
    epoll_evt.handler_fn = &SocketHandler::DispatchEvent;
    epoll_evt.context = this;
    
    return true;
}

void AppMonitor::SocketHandler::HandleEvent(EventLoop &, uint32_t) {
    alignas(MsgHead) char buffer[8192];

    for (;;) {
        ssize_t nread = recv(sock_fd_, buffer, sizeof(buffer), 0);
        if (nread == -1) {
            if (errno == EAGAIN) break;
            PLOGE("SocketHandler: recv");
            continue;
        }
        
        if (static_cast<size_t>(nread) < sizeof(Command)) continue;

        MsgHead &full_msg = *reinterpret_cast<MsgHead *>(buffer);

        if (full_msg.cmd >= Command::DAEMON_SET_INFO && full_msg.cmd != Command::SYSTEM_SERVER_STARTED) {
            if (static_cast<size_t>(nread) < sizeof(MsgHead) + full_msg.length) {
                LOGE("SocketHandler: mensaje truncado o incompleto");
                continue;
            }
        }

        switch (full_msg.cmd) {
        case START: monitor_.request_start(); break;
        case STOP: monitor_.request_stop("user requested"); break;
        case EXIT: monitor_.request_exit(); break;
        case ZYGOTE_INJECTED:
            monitor_.get_abi_manager().notify_injected();
            monitor_.update_status();
            break;
        case DAEMON_SET_INFO:
            monitor_.get_abi_manager().set_daemon_info(full_msg.data, (size_t) full_msg.length);
            monitor_.update_status();
            break;
        case DAEMON_SET_ERROR_INFO:
            monitor_.get_abi_manager().set_daemon_crashed(full_msg.data, (size_t) full_msg.length);
            monitor_.update_status();
            break;
        case SYSTEM_SERVER_STARTED:
            LOGV("system server started, module.prop updated");
            break;
        }
    }
}

// --- SigChldHandler Method Implementations ---

bool AppMonitor::SigChldHandler::Init() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        PLOGE("set sigprocmask");
        return false;
    }
    signal_fd_ = UniqueFd(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
    if (signal_fd_ == -1) {
        PLOGE("create signalfd");
        return false;
    }
    ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK);

    epoll_evt.fd = signal_fd_; 
    epoll_evt.handler_fn = &SigChldHandler::DispatchEvent;
    epoll_evt.context = this;
    
    return true;
}

/**
 * @brief The central dispatcher for process state changes and signal handling.
 *
 * This method is the primary entry point for the monitoring logic.
 * It is invoked by the `EventLoop` when the underlying `signalfd` becomes readable,
 * indicating that the kernel has delivered one or more `SIGCHLD` signals.
 *
 * Its responsibility is to consume the signal notification, reap all pending process
 * events using `waitpid`, and dispatch them according to the new hierarchical architecture.
 *
 * @section Architecture: Hierarchical Monitoring
 *
 * To support complex boot chains (e.g., `init -> stub -> zygote`), this handler implements
 * a recursive monitoring strategy rather than a flat list. It categorizes processes into
 * four distinct roles and processes them in strict priority order:
 *
 * 1.  Process Factories (Init & Stubs)
 *     - Criteria: PID is `1` (init) OR present in `stub_processes_`.
 *     - Role: These are parent nodes in the process tree.
 *     - Action: Delegated to `handleParentEvent()`. We monitor these processes
 *       primarily for `PTRACE_EVENT_FORK` to discover new children (potential Zygotes)
 *       or, in the case of stubs, for their termination.
 *
 * 2.  Helper Daemons
 *     - Criteria: PID matches a known `zygiskd` instance.
 *     - Role: Self-monitoring mechanism.
 *     - Action: Checks if the daemon has crashed or exited unexpectedly and
 *       updates the global status accordingly.
 *
 * 3.  Transitioning Candidates
 *     - Criteria: PID is present in the `process_` set.
 *     - Role: These are newly forked children whose identity is not yet established.
 *       They are being traced while waiting for an `execve` syscall.
 *     - Action: Delegated to `handleTracedProcess()`. This determines if the
 *       process has become a Zygote (triggering injection), an intermediate Stub
 *       (triggering promotion to a Process Factory), or an irrelevant process
 *       (triggering detachment).
 *
 * 4.  New Discoveries
 *     - Criteria: PID is unknown.
 *     - Role: Unexpected or previously unobserved children of a monitored parent.
 *     - Action: Delegated to `handleNewProcess()`. The monitor attaches via
 *       `ptrace` with `PTRACE_O_TRACEEXEC` and adds the PID to the candidate set
 *       (`process_`) to await its biological identity.
 */
void AppMonitor::SigChldHandler::HandleEvent(EventLoop &, uint32_t) {
    for (;;) {
        struct signalfd_siginfo fdsi[8];
        ssize_t s = read(signal_fd_, fdsi, sizeof(fdsi));
        if (s == -1) {
            if (errno == EAGAIN) break;
            PLOGE("read signalfd");
            continue;
        }

        int pid;
        while ((pid = waitpid(-1, &status_, __WALL | WNOHANG)) > 0) {
            handleChildEvent(pid, status_);
        }
        if (pid == -1 && errno != ECHILD && monitor_.get_tracing_state() != STOPPED) {
            PLOGE("waitpid");
        }
    }
}

/**
 * @brief The primary dispatcher for child process state changes.
 *
 * This function routes signals caught by waitpid() to the appropriate specialized
 * handler based on the process's current role in our monitoring hierarchy.
 */
void AppMonitor::SigChldHandler::handleChildEvent(int pid, int &status) {
    // Role 1: Process Factories (Init and Stub Zygotes)
    // These processes are monitored for PTRACE_EVENT_FORK to discover new children.
    if (pid == 1 || contains(stub_processes_, pid)) {
        handleParentEvent(pid, status);
        return;
    }

    // Role 2: Helper Daemons
    // Check if this is one of our own zygiskd daemon instances exiting.
    if (monitor_.get_abi_manager().handle_daemon_exit_if_match(pid, status)) {
        return;
    }

    // Role 3 & 4: Transitioning Candidates and New Discoveries
    // If the process is known to be in the pre-exec stage, evaluate its state.
    // Otherwise, treat it as a newly discovered process.
    if (contains(process_, pid)) {
        handleTracedProcess(pid, status);
    } else {
        handleNewProcess(pid);
    }
}

/**
 * @brief Handles events for parent processes (Init and Stub Zygotes).
 *
 * This handler manages the discovery of new processes via fork() and acts as a
 * shield to protect fragile parent processes (like stub_zygote) from kernel
 * signals generated by our ptrace manipulation of their children.
 */
void AppMonitor::SigChldHandler::handleParentEvent(int pid, int &status) {
    // Case 1: The parent successfully forked a new child.
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_FORK)) {
        long child_pid;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) != -1) {
            LOGV("parent %d forked %ld", pid, child_pid);
        } else {
            PLOGE("geteventmsg on parent %d", pid);
        }
    }
    // Case 2: Init has paused in response to our PTRACE_INTERRUPT stop request.
    else if (pid == 1 && stopped_with(status, SIGTRAP, PTRACE_EVENT_STOP) &&
             monitor_.get_tracing_state() == STOPPING) {
        LOGI("init process safely paused, detaching");
        if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("detach init failed");
        monitor_.notify_init_detached();
        return;
    }
    // Case 3: An intermediate stub process died naturally or crashed.
    else if (pid != 1 && (WIFEXITED(status) || WIFSIGNALED(status))) {
        LOGI("stub process %d exited (status: %d)", pid, status);
        fast_erase(stub_processes_, pid);
        return;
    }

    // Case 4: The parent was stopped by a standard POSIX signal.
    // We must act as a proxy: deciding whether to suppress the signal or inject it back.
    if (WIFSTOPPED(status)) {
        // WPTEVENT == 0 guarantees this is a standard signal, not a ptrace internal event.
        if (WPTEVENT(status) == 0) {
            int sig = WSTOPSIG(status);

            // Suppress job-control signals.
            // Injecting these back would physically freeze the parent process,
            // causing the entire boot chain to hang.
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
            // causing the entire boot chain to hang.
            }
            // Protect stub_zygote from SIGCHLD.
            // When we freeze/resume its child for injection, the kernel sends SIGCHLD to the stub.
            // By remaining attached and dropping the signal here, the stub remains safely ignorant.
            else if (pid != 1 && sig == SIGCHLD) {
                LOGV("shielding stub process %d from SIGCHLD to prevent native crash", pid);
            }
            // Pass all other signals (like SIGTERM, SIGUSR1) back to the process unaltered.
            else {
                LOGW("passing signal %s (%d) through to parent %d", sigabbrev_np(sig), sig, pid);
                ptrace(PTRACE_CONT, pid, 0, sig);
                return;
            }
        }

        // Resume the process for suppressed signals or any other benign ptrace stops.
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
}

/**
 * @brief Registers and prepares a newly discovered process for execve tracking.
 */
void AppMonitor::SigChldHandler::handleNewProcess(int pid) {
    LOGV("new process %d discovered and attached", pid);
    process_.push_back(pid);

    // Instruct the kernel to stop this process and notify us when it calls execve().
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
        PLOGE("set PTRACE_O_TRACEEXEC on new process %d", pid);
    }

    // Always resume the process.
    ptrace(PTRACE_CONT, pid, 0, 0);
}

/**
 * @brief Evaluates the state of processes waiting to execute a program.
 *
 * This handler manages the critical race condition window between a process
 * being forked and it calling execve().
 */
void AppMonitor::SigChldHandler::handleTracedProcess(int pid, int &status) {
    bool keep_attached = false;

    // The process has called execve(). We must now identify it.
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_EXEC)) {
        keep_attached = handleExecEvent(pid, status);
    }
    // The kernel auto-attaches the forked child and pauses it with PTRACE_EVENT_STOP.
    else if (stopped_with(status, SIGTRAP, PTRACE_EVENT_STOP)) {
        LOGV("process %d acknowledged auto-attach trap, configuring execve tracking", pid);

        // Safely apply the execve trap now that the process is guaranteed stopped and reaped.
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
            PLOGE("set PTRACE_O_TRACEEXEC on process %d", pid);
        }

        ptrace(PTRACE_CONT, pid, 0, 0);
        keep_attached = true;
    }
    // Unexpected state during the pre-exec phase.
    else {
        char status_buf[256];
        parse_status(status, status_buf, sizeof(status_buf));
        LOGW("traced process %d stopped with unexpected status: %s", pid, status_buf);
    }

    // Determine lifecycle routing based on the handlers above.
    if (keep_attached) {
        // If handleExecEvent promoted it to a stub or initiated injection,
        // it no longer belongs in the pre-exec candidate pool.
        if (stopped_with(status, SIGTRAP, PTRACE_EVENT_EXEC)) {
            fast_erase(process_, pid);
        }
        return;
    }

    // If the process is irrelevant (e.g., a random system daemon), clean up and detach.
    fast_erase(process_, pid);

    if (WIFSTOPPED(status)) {
        LOGV("detaching irrelevant process %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
}

/**
 * @brief Identifies the biological identity of a process post-execve.
 *
 * @return true if the process was promoted (Stub) or handed off (Zygote).
 *         false if the process is irrelevant and should be detached.
 */
bool AppMonitor::SigChldHandler::handleExecEvent(int pid, int &status) {
    char program[256];
    if (!get_program(pid, program, sizeof(program))) {
        return false;
    }
    LOGV("process %d executed program: %s", pid, program);

    bool handled = false;

    do {
        // --- Intermediate Stub Identification ---
        // If this program is a stub_zygote, we must promote it to a Process Factory.
        // It will remain attached forever so we can shield it from SIGCHLD.
        if (__builtin_strstr(program, "stub_zygote") != nullptr) {
            LOGI("detected stub zygote at %d, promoting to parent monitor", pid);
            stub_processes_.push_back(pid);

            // Upgrade tracing options to catch when it forks the real zygote.
            ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC);
            ptrace(PTRACE_CONT, pid, 0, 0);

            handled = true;
            break;
        }

        // --- Zygote Target Validation ---
        if (monitor_.get_tracing_state() != TRACING) {
            LOGW("ignoring potential target %d because tracing state is STOPPED", pid);
            break;
        }

        if (__builtin_strcmp(program, monitor_.get_abi_manager().program_path_) != 0) {
            break;  
        }

        const char *tracer = monitor_.get_abi_manager().check_and_prepare_injection();
        if (tracer == nullptr) {
            LOGE("failed to prepare injector for target %d", pid);
            break;
        }

        // --- Zygote Handover Sequence ---
        LOGV("intercepted target zygote %d, halting for injector hand-off", pid);

        // Force the process into a standard SIGSTOP state.
        kill(pid, SIGSTOP);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, __WALL);

        if (stopped_with(status, SIGSTOP, 0)) {
            LOGV("target %d halted, detaching monitor to allow injector seize", pid);

            // Detach, but leave the process frozen (SIGSTOP) for the injector daemon.
            if (ptrace(PTRACE_DETACH, pid, 0, SIGSTOP) == -1) {
                PLOGE("detach target %d", pid);
            }

            // Fork and execute the external injector daemon.
            auto p = fork_dont_care();
            if (p == 0) {
                char pid_str[12];
                snprintf(pid_str, sizeof(pid_str), "%d", pid);
                execl(tracer, basename(tracer), "trace", pid_str, "--restart", nullptr);
                PLOGE("execute injector daemon");
                kill(pid, SIGKILL);
                _exit(1);
            } else if (p == -1) {
                PLOGE("fork injector daemon");
                kill(pid, SIGKILL);
            }

            handled = true;
        } else {
            char status_str[256];
            parse_status(status, status_str, sizeof(status_str));
            LOGE("target %d failed to enter SIGSTOP, status: %s", pid, status_str);
        }

    } while (false);

    // Ensure state transitions (like zygote_injected flags) are flushed to disk.
    monitor_.update_status();
    return handled;
}
