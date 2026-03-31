#include "zygote_abi.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

ZygoteAbiManager::ZygoteAbiManager(AppMonitor& monitor, bool is_64bit)
    : abi_name_(is_64bit ? "64" : "32"),
      program_path_(is_64bit ? "/system/bin/app_process64" : "/system/bin/app_process32"),
      tracer_path_(is_64bit ? "./bin/zygisk-ptrace64" : "./bin/zygisk-ptrace32"),
      monitor_(monitor) {}

const Status& ZygoteAbiManager::get_status() const { return status_; }

void ZygoteAbiManager::notify_injected() { status_.zygote_injected = true; }

void ZygoteAbiManager::set_daemon_info(std::string_view info) { 
    strlcpy(status_.daemon_info, info.data(), sizeof(status_.daemon_info)); 
}

void ZygoteAbiManager::set_daemon_crashed(std::string_view error) {
    status_.daemon_running = false;
    strlcpy(status_.daemon_error_info, error.data(), sizeof(status_.daemon_error_info));
}

bool ZygoteAbiManager::is_in_crash_loop() {
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - counter.last_start_time.tv_sec < ZygoteAbiManager::CRASH_LOOP_WINDOW_SECONDS) {
        counter.count++;
    } else {
        counter.count = 1;
    }
    counter.last_start_time = now;
    return counter.count >= ZygoteAbiManager::CRASH_LOOP_RETRY_COUNT;
}

bool ZygoteAbiManager::ensure_daemon_created() {
    status_.zygote_injected = false;
    if (status_.daemon_pid == -1) {
        auto pid = fork();
        if (pid < 0) {
            PLOGE("create daemon (abi=%s)", abi_name_);
            return false;
        }
        if (pid == 0) {
            char daemon_name[32];
            snprintf(daemon_name, sizeof(daemon_name), "./bin/zygiskd%s", abi_name_);
            execl(daemon_name, daemon_name, nullptr);
            PLOGE("exec daemon %s", daemon_name);
            exit(1);
        }
        status_.supported = true;
        status_.daemon_pid = pid;
        status_.daemon_running = true;
    }
    return status_.daemon_running;
}

const char* ZygoteAbiManager::check_and_prepare_injection() {
    if (is_in_crash_loop()) {
        monitor_.request_stop("zygote crashed");
        return nullptr;
    }
    if (!ensure_daemon_created()) {
        monitor_.request_stop("daemon not running");
        return nullptr;
    }
    return tracer_path_;
}

bool ZygoteAbiManager::handle_daemon_exit_if_match(int pid, int process_status) {
    if (status_.supported && pid == status_.daemon_pid) {
        char status_str[256];
        parse_status(process_status, status_str, sizeof(status_str));
        LOGW("ZygoteAbiManager: daemon%s (pid %d) exited: %s", abi_name_, pid, status_str);
        status_.daemon_running = false;
        if (status_.daemon_error_info[0] == '\0') {
            strlcpy(status_.daemon_error_info, status_str, sizeof(status_.daemon_error_info));
        }
        monitor_.update_status();
        return true;
    }
    return false;
}
