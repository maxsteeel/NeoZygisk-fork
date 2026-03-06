#pragma once

#include <jni.h>
#include <sys/types.h>

#include <string>

struct mount_info {
    unsigned int id;
    unsigned int parent;
    dev_t device;
    std::string root;
    std::string target;
    std::string vfs_options;
    std::string type;
    std::string source;
    std::string fs_options;
    std::string raw_info;
};

void hook_entry(void *start_addr, size_t block_size);

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);

void send_seccomp_event_if_needed();

std::vector<mount_info> check_zygote_traces(uint32_t info_flags);
