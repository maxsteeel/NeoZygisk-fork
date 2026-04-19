#pragma once

#include <jni.h>

struct mount_info {
    unsigned int id;
    unsigned int parent;
    dev_t device;
    char root[128];       
    char target[256];     
    char vfs_options[128];
    char type[64];        
    char source[256];     
    char fs_options[128];
};

void hook_entry(void *start_addr, size_t block_size);

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);

void send_seccomp_event_if_needed();
