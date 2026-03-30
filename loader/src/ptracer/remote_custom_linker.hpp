#pragma once
#include "utils.hpp" 
#include <sys/syscall.h>

#ifndef SYS_mmap
  #ifdef __NR_mmap
    #define SYS_mmap __NR_mmap
  #elif defined(__NR_mmap2)
    #define SYS_mmap __NR_mmap2
  #endif
#endif

#ifndef SYS_openat
  #define SYS_openat __NR_openat
#endif

#ifndef SYS_memfd_create
  #if defined(__aarch64__)
    #define SYS_memfd_create 279
  #elif defined(__x86_64__)
    #define SYS_memfd_create 319
  #elif defined(__arm__)
    #define SYS_memfd_create 385
  #elif defined(__i386__)
    #define SYS_memfd_create 356
  #endif
#endif

#ifndef SYS_ftruncate
  #if defined(__aarch64__)
    #define SYS_ftruncate 46
  #elif defined(__x86_64__)
    #define SYS_ftruncate 77
  #elif defined(__arm__) || defined(__i386__)
    #define SYS_ftruncate 93
  #endif
#endif

bool remote_custom_linker_load_and_resolve_entry(int pid, struct user_regs_struct *regs,
                                             const std::vector<MapInfo>& local_map,
                                             const std::vector<MapInfo>& remote_map, 
                                             const char *lib_path, uintptr_t *out_base,
                                             size_t *out_total_size, uintptr_t *out_entry,
                                             uintptr_t *out_init_array, size_t *out_init_count);