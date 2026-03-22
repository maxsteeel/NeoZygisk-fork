#pragma once
#include "utils.hpp" 

bool remote_custom_linker_load_and_resolve_entry(int pid, struct user_regs_struct *regs,
                                             uintptr_t libc_return_addr, 
                                             const std::vector<MapInfo>& local_map,
                                             const std::vector<MapInfo>& remote_map, 
                                             const char *libc_path,
                                             const char *lib_path, uintptr_t *out_base,
                                             size_t *out_total_size, uintptr_t *out_entry,
                                             uintptr_t *out_init_array, size_t *out_init_count);
