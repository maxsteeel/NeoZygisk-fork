#pragma once
#include <cstdint>
#include <stddef.h>

bool is_custom_linker_address(const void* addr);
bool custom_linker_cleanup();
void custom_linker_unload(void* handle);
extern "C" bool custom_linker_load(int memfd, uintptr_t *out_base, size_t *out_total_size, uintptr_t *out_entry, uintptr_t *out_init_array, size_t *out_init_count);
