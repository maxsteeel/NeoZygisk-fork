/*
 * Custom Linker for NeoZygisk-fork
 * 
 * This file is a derivative work based on CSOLoader.
 * Original Author: ThePedroo (Copyright (c) 2025)
 * C++ rewrite and modifications by: maxsteeel (Copyright (c) 2026)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <stdatomic.h>

#include "misc.hpp"
#include "logging.hpp"
#include "files.hpp"
#include "elf_utils.hpp"
#include "utils.hpp"

// Definitions
#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif
#ifndef R_AARCH64_TLSDESC
#define R_AARCH64_TLSDESC 1031
#endif
#ifndef R_AARCH64_IRELATIVE
#define R_AARCH64_IRELATIVE 1032
#endif
#ifndef R_X86_64_IRELATIVE
#define R_X86_64_IRELATIVE 37
#endif
#ifndef R_ARM_IRELATIVE
#define R_ARM_IRELATIVE 160
#endif
#ifndef R_386_IRELATIVE
#define R_386_IRELATIVE 42
#endif

#ifdef __LP64__
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#endif

#ifndef ELF_ST_BIND
#define ELF_ST_BIND(i) ((i)>>4)
#endif
#ifndef STB_WEAK
#define STB_WEAK 2
#endif

#if defined(__aarch64__)
// Bionic-grade TLSDESC resolver. Saves all volatile registers 
// before calling the C++ TLS allocator.
__asm__ (
    ".global custom_tlsdesc_resolver_stub\n"
    ".hidden custom_tlsdesc_resolver_stub\n"
    ".type custom_tlsdesc_resolver_stub, %function\n"
    "custom_tlsdesc_resolver_stub:\n"
    "    stp x29, x30, [sp, #-256]!\n"
    "    mov x29, sp\n"
    "    stp x1, x2, [sp, #16]\n"
    "    stp x3, x4, [sp, #32]\n"
    "    stp x5, x6, [sp, #48]\n"
    "    stp x7, x8, [sp, #64]\n"
    "    stp x9, x10, [sp, #80]\n"
    "    stp x11, x12, [sp, #96]\n"
    "    stp x13, x14, [sp, #112]\n"
    "    stp x15, x16, [sp, #128]\n"
    "    stp x17, x18, [sp, #144]\n"
    "    stp d0, d1, [sp, #160]\n"
    "    stp d2, d3, [sp, #176]\n"
    "    stp d4, d5, [sp, #192]\n"
    "    stp d6, d7, [sp, #208]\n"
    
    // x0 points to the tlsdesc structure. Our tls_index* is at [x0, #8]
    "    ldr x0, [x0, #8]\n"
    
    // Call our C++ function (which returns an absolute pointer)
    "    bl custom_tls_get_addr\n"
    
    // Transform the absolute pointer into an offset of tpidr_el0
    "    mrs x1, tpidr_el0\n"
    "    sub x0, x0, x1\n"
    
    // Restore volatile logs
    "    ldp d6, d7, [sp, #208]\n"
    "    ldp d4, d5, [sp, #192]\n"
    "    ldp d2, d3, [sp, #176]\n"
    "    ldp d0, d1, [sp, #160]\n"
    "    ldp x17, x18, [sp, #144]\n"
    "    ldp x15, x16, [sp, #128]\n"
    "    ldp x13, x14, [sp, #112]\n"
    "    ldp x11, x12, [sp, #96]\n"
    "    ldp x9, x10, [sp, #80]\n"
    "    ldp x7, x8, [sp, #64]\n"
    "    ldp x5, x6, [sp, #48]\n"
    "    ldp x3, x4, [sp, #32]\n"
    "    ldp x1, x2, [sp, #16]\n"
    "    ldp x29, x30, [sp], #256\n"
    "    ret\n"
);

extern "C" ptrdiff_t custom_tlsdesc_resolver_stub(void*);
#endif

inline void* operator new(size_t, void* p) noexcept { return p; }

struct tlsdesc { void* resolver; uint64_t arg; };
struct CustomTlsInfo { size_t module_id; pthread_key_t key; size_t size; };
struct tls_index { size_t module_id; size_t offset; };
using TlsIndexList = UniqueList<tls_index*>;

struct DestructorAction {
    enum Type { FUNC_PTR, TLS_CLEANUP, TLSDESC_CLEANUP } type;
    union {
        void (*func_ptr)();
        size_t mod_id;
        uintptr_t frame_ptr;
        tls_index* tlsdesc_arg;
    };
};
using DestructorList = UniqueList<DestructorAction>;

struct MemMap { uintptr_t base; size_t size; };
using MemMapList = UniqueList<MemMap>;

struct LoadedModule {
    char path[256];
    uint16_t basename_offset;
    uint32_t name_hash;
    uintptr_t load_bias;
    uintptr_t base;
    size_t size;
    elf_dyn_info dinfo;
    TlsIndexList tlsdesc_args;
};

struct LoadedModuleList : public UniqueList<LoadedModule> {
    LoadedModule& push_back() {
        if (this->size >= this->capacity) {
            size_t new_cap = this->capacity == 0 ? 4 : this->capacity * 2;
            LoadedModule* new_data = static_cast<LoadedModule*>(malloc(new_cap * sizeof(LoadedModule)));
            if (this->data && this->size > 0) {
                __builtin_memcpy((void*)new_data, (void*)this->data, this->size * sizeof(LoadedModule));
            }
            if (this->data) free(this->data);
            this->data = new_data;
            this->capacity = new_cap;
        }
        LoadedModule* mod = new (&this->data[this->size]) LoadedModule();
        this->size++;
        return *mod;
    }
    void pop_back() {
        if (this->size > 0) {
            this->size--;
            this->data[this->size].~LoadedModule();
            __builtin_memset((void*)&this->data[this->size], 0, sizeof(LoadedModule)); 
        }
    }
};

struct CustomRegion { uintptr_t handle; MemMapList maps; DestructorList destructors; };
struct CustomRegionList : public UniqueList<CustomRegion> {
    CustomRegion& push_back() {
        if (this->size >= this->capacity) {
            size_t new_cap = this->capacity == 0 ? 4 : this->capacity * 2;
            CustomRegion* new_data = static_cast<CustomRegion*>(malloc(new_cap * sizeof(CustomRegion)));
            if (this->data && this->size > 0) {
                __builtin_memcpy((void*)new_data, (void*)this->data, this->size * sizeof(CustomRegion));
            }
            if (this->data) free(this->data);
            this->data = new_data;
            this->capacity = new_cap;
        }
        CustomRegion* reg = new (&this->data[this->size]) CustomRegion();
        this->size++;
        return *reg;
    }

    void erase(size_t index) {
        if (index >= this->size) return;
        this->data[index].maps.~MemMapList();
        this->data[index].destructors.~DestructorList();
        if (index < this->size - 1) {
            __builtin_memmove((void*)&this->data[index], (void*)&this->data[index + 1], (this->size - index - 1) * sizeof(CustomRegion));
        }
        this->size--;
    }
};

struct SpinLockGuard {
    atomic_flag& flag_; 

    SpinLockGuard(atomic_flag& flag) : flag_(flag) {
        while (atomic_flag_test_and_set_explicit(&flag_, memory_order_acquire)) {
#if defined(__aarch64__) || defined(__arm__)
            asm volatile("yield" ::: "memory");
#elif defined(__i386__) || defined(__x86_64__)
            asm volatile("pause" ::: "memory");
#endif
        }
    }
    
    ~SpinLockGuard() {
        atomic_flag_clear_explicit(&flag_, memory_order_release);
    }
};

static atomic_flag g_custom_regions_lock = ATOMIC_FLAG_INIT;

static CustomRegionList& get_custom_regions() {
    static CustomRegionList instance;
    return instance;
}

bool is_custom_linker_address(const void* addr) {
    uintptr_t ptr = reinterpret_cast<uintptr_t>(addr);
    SpinLockGuard lock(g_custom_regions_lock);
    for (size_t i = 0; i < get_custom_regions().size; i++) {
        const auto& reg = get_custom_regions().data[i];
        for (size_t j = 0; j < reg.maps.size; j++) {
            const auto& map = reg.maps.data[j];
            if (ptr >= map.base && ptr < map.base + map.size) return true;
        }
    }
    return false;
}

void custom_linker_unload(void* handle) {
    uintptr_t base = reinterpret_cast<uintptr_t>(handle);
    CustomRegion region_to_unload;
    bool found = false;

    {
        SpinLockGuard lock(g_custom_regions_lock);
        for (size_t i = 0; i < get_custom_regions().size; i++) {
            if (get_custom_regions().data[i].handle == base) {
                __builtin_memcpy((void*)&region_to_unload, &get_custom_regions().data[i], sizeof(CustomRegion));
                get_custom_regions().data[i].maps.data = nullptr;
                get_custom_regions().data[i].maps.size = 0;
                get_custom_regions().data[i].destructors.data = nullptr;
                get_custom_regions().data[i].destructors.size = 0;
                get_custom_regions().erase(i);
                found = true;
                break;
            }
        }
    }

    if (found) {
        for (size_t j = 0; j < region_to_unload.destructors.size; j++) {
            const auto& d = region_to_unload.destructors.data[j];
            if (d.type == DestructorAction::FUNC_PTR && d.func_ptr) {
                d.func_ptr();
            } else if (d.type == DestructorAction::TLS_CLEANUP) {
                CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(d.mod_id);
                pthread_key_delete(tls_info->key);
                delete tls_info;
            } else if (d.type == DestructorAction::TLSDESC_CLEANUP) {
                delete d.tlsdesc_arg;
            }
        }
        
        for (size_t j = 0; j < region_to_unload.maps.size; j++) {
            const auto& map = region_to_unload.maps.data[j];
            if (map.base != 0 && map.size != 0) {
                munmap(reinterpret_cast<void*>(map.base), map.size);
            }
        }
        
        // Exiting this 'if' leaves region_to_unload out of scope and ~UniqueList 
        // frees the metadata array using free().
    }
}

static bool resolve_symbol_addr(const elf_dyn_info *info,
                                const LoadedModuleList& loaded_modules,
                                uintptr_t load_bias, size_t sym_idx, uintptr_t *out_addr) {

    if (sym_idx >= info->nsyms) return false;
    const ElfW(Sym)& sym = info->symtab[sym_idx];
    uint64_t hwcap = getauxval(AT_HWCAP);

    if (sym.st_shndx != SHN_UNDEF) { 
        uintptr_t addr = (uintptr_t)load_bias + (uintptr_t)sym.st_value;
        if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
            typedef void* (*ifunc_resolver_t)(uint64_t);
            auto ifunc = reinterpret_cast<ifunc_resolver_t>(addr);
            addr = PAC_STRIP(reinterpret_cast<uintptr_t>(ifunc(hwcap)));
        }
        *out_addr = PAC_STRIP(addr); 
        return true; 
    }
    if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;

    const char *name = &info->strtab[sym.st_name];
    if (!name || !*name) return false;

    ElfW(Addr) local_val = 0;
    uint8_t local_type = 0;
    if (find_dynsym_value(info, name, &local_val, &local_type) && local_val != 0) {
        uintptr_t addr = (uintptr_t)load_bias + local_val;
        if (local_type == STT_GNU_IFUNC) {
            typedef void* (*ifunc_resolver_t)(uint64_t);
            auto ifunc = reinterpret_cast<ifunc_resolver_t>(addr);
            addr = PAC_STRIP(reinterpret_cast<uintptr_t>(ifunc(hwcap)));
        }
        *out_addr = PAC_STRIP(addr);
        return true;
    }

    for (size_t i = 0; i < loaded_modules.size; i++) {
        const auto& mod = loaded_modules.data[i];
        if (&mod.dinfo == info) continue; // Skip self
        
        ElfW(Addr) mod_val = 0;
        uint8_t mod_type = 0;
        if (find_dynsym_value(&mod.dinfo, name, &mod_val, &mod_type) && mod_val != 0) {
            uintptr_t addr = (uintptr_t)mod.load_bias + mod_val;
            if (mod_type == STT_GNU_IFUNC) {
                typedef void* (*ifunc_resolver_t)(uint64_t);
                auto ifunc = reinterpret_cast<ifunc_resolver_t>(addr);
                addr = PAC_STRIP(reinterpret_cast<uintptr_t>(ifunc(hwcap)));
            }
            *out_addr = PAC_STRIP(addr);
            return true;
        }
    }

    // Fallback to dlsym
    void* sym_ptr = dlsym(RTLD_DEFAULT, name);
    if (sym_ptr) {
        // dlsym returns PAC-signed pointers in Android 14+ ARMv9.
        // We MUST strip it before it gets added to r.r_addend in relocations.
        *out_addr = PAC_STRIP(reinterpret_cast<uintptr_t>(sym_ptr));
        return true;
    }

    return false;
}

static inline int64_t sleb128_decode(const uint8_t*& current) {
    int64_t value = 0; size_t shift = 0;
    uint8_t byte;

    do {
        byte = *current++;
        value |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if (shift < 64 && (byte & 0x40)) {
        value |= -((int64_t)1 << shift);
    }
    return value;
}

__attribute__((noinline))
static bool process_relocation([[maybe_unused]] LoadedModule& mod, const LoadedModuleList& loaded_modules,
                               uintptr_t load_bias, const elf_dyn_info* info, uintptr_t target, unsigned current_type, 
                               unsigned current_sym_idx, ElfW(Addr) current_addend, [[maybe_unused]] bool is_rela) {
    
    ElfW(Addr) value = 0;

#if defined(__aarch64__)
    switch (current_type) {
        case R_AARCH64_RELATIVE: 
            value = (ElfW(Addr))load_bias + current_addend; 
            break;
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
        case R_AARCH64_ABS64: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr))) {
                if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            value = sym_addr ? (ElfW(Addr))sym_addr + current_addend : 0;
            break;
        }
        case R_AARCH64_TLS_DTPMOD: 
            value = info->tls_mod_id; 
            break;
        case R_AARCH64_TLS_DTPREL: {
            const ElfW(Sym)& sym = info->symtab[current_sym_idx];
            value = (ElfW(Addr))sym.st_value + current_addend;
            break;
        }
        case R_AARCH64_TLS_TPREL: {
            uintptr_t sym_addr = 0;
            if (current_sym_idx == 0) {
                value = info->tls_segment_vaddr + current_addend;
            } else if (resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
            break;
        }
        case R_AARCH64_TLSDESC: {
            tlsdesc* td = reinterpret_cast<tlsdesc*>(target);
            tls_index* ti = new tls_index;
            ti->module_id = info->tls_mod_id;
            uintptr_t sym_addr = 0;
            if (current_sym_idx == 0) {
                ti->offset = current_addend;
            } else if (resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                ti->offset = (sym_addr - load_bias) + current_addend;
            } else {
                ti->offset = current_addend;
            }
            td->resolver = reinterpret_cast<void*>(custom_tlsdesc_resolver_stub);
            td->arg = reinterpret_cast<uint64_t>(ti);
            mod.tlsdesc_args.push_back(ti);
            return true;
        }
        default: return false;
    }

#elif defined(__x86_64__)
    switch (current_type) {
        case R_X86_64_RELATIVE: 
            value = (ElfW(Addr))load_bias + current_addend; 
            break;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_64: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr))) {
                if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            value = sym_addr ? (ElfW(Addr))sym_addr + current_addend : 0;
            break;
        }
        case R_X86_64_DTPMOD64: 
            value = info->tls_mod_id; 
            break;
        case R_X86_64_DTPOFF64: {
            const ElfW(Sym)& sym = info->symtab[current_sym_idx];
            value = (ElfW(Addr))sym.st_value + current_addend;
            break;
        }
        case R_X86_64_TPOFF64: {
            uintptr_t sym_addr = 0;
            if (current_sym_idx == 0) {
                value = info->tls_segment_vaddr + current_addend;
            } else if (resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
            break;
        }
        default: return false;
    }

#elif defined(__arm__)
    ElfW(Addr) addend_rel = is_rela ? current_addend : *reinterpret_cast<ElfW(Addr)*>(target);

    switch (current_type) {
        case R_ARM_RELATIVE: 
            value = (ElfW(Addr))load_bias + addend_rel; 
            break;
        case R_ARM_GLOB_DAT:
        case R_ARM_JUMP_SLOT:
        case R_ARM_ABS32: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr))) {
                if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            if (sym_addr == 0) value = 0;
            else if (current_type == R_ARM_ABS32) value = (ElfW(Addr))sym_addr + addend_rel;
            else value = (ElfW(Addr))sym_addr;
            break;
        }
        case R_ARM_TLS_DTPMOD32: 
            value = info->tls_mod_id; 
            break;
        case R_ARM_TLS_DTPOFF32: {
            const ElfW(Sym)& sym = info->symtab[current_sym_idx];
            value = (ElfW(Addr))sym.st_value + current_addend;
            break;
        }
        case R_ARM_TLS_TPOFF32: {
            uintptr_t sym_addr = 0;
            if (current_sym_idx == 0) {
                value = info->tls_segment_vaddr + current_addend;
            } else if (resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
            break;
        }
        default: return false;
    }

#elif defined(__i386__)
    ElfW(Addr) addend_rel = is_rela ? current_addend : *reinterpret_cast<ElfW(Addr)*>(target);

    switch (current_type) {
        case R_386_RELATIVE: 
            value = (ElfW(Addr))load_bias + addend_rel; 
            break;
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
        case R_386_32: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr))) {
                if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            if (sym_addr == 0) value = 0;
            else if (current_type == R_386_32) value = (ElfW(Addr))sym_addr + addend_rel;
            else value = (ElfW(Addr))sym_addr;
            break;
        }
        case R_386_TLS_DTPMOD32: 
            value = info->tls_mod_id; 
            break;
        case R_386_TLS_DTPOFF32: {
            const ElfW(Sym)& sym = info->symtab[current_sym_idx];
            value = (ElfW(Addr))sym.st_value + current_addend;
            break;
        }
        case R_386_TLS_TPOFF: {
            uintptr_t sym_addr = 0;
            if (current_sym_idx == 0) {
                value = info->tls_segment_vaddr + current_addend;
            } else if (resolve_symbol_addr(info, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
            break;
        }
        default: return false;
    }

#else
    if (current_type == 0) value = (ElfW(Addr))load_bias + current_addend;
    else return false;
#endif

    *reinterpret_cast<ElfW(Addr)*>(target) = value;
    return true;
}

template <typename RelType, bool IsRela>
__attribute__((noinline))
static bool apply_relocations(LoadedModule& mod, const LoadedModuleList& loaded_modules, off_t rel_vaddr, size_t rel_sz) {
    const elf_dyn_info* info = &mod.dinfo;
    uintptr_t load_bias = mod.load_bias;
    size_t count = rel_sz / sizeof(RelType);

    RelType* rels = reinterpret_cast<RelType*>(load_bias + rel_vaddr);

    for (size_t i = 0; i < count; i++) {
        const RelType& r = rels[i];

        unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;

        ElfW(Addr) addend = 0;
        if constexpr (IsRela) addend = r.r_addend;

        if (unlikely(!process_relocation(mod, loaded_modules, load_bias, info, target, type, sym, addend, IsRela))) {
            return false;
        }
    }
    return true;
}

static bool apply_android_relocations(LoadedModule& mod, const LoadedModuleList& loaded_modules,
                                      off_t reloc_vaddr, size_t reloc_sz, bool is_rela) {
    const elf_dyn_info* info = &mod.dinfo;
    uintptr_t load_bias = mod.load_bias;
    uint8_t* reloc_data = reinterpret_cast<uint8_t*>(load_bias + reloc_vaddr);

    if (reloc_sz < 4 || *reinterpret_cast<uint32_t*>(reloc_data) != *reinterpret_cast<const uint32_t*>("APS2")) {
        LOGE("Invalid Android REL/RELA magic");
        return false;
    }

    const uint8_t* current = reloc_data + 4;
    uint64_t num_relocs = sleb128_decode(current);
    ElfW(Addr) current_offset = sleb128_decode(current);

    unsigned current_sym_idx = 0;
    unsigned current_type = 0;
    ElfW(Addr) current_addend = 0;

    for (uint64_t i = 0; i < num_relocs; ) {
        uint64_t group_size = sleb128_decode(current);
        uint64_t group_flags = sleb128_decode(current);

        size_t group_r_offset_delta = 0;
        const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
        const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
        const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
        const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

        if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
            group_r_offset_delta = sleb128_decode(current);
        }

        if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
            ElfW(Addr) r_info = sleb128_decode(current);
            current_sym_idx = ELF_R_SYM(r_info);
            current_type = ELF_R_TYPE(r_info);
        }

        size_t group_flags_reloc = 0;
        if (is_rela) {
            group_flags_reloc = group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG);
            if (group_flags_reloc == (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
                current_addend += sleb128_decode(current);
            } else {
                current_addend = 0;
            }
        } else {
            if (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) return false;
        }

        for (size_t j = 0; j < group_size; ++j) {
            if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
                current_offset += group_r_offset_delta;
            } else {
                current_offset += sleb128_decode(current);
            }
            if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
                ElfW(Addr) r_info = sleb128_decode(current);
                current_sym_idx = ELF_R_SYM(r_info);
                current_type = ELF_R_TYPE(r_info);
            }
            if (is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                current_addend += sleb128_decode(current);
            }

            uintptr_t target = load_bias + current_offset;
            if (unlikely(!process_relocation(mod, loaded_modules, load_bias, info, target, current_type, current_sym_idx, current_addend, is_rela))) {
                return false;
            }
        }

        i += group_size;
    }
    return true;
}

static bool apply_relr_section(LoadedModule& mod, off_t relr_vaddr, size_t relr_sz) {
    uintptr_t load_bias = mod.load_bias;
    size_t count = relr_sz / sizeof(ElfW(Addr));
    ElfW(Addr)* relr = reinterpret_cast<ElfW(Addr)*>(load_bias + relr_vaddr);

    const size_t bits_per_entry = sizeof(ElfW(Addr)) * 8;
    ElfW(Addr) base_offset = 0;

    for (size_t i = 0; i < count; i++) {
        ElfW(Addr) entry = relr[i];

        if (unlikely((entry & 1) == 0)) {
            ElfW(Addr) reloc_offset = entry;
            uintptr_t target = load_bias + reloc_offset;
            *reinterpret_cast<ElfW(Addr)*>(target) += load_bias;
            base_offset = reloc_offset + sizeof(ElfW(Addr));
            continue;
        }

        ElfW(Addr) bitmap = entry >> 1;

        for (size_t bit = 0; bitmap != 0 && bit < bits_per_entry - 1; bit++, bitmap >>= 1) {
            if ((bitmap & 1) == 0) continue;
            uintptr_t target = load_bias + base_offset + (bit * sizeof(ElfW(Addr)));
            *reinterpret_cast<ElfW(Addr)*>(target) += load_bias;
        }

        base_offset += sizeof(ElfW(Addr)) * (bits_per_entry - 1);
    }

    return true;
}

static bool apply_module_relocations(LoadedModule& mod, const LoadedModuleList& loaded_modules) {

    if (mod.dinfo.rela_sz && mod.dinfo.rela_vaddr) {
        if (!apply_relocations<ElfW(Rela), true>(mod, loaded_modules, mod.dinfo.rela_vaddr, mod.dinfo.rela_sz)) return false;
    }
    if (mod.dinfo.rel_sz && mod.dinfo.rel_vaddr) {
        if (!apply_relocations<ElfW(Rel), false>(mod, loaded_modules, mod.dinfo.rel_vaddr, mod.dinfo.rel_sz)) return false;
    }
    if (mod.dinfo.jmprel_sz && mod.dinfo.jmprel_vaddr) {
        if (mod.dinfo.pltrel_type == DT_RELA) {
            if (!apply_relocations<ElfW(Rela), true>(mod, loaded_modules, mod.dinfo.jmprel_vaddr, mod.dinfo.jmprel_sz)) return false;
        } else {
            if (!apply_relocations<ElfW(Rel), false>(mod, loaded_modules, mod.dinfo.jmprel_vaddr, mod.dinfo.jmprel_sz)) return false;
        }
    }

    if (mod.dinfo.android_rel_sz && mod.dinfo.android_rel_vaddr) {
        if (!apply_android_relocations(mod, loaded_modules, mod.dinfo.android_rel_vaddr, mod.dinfo.android_rel_sz, mod.dinfo.android_is_rela)) return false;
    }
    if (mod.dinfo.relr_sz && mod.dinfo.relr_vaddr) {
        if (!apply_relr_section(mod, mod.dinfo.relr_vaddr, mod.dinfo.relr_sz)) return false;
    }

    return true;
}

static bool load_single_library(int memfd, LoadedModule* out_module, const char* module_name) {
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size = (size_t)page_size_long;

    if (memfd < 0) return false;
    UniqueFd fd(dup(memfd));
    if (fd < 0) return false;

    ElfW(Ehdr) eh;
    ElfW(Phdr) phdr[64];
    ElfW(Addr) min_vaddr = 0;
    size_t map_size = 0;

    if (!compute_load_layout(fd, page_size, &eh, phdr, &min_vaddr, &map_size)) return false;

    void* remote_base_ptr = mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remote_base_ptr == MAP_FAILED) return false;
    uintptr_t remote_base = reinterpret_cast<uintptr_t>(remote_base_ptr);

    uintptr_t load_bias = remote_base - min_vaddr;
    struct SegInfo { uintptr_t addr; size_t len; int prot; };
    SegInfo segs[64];
    size_t seg_count = 0;

    for (int i = 0; i < eh.e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        uintptr_t seg_start = phdr[i].p_vaddr + load_bias;
        uintptr_t seg_page = page_start(seg_start, page_size);
        uintptr_t seg_end = phdr[i].p_vaddr + phdr[i].p_memsz + load_bias;
        uintptr_t seg_page_end = page_end(seg_end, page_size);
        size_t seg_page_len = seg_page_end - seg_page;

        if (phdr[i].p_filesz > 0) {
            if (pread(fd, reinterpret_cast<void*>(seg_start), phdr[i].p_filesz, phdr[i].p_offset) != (ssize_t)phdr[i].p_filesz) {
                munmap(remote_base_ptr, map_size);
                return false;
            }
        }

        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        if (seg_count < 64) segs[seg_count++] = {seg_page, seg_page_len, prot};
    }

    elf_dyn_info dinfo;
    if (!elf_load_dyn_info(reinterpret_cast<void*>(load_bias), false, &eh, phdr, &dinfo)) return false;

    for (size_t k = 0; k < seg_count; k++) {
        const auto& s = segs[k];
        if (s.prot == (PROT_READ | PROT_WRITE)) continue;
        mprotect(reinterpret_cast<void*>(s.addr), s.len, s.prot);
    }

    if (dinfo.tls_segment_vaddr && dinfo.tls_segment_memsz) {
        CustomTlsInfo* tls_info = new CustomTlsInfo();
        tls_info->module_id = reinterpret_cast<size_t>(tls_info);
        tls_info->size = dinfo.tls_segment_memsz;
        pthread_key_create(&tls_info->key, free);
        dinfo.tls_mod_id = tls_info->module_id;
    }

    strlcpy(out_module->path, module_name, sizeof(out_module->path));
    out_module->basename_offset = 0;
    out_module->name_hash = calc_gnu_hash(module_name);
    out_module->load_bias = load_bias;
    out_module->base = remote_base;
    out_module->size = map_size;
    out_module->dinfo = dinfo;

    return true;
}

static bool is_lib_loaded(const char* target_soname) {
    struct CallbackCtx {
        const char* target;
        bool found;
        static int check(struct dl_phdr_info* info, size_t, void* data) {
            auto* ctx = reinterpret_cast<CallbackCtx*>(data);
            if (info->dlpi_name) {
                const char* name = __builtin_strrchr(info->dlpi_name, '/');
                name = name ? name + 1 : info->dlpi_name;
                if (__builtin_strcmp(name, ctx->target) == 0) {
                    ctx->found = true;
                    return 1; // Stop iterating! We found it.
                }
            }
            return 0;
        }
    } ctx = {target_soname, false};
    
    dl_iterate_phdr(CallbackCtx::check, &ctx);
    return ctx.found;
}

static bool load_dependencies_recursive(const char *module_name, int memfd, LoadedModuleList& loaded_modules) {
    uint32_t soname_hash = calc_gnu_hash(module_name);

    for (size_t i = 0; i < loaded_modules.size; i++) {
        const auto& m = loaded_modules.data[i];
        if (m.name_hash == soname_hash) {
            if (__builtin_strcmp(&m.path[m.basename_offset], module_name) == 0) return true;
        }
    }

    if (is_lib_loaded(module_name)) return true;

    LoadedModule& mod = loaded_modules.push_back();
    if (!load_single_library(memfd, &mod, module_name)) {
        // Revert push_back if failed
        loaded_modules.pop_back();
        return false;
    }

    size_t current_idx = loaded_modules.size - 1;
    size_t offsets_count = loaded_modules.data[current_idx].dinfo.needed_count;

    for (size_t i = 0; i < offsets_count; i++) {
        size_t off = loaded_modules.data[current_idx].dinfo.needed_str_offsets[i];
        if (off >= loaded_modules.data[current_idx].dinfo.strsz) continue;
        const char *dep_soname = &loaded_modules.data[current_idx].dinfo.strtab[off];
        if (!is_lib_loaded(dep_soname)) {
            LOGW("Warning: Module requires non-system dependency `%s` which is not in RAM.", dep_soname);

            // TODO: support multi-so module packages, maybe constructing
            // local module directory path here and loading dependencies directly.
            // But it is not much necessary, most Zygisk modules only relying
            // on system libraries.
        }
    }
    return true;
}

static void register_loaded_modules(const LoadedModuleList& loaded_modules) {
    if (loaded_modules.size == 0) return;

    SpinLockGuard lock(g_custom_regions_lock);
    const LoadedModule& main_mod = loaded_modules.data[0];
    
    CustomRegion& region = get_custom_regions().push_back();
    region.handle = main_mod.base;
    DestructorAction action;

    for (size_t i = 0; i < loaded_modules.size; i++) {
        const auto& mod = loaded_modules.data[i];
        if (mod.base != 0 && mod.size != 0) {
            region.maps.push_back({mod.base, mod.size});
        }
    }

    for (size_t i = loaded_modules.size; i > 0; --i) {
        const auto& mod = loaded_modules.data[i - 1];

        // 1. FINI_ARRAY is executed in reverse order
        if (mod.dinfo.fini_array_vaddr && mod.dinfo.fini_arraysz) {
            size_t count = mod.dinfo.fini_arraysz / sizeof(ElfW(Addr));
            ElfW(Addr)* array_addr = reinterpret_cast<ElfW(Addr)*>(mod.load_bias + mod.dinfo.fini_array_vaddr);
            for (size_t j = 0; j < count; ++j) {
                if (array_addr[count - 1 - j]) {
                    action.type = DestructorAction::FUNC_PTR;
                    action.func_ptr = reinterpret_cast<void (*)()>(array_addr[count - 1 - j]);
                    region.destructors.push_back(action);
                }
            }
        }

        // 2. DT_FINI is executed after FINI_ARRAY
        if (mod.dinfo.fini_vaddr) {
            action.type = DestructorAction::FUNC_PTR;
            action.func_ptr = reinterpret_cast<void (*)()>(mod.load_bias + mod.dinfo.fini_vaddr);
            region.destructors.push_back(action);
        }

        // 3. It's also the perfect time to clean up TLS and DWARF
        if (mod.dinfo.tls_mod_id) {
            action.type = DestructorAction::TLS_CLEANUP;
            action.mod_id = mod.dinfo.tls_mod_id;
            region.destructors.push_back(action);
        }

        for (size_t j = 0; j < mod.tlsdesc_args.size; j++) {
            action.type = DestructorAction::TLSDESC_CLEANUP;
            action.tlsdesc_arg = mod.tlsdesc_args.data[j];
            region.destructors.push_back(action);
        }
    }
}

static inline void cleanup_failed_load(const LoadedModuleList& loaded_modules) {
    for (size_t i = loaded_modules.size; i > 0; --i) {
        const auto& mod = loaded_modules.data[i - 1];
        if (mod.dinfo.tls_mod_id) {
            CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(mod.dinfo.tls_mod_id);
            pthread_key_delete(tls_info->key);
            delete tls_info;
        }
        if (mod.base != 0 && mod.size != 0) {
            munmap(reinterpret_cast<void*>(mod.base), mod.size);
        }
    }
}

extern "C" void* custom_tls_get_addr(tls_index* ti) {
    CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(ti->module_id);
    if (tls_info && tls_info->module_id == ti->module_id) {
        void* ptr = pthread_getspecific(tls_info->key);
        if (!ptr) { 
            posix_memalign(&ptr, 16, tls_info->size);
            memset(ptr, 0, tls_info->size);
            pthread_setspecific(tls_info->key, ptr);
        }
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(ptr) + ti->offset);
    }
    auto original_tls = reinterpret_cast<void*(*)(tls_index*)>(dlsym(RTLD_DEFAULT, "__tls_get_addr"));
    return original_tls ? original_tls(ti) : nullptr;
}

// ---------------- MAIN ----------------
extern "C" bool custom_linker_load(int memfd, uintptr_t *out_base, size_t *out_total_size, uintptr_t *out_entry, uintptr_t *out_init_array, size_t *out_init_count) {
    LoadedModuleList loaded_modules;

    // Give a dummy name for the main module
    if (!load_dependencies_recursive("main_module", memfd, loaded_modules)) {
        LOGE("Failed to recursively load main module and its dependencies");
        cleanup_failed_load(loaded_modules);
        return false;
    }

    if (loaded_modules.size == 0) return false;

    // Step 1: Hook TLS for all modules first
    constexpr const char* target_tls = "__tls_get_addr";

    for (size_t k = 0; k < loaded_modules.size; k++) {
        auto& mod = loaded_modules.data[k];
        const elf_dyn_info* info = &mod.dinfo;
        if (info->nsyms == 0 || info->symtab == nullptr) continue;

        // imported (undefined) symbols reside in the unhashed portion of the GNU hash table
        size_t limit = (info->gnu_buckets != nullptr) ? info->gnu_symndx : info->nsyms;
        for (size_t i = 0; i < limit; i++) {
            ElfW(Sym)& sym = info->symtab[i];
            if (sym.st_name != 0 && sym.st_name < info->strsz) {
                const char *name = &info->strtab[sym.st_name];
                if (__builtin_strcmp(name, target_tls) == 0) {
                    sym.st_value = PAC_STRIP(reinterpret_cast<uintptr_t>(&custom_tls_get_addr)) - mod.load_bias;
                    sym.st_shndx = 1;
                    break;
                }
            }
        }
    }

    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

    for (size_t k = loaded_modules.size; k > 0; --k) {
        auto& mod = loaded_modules.data[k - 1];

        if (!apply_module_relocations(mod, loaded_modules)) {
            LOGE("Failed to apply relocations for module %s", mod.path);
            cleanup_failed_load(loaded_modules);
            return false;
        }

        if (mod.dinfo.relro_vaddr && mod.dinfo.relro_sz) {
            uintptr_t relro_start = mod.load_bias + mod.dinfo.relro_vaddr;
            uintptr_t relro_end = relro_start + mod.dinfo.relro_sz;
            uintptr_t commit_start = page_start(relro_start, page_size);
            uintptr_t commit_end = page_start(relro_end, page_size);

            if (commit_end > commit_start) {
                mprotect(reinterpret_cast<void*>(commit_start), commit_end - commit_start, PROT_READ);
            }
        }

        // Execute Constructors immediately after DWARF registration
        if (mod.dinfo.init_vaddr) {
            auto func = reinterpret_cast<void (*)()>(mod.load_bias + mod.dinfo.init_vaddr);
            func();
        }

        if (mod.dinfo.init_array_vaddr && mod.dinfo.init_arraysz) {
            size_t count = mod.dinfo.init_arraysz / sizeof(ElfW(Addr));
            ElfW(Addr)* array_addr = reinterpret_cast<ElfW(Addr)*>(mod.load_bias + mod.dinfo.init_array_vaddr);
            for (size_t i = 0; i < count; ++i) {
                if (array_addr[i]) {
                    auto func = reinterpret_cast<void (*)()>(array_addr[i]);
                    func();
                }
            }
        }
    }

    LoadedModule& main_mod = loaded_modules.data[0];

    ElfW(Addr) entry_value = 0;
    // Look for the normal Zygote entry
    bool has_module_entry = find_dynsym_value(&main_mod.dinfo, "zygisk_module_entry", &entry_value);

    // If don't have it, look for the entry in the Companion
    if (!has_module_entry) {
        bool has_companion_entry = find_dynsym_value(&main_mod.dinfo, "zygisk_companion_entry", &entry_value);

        // If it has NEITHER of the two, then it is an invalid module
        if (!has_companion_entry) {
            LOGE("Module exports neither 'zygisk_module_entry' nor 'zygisk_companion_entry'. Invalid module.");
            cleanup_failed_load(loaded_modules);
            return false;
        }
    }

    *out_base = main_mod.base;
    *out_total_size = main_mod.size;
    *out_entry = main_mod.load_bias + entry_value;
    *out_init_array = main_mod.dinfo.init_array_vaddr ? (main_mod.load_bias + main_mod.dinfo.init_array_vaddr) : 0;
    *out_init_count = main_mod.dinfo.init_arraysz ? (main_mod.dinfo.init_arraysz / sizeof(ElfW(Addr))) : 0;

    register_loaded_modules(loaded_modules);
    return true;
}
