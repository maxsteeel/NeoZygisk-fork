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
#include <pthread.h>
#include <stdlib.h>
#include <sys/auxv.h>

#include <string>
#include <vector>
#include <mutex>
#include <functional>

#include "logging.hpp"
#include "files.hpp"
#include "elf_utils.hpp"

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

extern "C" void __register_frame(void*) __attribute__((weak));
extern "C" void __deregister_frame(void*) __attribute__((weak));

struct deferred_ifunc {
    uintptr_t target;
    uintptr_t resolver;
};

struct tlsdesc {
    void* resolver;
    uint64_t arg;
};

struct CustomTlsInfo {
    size_t module_id;
    pthread_key_t key;
};

struct tls_index {
    size_t module_id;
    size_t offset;
};

struct DestructorAction {
    enum Type { FUNC_PTR, TLS_CLEANUP, DWARF_CLEANUP, TLSDESC_CLEANUP } type;
    union {
        void (*func_ptr)();
        size_t mod_id;
        uintptr_t frame_ptr;
        tls_index* tlsdesc_arg;
    };
};

struct MemMap {
    uintptr_t base;
    size_t size;
};

struct CustomRegion {
    uintptr_t handle; // Main module identifier (for unload)
    std::vector<MemMap> maps; // List of all mapped memories (main + deps)
    std::vector<DestructorAction> destructors;
};

// Pointers and thread-safe initialization flag
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static std::mutex* g_custom_regions_lock = nullptr;
static std::vector<CustomRegion>* g_custom_regions = nullptr;

/* Actual allocator function called only once */
static void do_init_tracking() {
    g_custom_regions_lock = new std::mutex();
    g_custom_regions = new std::vector<CustomRegion>();
}

static void init_region_tracking() {
    // pthread_once guarantees do_init_tracking runs strictly once, 
    // even if 100 threads call it at the exact same nanosecond.
    pthread_once(&g_init_once, do_init_tracking);
}

bool is_custom_linker_address(const void* addr) {
    init_region_tracking();
    uintptr_t ptr = reinterpret_cast<uintptr_t>(addr);
    std::lock_guard<std::mutex> lock(*g_custom_regions_lock);
    for (const auto& reg : *g_custom_regions) {
        for (const auto& map : reg.maps) {
            if (ptr >= map.base && ptr < map.base + map.size) return true;
        }
    }
    return false;
}

void custom_linker_unload(void* handle) {
    init_region_tracking();
    uintptr_t base = reinterpret_cast<uintptr_t>(handle);
    std::lock_guard<std::mutex> lock(*g_custom_regions_lock);
    for (auto it = g_custom_regions->begin(); it != g_custom_regions->end(); ++it) {
        if (it->handle == base) {
            for (const auto& d : it->destructors) {
                if (d.type == DestructorAction::FUNC_PTR && d.func_ptr) {
                    d.func_ptr();
                } else if (d.type == DestructorAction::TLS_CLEANUP) {
                    CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(d.mod_id);
                    pthread_key_delete(tls_info->key);
                    delete tls_info;
                } else if (d.type == DestructorAction::TLSDESC_CLEANUP) {
                    delete d.tlsdesc_arg;
                } else if (d.type == DestructorAction::DWARF_CLEANUP && __deregister_frame) {
                    __deregister_frame(reinterpret_cast<void*>(d.frame_ptr));
                }
            }

            for (const auto& map : it->maps) {
                if (map.base != 0 && map.size != 0) {
                    munmap(reinterpret_cast<void*>(map.base), map.size);
                }
            }

            g_custom_regions->erase(it);
            return;
        }
    }
}

struct LoadedModule {
    char path[256];
    uintptr_t load_bias;
    uintptr_t base;
    size_t size;
    elf_dyn_info dinfo;

    bool eh_registered = false;
    uintptr_t eh_frame_ptr = 0;
    std::vector<tls_index*> tlsdesc_args;
};


#ifdef __LP64__
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#endif

static bool resolve_symbol_addr(const elf_dyn_info *info,
                                const char** needed_paths, size_t needed_count,
                                const std::vector<LoadedModule>& loaded_modules,
                                uintptr_t load_bias, size_t sym_idx, uintptr_t *out_addr) {

    if (sym_idx >= info->nsyms) return false;
    const ElfW(Sym)& sym = info->symtab[sym_idx];
    uint64_t hwcap = getauxval(AT_HWCAP);

    if (sym.st_shndx != SHN_UNDEF) { 
        uintptr_t addr = (uintptr_t)load_bias + (uintptr_t)sym.st_value;
        if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
            typedef void* (*ifunc_resolver_t)(uint64_t);
            auto ifunc = reinterpret_cast<ifunc_resolver_t>(addr);
            // IFUNC resolvers can return PAC-signed pointers
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

    for (size_t k = 0; k < needed_count; k++) {
        const char* mod_path = needed_paths[k];
        if (!mod_path || !*mod_path) continue;
        // First try to resolve within our newly loaded modules
        for (const auto& mod : loaded_modules) {
            if (mod.path == mod_path) {
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

struct sleb128_decoder {
    const uint8_t *current;
    const uint8_t *end;
};

static void sleb128_decoder_init(sleb128_decoder *decoder, const uint8_t *buffer, size_t count) {
    decoder->current = buffer;
    decoder->end = buffer + count;
}

static int64_t sleb128_decode(sleb128_decoder *decoder) {
    int64_t value = 0;
    size_t shift = 0;
    uint8_t byte;
    const size_t size = sizeof(int64_t) * CHAR_BIT;

    do {
        if (decoder->current >= decoder->end) {
            LOGE("Failed to decode SLEB128: buffer overrun");
            return 0; // Better than aborting the whole daemon
        }

        byte = *decoder->current++;
        value |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if (shift < size && (byte & 0x40)) {
        value |= -((int64_t)1 << shift);
    }

    return value;
}

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end) {
    const uint8_t *s = *p;
    uint64_t r = 0;
    unsigned shift = 0;

    while (s < end) {
        uint8_t b = *s++;
        r |= ((uint64_t)(b & 0x7f)) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift >= 64) break;
    }
    *p = s;
    return r;
}

#define DW_EH_PE_omit     0xff
#define DW_EH_PE_ptr      0x00
#define DW_EH_PE_uleb128  0x01
#define DW_EH_PE_udata2   0x02
#define DW_EH_PE_udata4   0x03
#define DW_EH_PE_udata8   0x04
#define DW_EH_PE_sdata2   0x0a
#define DW_EH_PE_sdata4   0x0b
#define DW_EH_PE_sdata8   0x0c

#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_indirect 0x80

#ifndef DT_VERSYM
#define DT_VERSYM 0x6ffffff0
#endif
#ifndef ELF_ST_BIND
#define ELF_ST_BIND(i) ((i)>>4)
#endif
#ifndef STB_WEAK
#define STB_WEAK 2
#endif

static int read_u16(const uint8_t **p, const uint8_t *end, uint16_t *out) {
    if ((size_t)(end - *p) < sizeof(uint16_t)) return -1;
    uint16_t v = 0;
    memcpy(&v, *p, sizeof(uint16_t));
    *p += sizeof(uint16_t);
    *out = v;
    return 0;
}

static int read_u32(const uint8_t **p, const uint8_t *end, uint32_t *out) {
    if ((size_t)(end - *p) < sizeof(uint32_t)) return -1;
    uint32_t v = 0;
    memcpy(&v, *p, sizeof(uint32_t));
    *p += sizeof(uint32_t);
    *out = v;
    return 0;
}

static int read_u64(const uint8_t **p, const uint8_t *end, uint64_t *out) {
    if ((size_t)(end - *p) < sizeof(uint64_t)) return -1;
    uint64_t v = 0;
    memcpy(&v, *p, sizeof(uint64_t));
    *p += sizeof(uint64_t);
    *out = v;
    return 0;
}

static uintptr_t decode_eh_value(uint8_t enc, const uint8_t **p, uintptr_t base, uintptr_t data_base, const uint8_t *end) {
    if (enc == DW_EH_PE_omit) return 0;
    uint8_t fmt = enc & 0x0f;
    uint8_t app = enc & 0x70;

    uintptr_t value = 0;
    switch (fmt) {
        case DW_EH_PE_ptr: {
#ifdef __LP64__
            uint64_t raw = 0;
            if (read_u64(p, end, &raw) != 0) return 0;
            value = (uintptr_t)raw;
#else
            uint32_t raw = 0;
            if (read_u32(p, end, &raw) != 0) return 0;
            value = (uintptr_t)raw;
#endif
            break;
        }
        case DW_EH_PE_uleb128:
            value = (uintptr_t)read_uleb128(p, end);
            break;
        case DW_EH_PE_udata2: {
            uint16_t raw = 0;
            if (read_u16(p, end, &raw) != 0) return 0;
            value = (uintptr_t)raw;
            break;
        }
        case DW_EH_PE_udata4: {
            uint32_t raw = 0;
            if (read_u32(p, end, &raw) != 0) return 0;
            value = (uintptr_t)raw;
            break;
        }
        case DW_EH_PE_udata8: {
            uint64_t raw = 0;
            if (read_u64(p, end, &raw) != 0) return 0;
            value = (uintptr_t)raw;
            break;
        }
        case DW_EH_PE_sdata2: {
            uint16_t raw = 0;
            if (read_u16(p, end, &raw) != 0) return 0;
            value = (uintptr_t)(intptr_t)(int16_t)raw;
            break;
        }
        case DW_EH_PE_sdata4: {
            uint32_t raw = 0;
            if (read_u32(p, end, &raw) != 0) return 0;
            value = (uintptr_t)(intptr_t)(int32_t)raw;
            break;
        }
        case DW_EH_PE_sdata8: {
            uint64_t raw = 0;
            if (read_u64(p, end, &raw) != 0) return 0;
            value = (uintptr_t)(intptr_t)(int64_t)raw;
            break;
        }
        default: return 0;
    }

    switch (app) {
        case DW_EH_PE_absptr: break;
        case DW_EH_PE_pcrel: value += base; break;
        case DW_EH_PE_datarel: value += data_base; break;
        default: break;
    }

    return value;
}

static bool apply_rela_section(int fd, LoadedModule& mod,
                               [[maybe_unused]] const char** needed_paths, 
                               [[maybe_unused]] size_t needed_count,
                               [[maybe_unused]] const std::vector<LoadedModule>& loaded_modules,
                               off_t rela_off, size_t rela_sz,
                               [[maybe_unused]] std::vector<deferred_ifunc>& ifuncs) {
    [[maybe_unused]] const elf_dyn_info* info = &mod.dinfo;
    uintptr_t load_bias = mod.load_bias;
    size_t count = rela_sz / sizeof(ElfW(Rela));
    auto rels = std::make_unique<ElfW(Rela)[]>(count);
    if (!read_loop_offset(fd, rels.get(), rela_sz, rela_off)) return false;

    for (size_t i = 0; i < count; i++) {
        const ElfW(Rela)& r = rels[i];

        [[maybe_unused]] unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        [[maybe_unused]] unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
        ElfW(Addr) value = 0;

#if defined(__aarch64__)
        if (type == R_AARCH64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else if (type == R_AARCH64_IRELATIVE) {
            ifuncs.push_back({target, (uintptr_t)load_bias + (uintptr_t)r.r_addend});
        } else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_ABS64) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                if (ELF_ST_BIND(info->symtab[sym].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false; // abort load
                }
                sym_addr = 0;
            }
            value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
        } else if (type == R_AARCH64_TLS_DTPMOD) {
            value = info->tls_mod_id;
        } else if (type == R_AARCH64_TLS_DTPREL) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value + r.r_addend;
        } else if (type == R_AARCH64_TLSDESC) {
            tlsdesc* td = reinterpret_cast<tlsdesc*>(target);
            tls_index* ti = new tls_index;
            ti->module_id = info->tls_mod_id;
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                ti->offset = r.r_addend;
            } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                ti->offset = (sym_addr - load_bias) + r.r_addend;
            } else {
                ti->offset = r.r_addend;
            }
            td->resolver = reinterpret_cast<void*>(custom_tlsdesc_resolver_stub);
            td->arg = reinterpret_cast<uint64_t>(ti);
            const_cast<LoadedModule&>(mod).tlsdesc_args.push_back(ti);

            continue;
        } else if (type == R_AARCH64_TLS_TPREL) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr + r.r_addend;
            } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#elif defined(__x86_64__)
        if (type == R_X86_64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else if (type == R_X86_64_IRELATIVE) {
            ifuncs.push_back({target, (uintptr_t)load_bias + (uintptr_t)r.r_addend});
            continue;
        } else if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT || type == R_X86_64_64) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                if (ELF_ST_BIND(info->symtab[sym].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
        } else if (type == R_X86_64_DTPMOD64) {
            value = info->tls_mod_id;
        } else if (type == R_X86_64_DTPOFF64) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value + r.r_addend;
        } else if (type == R_X86_64_TPOFF64) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr + r.r_addend;
            } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#else
        if (type == 0) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else return false;
#endif
        *reinterpret_cast<ElfW(Addr)*>(target) = value;
    }
    return true;
}

static bool apply_rel_section(int fd, LoadedModule& mod,
                              [[maybe_unused]] const char** needed_paths,
                              [[maybe_unused]] size_t needed_count,
                              [[maybe_unused]] const std::vector<LoadedModule>& loaded_modules,
                              off_t rel_off, size_t rel_sz,
                              [[maybe_unused]] std::vector<deferred_ifunc>& ifuncs) {
    [[maybe_unused]] const elf_dyn_info* info = &mod.dinfo;
    uintptr_t load_bias = mod.load_bias;
    size_t count = rel_sz / sizeof(ElfW(Rel));
    auto rels = std::make_unique<ElfW(Rel)[]>(count);
    if (!read_loop_offset(fd, rels.get(), rel_sz, rel_off)) return false;

    for (size_t i = 0; i < count; i++) {
        const ElfW(Rel)& r = rels[i];

        [[maybe_unused]] unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        [[maybe_unused]] unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
        [[maybe_unused]] ElfW(Addr) addend = 0;
        ElfW(Addr) value = 0;

#if defined(__arm__)
        if (type == R_ARM_RELATIVE) {
            addend = *reinterpret_cast<ElfW(Addr)*>(target);
            value = (ElfW(Addr))load_bias + addend;
        } else if (type == R_ARM_IRELATIVE) {
            addend = *reinterpret_cast<ElfW(Addr)*>(target);
            ifuncs.push_back({target, (uintptr_t)load_bias + addend});
            continue;
        } else if (type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT || type == R_ARM_ABS32) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                if (ELF_ST_BIND(info->symtab[sym].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            if (sym_addr == 0) value = 0;
            else if (type == R_ARM_ABS32) {
                addend = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))sym_addr + addend;
            } else value = (ElfW(Addr))sym_addr;
        } else if (type == R_ARM_TLS_DTPMOD32) {
            value = info->tls_mod_id;
        } else if (type == R_ARM_TLS_DTPOFF32) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value; // REL section relies on addend read from mem if present but usually 0 for dtpoff unless added manually
        } else if (type == R_ARM_TLS_TPOFF32) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr;
            } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#elif defined(__i386__)
        if (type == R_386_RELATIVE) {
            addend = *reinterpret_cast<ElfW(Addr)*>(target);
            value = (ElfW(Addr))load_bias + addend;
        } else if (type == R_386_IRELATIVE) {
            addend = *reinterpret_cast<ElfW(Addr)*>(target);
            ifuncs.push_back({target, (uintptr_t)load_bias + addend});
            continue;
        } else if (type == R_386_GLOB_DAT || type == R_386_JMP_SLOT || type == R_386_32) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                if (ELF_ST_BIND(info->symtab[sym].st_info) != STB_WEAK) {
                    LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                    return false;
                }
                sym_addr = 0;
            }
            if (sym_addr == 0) value = 0;
            else if (type == R_386_32) {
                addend = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))sym_addr + addend;
            } else value = (ElfW(Addr))sym_addr;
        } else if (type == R_386_TLS_DTPMOD32) {
            value = info->tls_mod_id;
        } else if (type == R_386_TLS_DTPOFF32) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value;
        } else if (type == R_386_TLS_TPOFF) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr;
            } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#else
        return false;
#endif
        *reinterpret_cast<ElfW(Addr)*>(target) = value;
    }
    return true;
}

static bool apply_android_relocations(int fd, LoadedModule& mod,
                                      const char** needed_paths, size_t needed_count,
                                      const std::vector<LoadedModule>& loaded_modules,
                                      off_t reloc_off, size_t reloc_sz,
                                      std::vector<deferred_ifunc>& ifuncs, bool is_rela) {
    const elf_dyn_info* info = &mod.dinfo;
    uintptr_t load_bias = mod.load_bias;
    auto reloc_data = std::make_unique<uint8_t[]>(reloc_sz);
    if (!read_loop_offset(fd, reloc_data.get(), reloc_sz, reloc_off)) return false;

    if (reloc_sz < 4 || memcmp(reloc_data.get(), "APS2", 4) != 0) {
        LOGE("Invalid Android REL/RELA magic");
        return false;
    }

    sleb128_decoder decoder;
    sleb128_decoder_init(&decoder, reloc_data.get() + 4, reloc_sz - 4);

    uint64_t num_relocs = sleb128_decode(&decoder);
    ElfW(Addr) current_offset = sleb128_decode(&decoder);

    unsigned current_sym_idx = 0;
    unsigned current_type = 0;
    ElfW(Addr) current_addend = 0;

    for (uint64_t i = 0; i < num_relocs; ) {
        uint64_t group_size = sleb128_decode(&decoder);
        uint64_t group_flags = sleb128_decode(&decoder);

        size_t group_r_offset_delta = 0;
        const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
        const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
        const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
        const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

        if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
            group_r_offset_delta = sleb128_decode(&decoder);
        }

        if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
            ElfW(Addr) r_info = sleb128_decode(&decoder);
            current_sym_idx = ELF_R_SYM(r_info);
            current_type = ELF_R_TYPE(r_info);
        }

        size_t group_flags_reloc = 0;
        if (is_rela) {
            group_flags_reloc = group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG);
            if (group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                // Each relocation has an addend.
            } else if (group_flags_reloc == (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
                current_addend += sleb128_decode(&decoder);
            } else {
                current_addend = 0;
            }
        } else {
            if (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                LOGE("REL relocations should not have addends");
                return false;
            }
        }

        for (size_t j = 0; j < group_size; ++j) {
            if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
                current_offset += group_r_offset_delta;
            } else {
                current_offset += sleb128_decode(&decoder);
            }
            if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
                ElfW(Addr) r_info = sleb128_decode(&decoder);
                current_sym_idx = ELF_R_SYM(r_info);
                current_type = ELF_R_TYPE(r_info);
            }
            if (is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                current_addend += sleb128_decode(&decoder);
            }

            uintptr_t target = (uintptr_t)load_bias + (uintptr_t)current_offset;
            ElfW(Addr) value = 0;

#if defined(__aarch64__)
            if (current_type == R_AARCH64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
            else if (current_type == R_AARCH64_IRELATIVE) {
                ifuncs.push_back({target, (uintptr_t)load_bias + (uintptr_t)current_addend});
                continue;
            } else if (current_type == R_AARCH64_GLOB_DAT || current_type == R_AARCH64_JUMP_SLOT || current_type == R_AARCH64_ABS64) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                        LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                        return false;
                    }
                    sym_addr = 0;
                }
                value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))current_addend : 0;
            } else if (current_type == R_AARCH64_TLS_DTPMOD) {
                value = info->tls_mod_id;
            } else if (current_type == R_AARCH64_TLS_DTPREL) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_AARCH64_TLS_TPREL) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr; // Rough TPREL emulation without tpidr thread-context
                }
            } else if (current_type == R_AARCH64_TLSDESC) {
                tlsdesc* td = reinterpret_cast<tlsdesc*>(target);
                tls_index* ti = new tls_index;
                ti->module_id = info->tls_mod_id;
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    ti->offset = current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    ti->offset = (sym_addr - load_bias) + current_addend;
                } else {
                    ti->offset = current_addend;
                }
                td->resolver = reinterpret_cast<void*>(custom_tlsdesc_resolver_stub);
                td->arg = reinterpret_cast<uint64_t>(ti);                
                const_cast<LoadedModule&>(mod).tlsdesc_args.push_back(ti);

                continue;
            } else return false;
#elif defined(__x86_64__)
            if (current_type == R_X86_64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
            else if (current_type == R_X86_64_IRELATIVE) {
                ifuncs.push_back({target, (uintptr_t)load_bias + (uintptr_t)current_addend});
                continue;
            } else if (current_type == R_X86_64_GLOB_DAT || current_type == R_X86_64_JUMP_SLOT || current_type == R_X86_64_64) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                        LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                        return false;
                    }
                    sym_addr = 0;
                }
                value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))current_addend : 0;
            } else if (current_type == R_X86_64_DTPMOD64) {
                value = info->tls_mod_id;
            } else if (current_type == R_X86_64_DTPOFF64) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_X86_64_TPOFF64) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr;
                }
            } else return false;
#elif defined(__arm__)
            if (current_type == R_ARM_RELATIVE) {
                ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))load_bias + addend_rel;
            } else if (current_type == R_ARM_IRELATIVE) {
                ifuncs.push_back({target, (uintptr_t)load_bias + (uintptr_t)current_addend});
                continue;
            } else if (current_type == R_ARM_GLOB_DAT || current_type == R_ARM_JUMP_SLOT || current_type == R_ARM_ABS32) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                        LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                        return false;
                    }
                    sym_addr = 0;
                }
                if (sym_addr == 0) value = 0;
                else if (current_type == R_ARM_ABS32) {
                    ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                    value = (ElfW(Addr))sym_addr + addend_rel;
                } else value = (ElfW(Addr))sym_addr;
            } else if (current_type == R_ARM_TLS_DTPMOD32) {
                value = info->tls_mod_id;
            } else if (current_type == R_ARM_TLS_DTPOFF32) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_ARM_TLS_TPOFF32) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr;
                }
            } else return false;
#elif defined(__i386__)
            if (current_type == R_386_RELATIVE) {
                ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))load_bias + addend_rel;
            } else if (current_type == R_386_IRELATIVE) {
                ifuncs.push_back({target, (uintptr_t)load_bias + (uintptr_t)current_addend});
                continue;
            } else if (current_type == R_386_GLOB_DAT || current_type == R_386_JMP_SLOT || current_type == R_386_32) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    if (ELF_ST_BIND(info->symtab[current_sym_idx].st_info) != STB_WEAK) {
                        LOGE("CANNOT LINK EXECUTABLE: missing strong symbol");
                        return false;
                    }
                    sym_addr = 0;
                }
                if (sym_addr == 0) value = 0;
                else if (current_type == R_386_32) {
                    ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                    value = (ElfW(Addr))sym_addr + addend_rel;
                } else value = (ElfW(Addr))sym_addr;
            } else if (current_type == R_386_TLS_DTPMOD32) {
                value = info->tls_mod_id;
            } else if (current_type == R_386_TLS_DTPOFF32) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_386_TLS_TPOFF) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, needed_count, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr;
                }
            } else return false;
#else
            return false;
#endif
            *reinterpret_cast<ElfW(Addr)*>(target) = value;
        }

        i += group_size;
    }
    return true;
}

static bool apply_relr_section(int fd, LoadedModule& mod, off_t relr_off, size_t relr_sz) {
    uintptr_t load_bias = mod.load_bias;
    size_t count = relr_sz / sizeof(ElfW(Addr));
    auto relr = std::make_unique<ElfW(Addr)[]>(count);
    if (!read_loop_offset(fd, relr.get(), relr_sz, relr_off)) return false;

    const size_t bits_per_entry = sizeof(ElfW(Addr)) * 8;
    ElfW(Addr) base_offset = 0;

    for (size_t i = 0; i < count; i++) {
        ElfW(Addr) entry = relr[i];

        if ((entry & 1) == 0) {
            // Even entries encode an explicit address
            ElfW(Addr) reloc_offset = entry;
            uintptr_t target = (uintptr_t)load_bias + reloc_offset;
            ElfW(Addr) value = *reinterpret_cast<ElfW(Addr)*>(target);
            value += load_bias;
            *reinterpret_cast<ElfW(Addr)*>(target) = value;

            base_offset = reloc_offset + sizeof(ElfW(Addr));
            continue;
        }

        // Odd entries encode a bitmap of up to (bits_per_entry - 1) following words
        ElfW(Addr) bitmap = entry >> 1;

        for (size_t bit = 0; bitmap != 0 && bit < bits_per_entry - 1; bit++, bitmap >>= 1) {
            if ((bitmap & 1) == 0) continue;

            uintptr_t target = (uintptr_t)load_bias + base_offset + (bit * sizeof(ElfW(Addr)));
            ElfW(Addr) value = *reinterpret_cast<ElfW(Addr)*>(target);
            value += load_bias;
            *reinterpret_cast<ElfW(Addr)*>(target) = value;
        }

        base_offset += sizeof(ElfW(Addr)) * (bits_per_entry - 1);
    }

    return true;
}

static bool apply_module_relocations(int memfd, LoadedModule& mod, const std::vector<LoadedModule>& loaded_modules) {
    std::vector<deferred_ifunc> ifuncs;
    UniqueFd fd;

    if (strcmp(mod.path, "main_module") == 0 && memfd >= 0) {
        fd = UniqueFd(dup(memfd));
    } else {
        fd = UniqueFd(open(mod.path, O_RDONLY | O_CLOEXEC));
    }

    if (fd < 0) {
        LOGE("Failed to open module file for relocations: %s", mod.path);
        return false;
    }

    size_t needed_count = mod.dinfo.needed_count;
    const char** needed_paths = (const char**)alloca(needed_count * sizeof(const char*));
    memset(needed_paths, 0, needed_count * sizeof(const char*));

    for (size_t i = 0; i < needed_count; i++) {
        size_t off = mod.dinfo.needed_str_offsets[i];
        if (off < mod.dinfo.strsz) {
            const char *soname = &mod.dinfo.strtab[off];
            for (const auto& m : loaded_modules) {
                const char *m_name = strrchr(m.path, '/');
                m_name = m_name ? m_name + 1 : m.path;
                if (strcmp(m_name, soname) == 0) {
                    needed_paths[i] = m.path;
                    break;
                }
            }
        }
    }

    if (mod.dinfo.rela_sz && mod.dinfo.rela_off) {
        if (!apply_rela_section(fd, mod, needed_paths, needed_count, loaded_modules, mod.dinfo.rela_off, mod.dinfo.rela_sz, ifuncs)) return false;
    }
    if (mod.dinfo.rel_sz && mod.dinfo.rel_off) {
        if (!apply_rel_section(fd, mod, needed_paths, needed_count, loaded_modules, mod.dinfo.rel_off, mod.dinfo.rel_sz, ifuncs)) return false;
    }
    if (mod.dinfo.jmprel_sz && mod.dinfo.jmprel_off) {
        if (mod.dinfo.pltrel_type == DT_RELA) {
            if (!apply_rela_section(fd, mod, needed_paths, needed_count, loaded_modules, mod.dinfo.jmprel_off, mod.dinfo.jmprel_sz, ifuncs)) return false;
        } else {
            if (!apply_rel_section(fd, mod, needed_paths, needed_count, loaded_modules, mod.dinfo.jmprel_off, mod.dinfo.jmprel_sz, ifuncs)) return false;
        }
    }

    if (mod.dinfo.android_rel_sz && mod.dinfo.android_rel_off) {
        if (!apply_android_relocations(fd, mod, needed_paths, needed_count, loaded_modules, mod.dinfo.android_rel_off, mod.dinfo.android_rel_sz, ifuncs, mod.dinfo.android_is_rela)) return false;
    }
    if (mod.dinfo.relr_sz && mod.dinfo.relr_off) {
        if (!apply_relr_section(fd, mod, mod.dinfo.relr_off, mod.dinfo.relr_sz)) return false;
    }

    // At this point all global tables (GOT, BSS, etc) are initialized.
    // It is safe to call executable code from the module.
    uint64_t hwcap = getauxval(AT_HWCAP);
    for (const auto& ifunc : ifuncs) {
        typedef void* (*ifunc_resolver_t)(uint64_t);
        auto resolver = reinterpret_cast<ifunc_resolver_t>(ifunc.resolver);
        uintptr_t value = PAC_STRIP(reinterpret_cast<uintptr_t>(resolver(hwcap)));
        *reinterpret_cast<ElfW(Addr)*>(ifunc.target) = value;
    }

    return true;
}

static bool load_single_library(const char *lib_path, int memfd, LoadedModule* out_module) {
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size = (size_t)page_size_long;

    UniqueFd fd;
    if (memfd >= 0) {
        fd = UniqueFd(dup(memfd));
    } else {
        fd = UniqueFd(open(lib_path, O_RDONLY | O_CLOEXEC));
    }
    if (fd < 0) return false;

    ElfW(Ehdr) eh;
    std::unique_ptr<ElfW(Phdr)[]> phdr;
    ElfW(Addr) min_vaddr = 0;
    size_t map_size = 0;

    if (!compute_load_layout(fd, page_size, &eh, phdr, &min_vaddr, &map_size)) { return false; }

    void* remote_base_ptr = mmap(nullptr, map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remote_base_ptr == MAP_FAILED) return false;
    uintptr_t remote_base = reinterpret_cast<uintptr_t>(remote_base_ptr);

    uintptr_t load_bias = remote_base - (uintptr_t)min_vaddr;
    struct SegInfo { uintptr_t addr; size_t len; int prot; };
    SegInfo segs[64];
    size_t seg_count = 0;

    for (int i = 0; i < eh.e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        uintptr_t seg_start = (uintptr_t)phdr[i].p_vaddr + load_bias;
        uintptr_t seg_page = page_start(seg_start, page_size);
        uintptr_t seg_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_memsz + load_bias;
        uintptr_t seg_page_end = page_end(seg_end, page_size);
        size_t seg_page_len = (size_t)(seg_page_end - seg_page);

        bool is_writable = (phdr[i].p_flags & PF_W) != 0;
        off_t file_page_offset = (off_t)page_start((uintptr_t)phdr[i].p_offset, page_size);
        uintptr_t file_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_filesz + load_bias;
        uintptr_t file_page_end = page_end(file_end, page_size);

        if (phdr[i].p_filesz > 0) {
            void* seg_map = mmap(reinterpret_cast<void*>(seg_page), file_page_end - seg_page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, file_page_offset);
            if (seg_map == MAP_FAILED) return false;

            if (is_writable && file_page_end > file_end) {
                memset(reinterpret_cast<void*>(file_end), 0, file_page_end - file_end);
            }
        }

        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            uintptr_t bss_start = file_end;
            uintptr_t bss_end = seg_end;
            uintptr_t bss_page_end_align = page_start(bss_start + page_size - 1, page_size);

            size_t zero_size = bss_page_end_align - bss_start;
            if (zero_size > 0 && is_writable) {
                memset(reinterpret_cast<void*>(bss_start), 0, zero_size);
            }

            if (bss_end > bss_page_end_align) {
                void* bss_map = mmap(reinterpret_cast<void*>(bss_page_end_align), bss_end - bss_page_end_align, 
                                     PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (bss_map == MAP_FAILED) return false;
            }
        }

        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        if (seg_count < 64) {
            segs[seg_count++] = {seg_page, seg_page_len, prot};
        } else {
            LOGW("Too many segments in the ELF, some may not have correct permissions set");
        }
    }

    elf_dyn_info dinfo;
    if (!elf_load_dyn_info(fd, &eh, phdr, &dinfo)) return false;

    for (const auto& s : segs) {
        if (s.prot == (PROT_READ | PROT_WRITE)) continue;
        mprotect(reinterpret_cast<void*>(s.addr), s.len, s.prot);
    }

    if (dinfo.tls_segment_vaddr && dinfo.tls_segment_memsz) {
        CustomTlsInfo* tls_info = new CustomTlsInfo();
        tls_info->module_id = reinterpret_cast<size_t>(tls_info);
        pthread_key_create(&tls_info->key, free);
        dinfo.tls_mod_id = tls_info->module_id;
    }

    strlcpy(out_module->path, lib_path, sizeof(out_module->path));
    out_module->load_bias = load_bias;
    out_module->base = remote_base;
    out_module->size = map_size;
    out_module->dinfo = std::move(dinfo);

    return true;
}

static bool _linker_find_library_path(const char *lib_name, char *full_path, size_t full_path_size) {
    const char *search_paths[] = {
#ifdef __LP64__
#ifdef __ANDROID__
        "/apex/com.android.runtime/lib64/bionic/",
        "/apex/com.android.runtime/lib64/",
        "/system/lib64/",
        "/vendor/lib64/",
#else
        "/lib64/",
        "/usr/lib64/",
        "/lib/x86_64-linux-gnu/",
        "/usr/lib/x86_64-linux-gnu/",
#endif
#else
#ifdef __ANDROID__
        "/apex/com.android.runtime/lib/bionic/",
        "/apex/com.android.runtime/lib/",
        "/system/lib/",
        "/vendor/lib/",
#else
        "/lib/",
        "/usr/lib/",
        "/lib/i386-linux-gnu/",
#endif
#endif
        "/usr/local/lib/",
        nullptr
    };

#ifdef __ANDROID__
    if (strstr(lib_name, "libc++")) {
        LOGD("Forced replacement for using /system/lib64 for libc++.so");
#ifdef __LP64__
        snprintf(full_path, full_path_size, "/system/lib64/%s", lib_name);
#else
        snprintf(full_path, full_path_size, "/system/lib/%s", lib_name);
#endif
        return true;
    }
#endif

    for (int i = 0; search_paths[i] != nullptr; ++i) {
        snprintf(full_path, full_path_size, "%s%s", search_paths[i], lib_name);
        if (access(full_path, F_OK) == 0) return true;
    }

    full_path[0] = '\0';
    return false;
}

static bool load_dependencies_recursive(const char *lib_path, int memfd, std::vector<LoadedModule>& loaded_modules) {
    const char *soname = strrchr(lib_path, '/');
    soname = soname ? soname + 1 : lib_path;

    for (const auto& m : loaded_modules) {
        const char *m_name = strrchr(m.path, '/');
        m_name = m_name ? m_name + 1 : m.path;
        if (strcmp(m_name, soname) == 0) {
            return true; // Already loaded
        }
    }

    // Allows the system linker (Bionic) to load the library if it is system.
    // We remove RTLD_NOLOAD so that Bionic can safely load it if it is missing, 
    // avoiding mapping duplicate manual copies of the OS.
    void* existing_handle = dlopen(soname, RTLD_NOW);
    if (existing_handle != nullptr) {
        // We INTENTIONALLY do not do dlclose(). We want the system to maintain
        // the library lives in memory so that our module can use it.
        return true;
    }

    LoadedModule mod;
    if (!load_single_library(lib_path, memfd, &mod)) {
        LOGE("Failed to load dependency: %s", lib_path);
        return false;
    }

    loaded_modules.push_back(std::move(mod));
    size_t current_idx = loaded_modules.size() - 1;
    size_t offsets_count = loaded_modules[current_idx].dinfo.needed_count;

    for (size_t i = 0; i < offsets_count; i++) {
        size_t off = loaded_modules[current_idx].dinfo.needed_str_offsets[i];
        if (off >= loaded_modules[current_idx].dinfo.strsz) continue;

        const char *dep_soname = &loaded_modules[current_idx].dinfo.strtab[off];

        char full_path[1024];
        if (_linker_find_library_path(dep_soname, full_path, sizeof(full_path))) {
            if (!load_dependencies_recursive(full_path, -1, loaded_modules)) {
                LOGW("Failed to recursively load dependency %s for %s", full_path, lib_path);
            }
        } else {
            LOGW("Could not find library path for %s needed by %s", dep_soname, lib_path);
        }
    }
    return true;
}

static inline void cleanup_failed_load(const std::vector<LoadedModule>& loaded_modules) {
    for (auto it = loaded_modules.rbegin(); it != loaded_modules.rend(); ++it) {
        const auto& mod = *it;
        if (mod.eh_registered && __deregister_frame) {
            __deregister_frame(reinterpret_cast<void*>(mod.eh_frame_ptr));
        }
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
            size_t size = 4096;
            posix_memalign(&ptr, 16, size);
            memset(ptr, 0, size);
            pthread_setspecific(tls_info->key, ptr);
        }
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(ptr) + ti->offset);
    }
    auto original_tls = reinterpret_cast<void*(*)(tls_index*)>(dlsym(RTLD_DEFAULT, "__tls_get_addr"));
    return original_tls ? original_tls(ti) : nullptr;
}

// ---------------- MAIN ----------------
extern "C" bool custom_linker_load(int memfd, uintptr_t *out_base, size_t *out_total_size, uintptr_t *out_entry, uintptr_t *out_init_array, size_t *out_init_count) {
    std::vector<LoadedModule> loaded_modules;

    // Give a dummy name for the main module
    if (!load_dependencies_recursive("main_module", memfd, loaded_modules)) {
        LOGE("Failed to recursively load main module and its dependencies");
        cleanup_failed_load(loaded_modules);
        return false;
    }

    if (loaded_modules.empty()) return false;

    // Step 1: Hook TLS for all modules first
    for (auto& mod : loaded_modules) {
        for (size_t i = 0; i < mod.dinfo.nsyms; i++) {
            ElfW(Sym)& sym = mod.dinfo.symtab[i];
            if (sym.st_name != 0 && sym.st_name < mod.dinfo.strsz) {
                const char *name = &mod.dinfo.strtab[sym.st_name];
                if (strcmp(name, "__tls_get_addr") == 0) {
                    // PAC Strip local function pointer before writing
                    sym.st_value = PAC_STRIP(reinterpret_cast<uintptr_t>(&custom_tls_get_addr)) - mod.load_bias;
                    sym.st_shndx = 1;
                }
            }
        }
    }

    // Step 2: Relocate and Initialize in REVERSE order (dependencies first)
    for (auto it = loaded_modules.rbegin(); it != loaded_modules.rend(); ++it) {
        auto& mod = *it;

        if (!apply_module_relocations(memfd, mod, loaded_modules)) {
            LOGE("Failed to apply relocations for module %s", mod.path);
            cleanup_failed_load(loaded_modules);
            return false;
        }

        if (mod.dinfo.relro_vaddr && mod.dinfo.relro_sz) {
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            uintptr_t relro_start = mod.load_bias + mod.dinfo.relro_vaddr;
            uintptr_t relro_end = relro_start + mod.dinfo.relro_sz;

            // We align the end down (page_start instead of page_end).
            // This avoids making the adjacent page read-only if the compiler 
            // it didn't zero-padded it perfectly, protecting neighboring global variables.
            uintptr_t commit_start = page_start(relro_start, page_size);
            uintptr_t commit_end = page_start(relro_end, page_size);

            if (commit_end > commit_start) {
                mprotect(reinterpret_cast<void*>(commit_start), commit_end - commit_start, PROT_READ);
            }
        }

        // Register DWARF immediately after relocation
        if (__register_frame && mod.dinfo.eh_frame_hdr_sz && mod.dinfo.eh_frame_hdr_vaddr) {
            uintptr_t hdr_addr = mod.load_bias + mod.dinfo.eh_frame_hdr_vaddr;
            const uint8_t *p = reinterpret_cast<const uint8_t*>(hdr_addr);
            const uint8_t *end = p + mod.dinfo.eh_frame_hdr_sz;

            if (mod.dinfo.eh_frame_hdr_sz >= 4) {
                uint8_t version = *p++;
                uint8_t eh_frame_ptr_enc = *p++;
                [[maybe_unused]] uint8_t fde_count_enc = *p++;
                [[maybe_unused]] uint8_t table_enc = *p++;

                if (version == 1) {
                    uintptr_t base = hdr_addr + (p - reinterpret_cast<const uint8_t*>(hdr_addr));
                    uintptr_t eh_frame_ptr = decode_eh_value(eh_frame_ptr_enc, &p, base, hdr_addr, end);
                    if (eh_frame_ptr) {
                        __register_frame(reinterpret_cast<void*>(eh_frame_ptr));
                        mod.eh_registered = true;
                        mod.eh_frame_ptr = eh_frame_ptr;
                    }
                }
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

    LoadedModule& main_mod = loaded_modules[0];

    ElfW(Addr) entry_value = 0;
    // Look for the normal Zygote entry
    bool has_module_entry = find_dynsym_value(&main_mod.dinfo, "zygisk_module_entry", &entry_value);

    // If don't have it, look for the entry in the Companion
    if (!has_module_entry) {
        bool has_companion_entry = find_dynsym_value(&main_mod.dinfo, "zygisk_companion_entry", &entry_value);

        // If it has NEITHER of the two, then it is an invalid module
        if (!has_companion_entry) {
            LOGE("Module %s exports neither 'zygisk_module_entry' nor 'zygisk_companion_entry'. Invalid module.", main_mod.path);
            cleanup_failed_load(loaded_modules);
            return false;
        }
    }

    *out_base = main_mod.base;
    *out_total_size = main_mod.size;
    *out_entry = (uintptr_t)main_mod.load_bias + (uintptr_t)entry_value;
    *out_init_array = main_mod.dinfo.init_array_vaddr ? ((uintptr_t)main_mod.load_bias + main_mod.dinfo.init_array_vaddr) : 0;
    *out_init_count = main_mod.dinfo.init_arraysz ? (main_mod.dinfo.init_arraysz / sizeof(ElfW(Addr))) : 0;

    {
        init_region_tracking();
        std::lock_guard<std::mutex> lock(*g_custom_regions_lock);
        CustomRegion region;
        region.handle = main_mod.base; // Use this as primary ID

        // We save the memory addresses of all modules (Main + Dependencies)
        for (const auto& mod : loaded_modules) {
            if (mod.base != 0 && mod.size != 0) {
                MemMap map;
                map.base = mod.base;
                map.size = mod.size;
                region.maps.push_back(map);
            }
        }

        // We collect all destroyers in reverse order of loading
        for (auto it = loaded_modules.rbegin(); it != loaded_modules.rend(); ++it) {
            const auto& mod = *it;

            // 1. FINI_ARRAY is executed in reverse order
            if (mod.dinfo.fini_array_vaddr && mod.dinfo.fini_arraysz) {
                size_t count = mod.dinfo.fini_arraysz / sizeof(ElfW(Addr));
                ElfW(Addr)* array_addr = reinterpret_cast<ElfW(Addr)*>(mod.load_bias + mod.dinfo.fini_array_vaddr);
                for (size_t i = 0; i < count; ++i) {
                    if (array_addr[count - 1 - i]) {
                        auto func = reinterpret_cast<void (*)()>(array_addr[count - 1 - i]);
                        DestructorAction action;
                        action.type = DestructorAction::FUNC_PTR;
                        action.func_ptr = func;
                        region.destructors.push_back(action);
                    }
                }
            }

            // 2. DT_FINI is executed after FINI_ARRAY
            if (mod.dinfo.fini_vaddr) {
                auto func = reinterpret_cast<void (*)()>(mod.load_bias + mod.dinfo.fini_vaddr);
                DestructorAction action;
                action.type = DestructorAction::FUNC_PTR;
                action.func_ptr = func;
                region.destructors.push_back(action);
            }

            // 3. It's also the perfect time to clean up TLS and DWARF
            if (mod.dinfo.tls_mod_id) {
                DestructorAction action;
                action.type = DestructorAction::TLS_CLEANUP;
                action.mod_id = mod.dinfo.tls_mod_id;
                region.destructors.push_back(action);
            }

            if (mod.eh_registered && __deregister_frame) {
                DestructorAction action;
                action.type = DestructorAction::DWARF_CLEANUP;
                action.frame_ptr = mod.eh_frame_ptr;
                region.destructors.push_back(action);
            }

            for (tls_index* ti : mod.tlsdesc_args) {
                DestructorAction action;
                action.type = DestructorAction::TLSDESC_CLEANUP;
                action.tlsdesc_arg = ti;
                region.destructors.push_back(action);
            }
        }

        g_custom_regions->push_back(std::move(region));
    }
    return true;
}
